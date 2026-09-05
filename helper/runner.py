#!/usr/bin/python3
"""Linux lease worker, invoked by a trusted full-sudo application.

This file handles NO passwords. Its manifest is immutable, not a sudoers policy.
A user-writable runner is unsuitable for accounts with restricted sudo rights.

stdin: bounded JSON lines, run {type,id,operationId} or lock {type}.
stdout: ready {type,uid}, then result {type,id,exitCode,stdout,stderr,
truncated,timedOut}. Any protocol violation revokes the entire lease, without
reflecting input into diagnostics. stdout/stderr from commands are untrusted.

Cleanup kills a command's process group, including descendants retaining that
group after its leader exits. Deliberately escaped groups, daemon/service effects,
uninterruptible kernel waits, and previously completed effects are NOT undone.
"""
from __future__ import annotations

import base64
import binascii
import ctypes
from dataclasses import dataclass, field
import json
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from types import MappingProxyType

MAX_MANIFEST_BYTES = 32768
MAX_FRAME_BYTES = 4096
MAX_OUTPUT_BYTES = 65536
MAX_REQUESTS = 4096
TERM_GRACE = 0.2
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
            "LANG": "C", "LC_ALL": "C", "USER": "root", "LOGNAME": "root"}


class Invalid(ValueError):
    """Invalid untrusted input, intentionally without its contents."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate key")
        result[key] = value
    return result


def _json(raw):
    def bad_constant(_):
        raise Invalid("invalid constant")
    try:
        return json.loads(raw, object_pairs_hook=_object,
                          parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid("invalid JSON") from exc


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise Invalid("invalid fields")


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise Invalid("invalid integer")
    return value


def _text(value, maximum, *, empty=False):
    if type(value) is not str or (not empty and not value) or len(value) > maximum:
        raise Invalid("invalid string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Invalid("control character")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise Invalid("invalid Unicode") from exc
    return value


def _identifier(value):
    if type(value) is not str or not ID_PATTERN.fullmatch(value):
        raise Invalid("invalid id")
    return value


@dataclass(frozen=True)
class Operation:
    id: str
    label: str
    executable: str
    args: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class Manifest:
    ttl_seconds: int
    operations: object


def parse_manifest(encoded):
    if type(encoded) is not str or len(encoded) > ((MAX_MANIFEST_BYTES + 2) // 3) * 4:
        raise Invalid("manifest too large")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise Invalid("invalid base64url")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                               altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise Invalid("invalid base64url") from exc
    if len(raw) > MAX_MANIFEST_BYTES or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != encoded:
        raise Invalid("invalid manifest encoding")
    manifest = _json(raw)
    _keys(manifest, ("version", "ttlSeconds", "operations"))
    _integer(manifest["version"], 1, 1)
    ttl = _integer(manifest["ttlSeconds"], 30, 900)
    entries = manifest["operations"]
    if type(entries) is not list or not 1 <= len(entries) <= 16:
        raise Invalid("invalid operations")
    operations = {}
    for entry in entries:
        _keys(entry, ("id", "label", "executable", "args", "timeoutSeconds"))
        operation_id = _identifier(entry["id"])
        if operation_id in operations:
            raise Invalid("duplicate operation")
        label = _text(entry["label"], 120)
        executable = _text(entry["executable"], 1024)
        if not executable.startswith("/") or any(char.isspace() for char in executable):
            raise Invalid("invalid executable")
        # A single canonical lexical path, with no symlink traversal at launch.
        if executable == "/" or any(part in ("", ".", "..") for part in executable.split("/")[1:]):
            raise Invalid("noncanonical executable")
        arguments = entry["args"]
        if type(arguments) is not list or len(arguments) > 32:
            raise Invalid("invalid arguments")
        args = tuple(_text(arg, 1024, empty=True) for arg in arguments)
        timeout = _integer(entry["timeoutSeconds"], 1, 120)
        operations[operation_id] = Operation(operation_id, label, executable, args, timeout)
    return Manifest(ttl, MappingProxyType(operations))


def validate_executable(path):
    """Reject symlink traversal; enforce ownership/modes when privileged.

    Root-owned directories prevent same-user replacement after these checks.
    This does not protect against root races, writable command configuration,
    interpreters, ACLs granting writes, or root-owned network filesystems.
    """
    root = os.geteuid() == 0
    parts = path.split("/")[1:]
    current = "/"
    for index, part in enumerate([""] + parts):
        if index:
            current = os.path.join(current, part)
        info = os.lstat(current)
        leaf = index == len(parts)
        if stat.S_ISLNK(info.st_mode):
            raise Invalid("symlink executable path")
        if root and (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise Invalid("untrusted executable path")
        if leaf:
            if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
                raise Invalid("not executable")
        elif not stat.S_ISDIR(info.st_mode):
            raise Invalid("not directory")


@dataclass
class Job:
    process: subprocess.Popen
    request_id: str
    deadline: float
    streams: dict
    captured: dict = field(default_factory=lambda: {"stdout": bytearray(), "stderr": bytearray()})
    captured_size: int = 0
    truncated: bool = False
    timed_out: bool = False
    stopping_at: float | None = None
    killed: bool = False
    killed_at: float | None = None
    exit_code: int | None = None


class Worker:
    def __init__(self, manifest, started):
        self.manifest = manifest
        self.deadline = started + manifest.ttl_seconds
        self.selector = selectors.DefaultSelector()
        self.input = bytearray()
        self.output = bytearray()
        self.seen = set()
        self.job = None
        self.revoked = False
        self.exit_code = 0
        self.signal_received = False

    def _signal(self, _number, _frame):
        # Signal handlers must not re-enter subprocess/selector operations.
        self.signal_received = True

    def _queue(self, message):
        self.output.extend(json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
        try:
            self.selector.modify(1, selectors.EVENT_WRITE, "output")
        except KeyError:
            self.selector.register(1, selectors.EVENT_WRITE, "output")

    def _unregister(self, fd):
        try:
            self.selector.unregister(fd)
        except KeyError:
            pass

    def _group_signal(self, number):
        try:
            os.killpg(self.job.process.pid, number)
        except ProcessLookupError:
            pass

    def _stop_job(self, now):
        if self.job is not None and self.job.stopping_at is None:
            self.job.stopping_at = now
            self._group_signal(signal.SIGTERM)

    def _revoke(self, code=0):
        self.revoked = True
        self.exit_code = max(self.exit_code, code)
        self._unregister(0)
        self._unregister(1)
        self.input.clear()
        self.output.clear()
        self._stop_job(time.monotonic())

    def _frame(self, raw):
        frame = _json(raw)
        if type(frame) is not dict:
            raise Invalid("invalid frame")
        if frame.get("type") == "lock":
            _keys(frame, ("type",))
            self._revoke()
            return
        _keys(frame, ("type", "id", "operationId"))
        if frame["type"] != "run":
            raise Invalid("invalid frame type")
        request_id = _identifier(frame["id"])
        operation_id = _identifier(frame["operationId"])
        if self.job is not None or self.output or request_id in self.seen or len(self.seen) >= MAX_REQUESTS:
            raise Invalid("busy or repeated request")
        operation = self.manifest.operations.get(operation_id)
        if operation is None:
            raise Invalid("unknown operation")
        # A policy/clock check immediately before spawn; never extend the deadline.
        now = time.monotonic()
        if self.signal_received or now >= self.deadline or self.revoked:
            self._revoke()
            return
        validate_executable(operation.executable)
        self.seen.add(request_id)
        process = subprocess.Popen(
            [operation.executable, *operation.args], executable=operation.executable,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd="/", env=SAFE_ENV.copy(), shell=False, close_fds=True,
            start_new_session=True, restore_signals=True, umask=0o077,
        )
        self.job = Job(process, request_id, min(self.deadline, now + operation.timeout_seconds),
                       {"stdout": process.stdout, "stderr": process.stderr})
        for name, stream in self.job.streams.items():
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, ("stream", name))

    def _read_input(self):
        data = os.read(0, MAX_FRAME_BYTES + 1)
        if not data:
            self._revoke()
            return
        self.input.extend(data)
        while b"\n" in self.input and not self.revoked:
            line, _, remaining = self.input.partition(b"\n")
            self.input = bytearray(remaining)
            if not line or len(line) > MAX_FRAME_BYTES:
                raise Invalid("invalid frame length")
            self._frame(bytes(line))
        if len(self.input) > MAX_FRAME_BYTES:
            raise Invalid("oversized frame")

    def _read_stream(self, name):
        stream = self.job.streams[name]
        data = os.read(stream.fileno(), 8192)
        if not data:
            self._unregister(stream)
            stream.close()
            del self.job.streams[name]
            return
        available = MAX_OUTPUT_BYTES - self.job.captured_size
        kept = data[:available]
        self.job.captured[name].extend(kept)
        self.job.captured_size += len(kept)
        if len(kept) != len(data):
            self.job.truncated = True

    def _tick(self, now):
        if self.signal_received or now >= self.deadline:
            self._revoke()
        job = self.job
        if job is None:
            return
        # WNOWAIT keeps the leader PID reserved until group cleanup, avoiding
        # accidentally signalling an unrelated reused process-group ID.
        if job.exit_code is None:
            result = os.waitid(os.P_PID, job.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None:
                job.exit_code = result.si_status if result.si_code == os.CLD_EXITED else -result.si_status
                self._stop_job(now)
        if not self.revoked and job.exit_code is None and now >= job.deadline:
            job.timed_out = True
            self._stop_job(now)
        if job.stopping_at is None or now < job.stopping_at + TERM_GRACE:
            return
        if not job.killed:
            self._group_signal(signal.SIGKILL)
            job.killed = True
            job.killed_at = now
            return
        # Give killed descendants a scheduling turn before collecting zombies.
        if now < job.killed_at + 0.05:
            return
        # A kill cannot resolve an uninterruptible kernel wait. Stay revoked/
        # busy and wait to reap rather than falsely reporting the process dead.
        if job.exit_code is None:
            return
        # Drain only bounded currently available bytes before closing inherited
        # pipes. Escaped descendants must not hold the worker open indefinitely.
        for name in list(job.streams):
            for _ in range(16):
                if name not in job.streams:
                    break
                try:
                    self._read_stream(name)
                except BlockingIOError:
                    break
            if name in job.streams:
                stream = job.streams.pop(name)
                self._unregister(stream)
                stream.close()
        job.process.wait()
        # As a subreaper, collect already-exited adopted descendants as well.
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break
        if not self.revoked:
            self._queue({"type": "result", "id": job.request_id,
                         "exitCode": job.exit_code,
                         "stdout": job.captured["stdout"].decode("utf-8", errors="replace"),
                         "stderr": job.captured["stderr"].decode("utf-8", errors="replace"),
                         "truncated": job.truncated, "timedOut": job.timed_out})
        self.job = None

    def _emergency_cleanup(self):
        """Last-resort cleanup if selector/tick/setup itself unexpectedly fails.

        Keep the leader unreaped until the group receives SIGKILL. This bounded
        fallback cannot promise to reap an uninterruptible kernel wait.
        """
        job = self.job
        if job is None:
            return
        self.revoked = True
        self.input.clear()
        self.output.clear()
        if job.process.returncode is None:
            for number in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(job.process.pid, number)
                except OSError:
                    pass
                if number == signal.SIGTERM:
                    time.sleep(TERM_GRACE)
            try:
                job.process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for stream in job.streams.values():
            try:
                stream.close()
            except OSError:
                pass
        # Let ordinary killed descendants settle before reaping adopted zombies.
        time.sleep(0.05)
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except OSError:
                break
        self.job = None

    def run(self):
        previous = {number: signal.signal(number, self._signal)
                    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        try:
            os.set_blocking(0, False)
            os.set_blocking(1, False)
            self.selector.register(0, selectors.EVENT_READ, "input")
            self._queue({"type": "ready", "uid": os.geteuid()})
            while True:
                self._tick(time.monotonic())
                if self.revoked and self.job is None:
                    return self.exit_code
                for key, _ in self.selector.select(0.05):
                    try:
                        if key.data == "input":
                            if not self.revoked:
                                self._read_input()
                        elif key.data == "output":
                            if not self.revoked and self.output:
                                count = os.write(1, self.output)
                                del self.output[:count]
                                if not self.output:
                                    self._unregister(1)
                        elif self.job is not None and key.data[1] in self.job.streams:
                            self._read_stream(key.data[1])
                    except BlockingIOError:
                        pass
                    except (Invalid, OSError, ValueError):
                        self._revoke(65)
        finally:
            try:
                self._emergency_cleanup()
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
                self.selector.close()


def main(argv=None):
    started = time.monotonic()
    argv = sys.argv if argv is None else argv
    if not sys.platform.startswith("linux") or len(argv) != 2:
        return 64
    try:
        manifest = parse_manifest(argv[1])
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        libc = ctypes.CDLL(None, use_errno=True)
        # Process-local only: no system service, auth, or sudoers changes.
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            return 70
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            return 70
        return Worker(manifest, started).run()
    except Exception:
        # Unexpected failures also stay silent; Worker.run's finally has already
        # attempted root-owned cleanup. Never print argv, frames, or tracebacks.
        return 65


if __name__ == "__main__":
    raise SystemExit(main())
