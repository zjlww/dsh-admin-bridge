"""Read-only-to-system, unprivileged worker tests. Never invokes sudo.

Tests deliberately approve a Python interpreter to create disposable child
processes. Production catalog entries must not expose such generic authority.
"""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "helper" / "runner.py"
spec = importlib.util.spec_from_file_location("bridge_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)
PYTHON = os.path.realpath(sys.executable)


def operation(operation_id="example", executable="/usr/bin/echo", args=None, timeout=5):
    return {"id": operation_id, "label": "Test operation", "executable": executable,
            "args": ["hello"] if args is None else args, "timeoutSeconds": timeout}


def manifest(*operations, ttl=30):
    return {"version": 1, "ttlSeconds": ttl,
            "operations": list(operations) if operations else [operation()]}


def encode(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Bridge:
    def __init__(self, value=None, launcher=None):
        entry = [str(RUNNER)] if launcher is None else ["-c", launcher]
        self.process = subprocess.Popen([PYTHON, "-I", *entry, encode(value or manifest())],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
        self.buffer = bytearray()

    def frame(self, timeout=4):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError("worker frame deadline exceeded")
            chunk = os.read(self.process.stdout.fileno(), 8192)
            if not chunk:
                raise AssertionError("worker exited without a frame")
            self.buffer.extend(chunk)
        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = bytearray(rest)
        return json.loads(line)

    def ready(self):
        result = self.frame()
        if result != {"type": "ready", "uid": os.geteuid()}:
            raise AssertionError(result)
        return self

    def send(self, value):
        self.process.stdin.write(json.dumps(value).encode() + b"\n")
        self.process.stdin.flush()

    def run(self, operation_id="example", request_id="request_1"):
        self.send({"type": "run", "id": request_id, "operationId": operation_id})

    def close(self):
        if self.process.poll() is None:
            try:
                self.send({"type": "lock"})
            except (BrokenPipeError, ValueError):
                pass
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class ValidationTests(unittest.TestCase):
    def test_valid_manifest_is_immutable(self):
        result = runner.parse_manifest(encode(manifest()))
        self.assertEqual(result.ttl_seconds, 30)
        self.assertEqual(result.operations["example"].args, ("hello",))
        with self.assertRaises(TypeError):
            result.operations["new"] = result.operations["example"]
        with self.assertRaises(AttributeError):
            result.operations["example"].executable = "/usr/bin/id"

    def test_top_level_validation(self):
        values = [[], None, {}, {**manifest(), "extra": True}]
        for key, replacements in (("version", [0, 2, True, "1"]),
                                  ("ttlSeconds", [29, 901, True, 30.0, "30"]),
                                  ("operations", [[], {}, [operation()] * 17])):
            for value in replacements:
                candidate = manifest()
                candidate[key] = value
                values.append(candidate)
        values.append(manifest(operation(), operation()))
        for value in values:
            with self.subTest(value=value), self.assertRaises(runner.Invalid):
                runner.parse_manifest(encode(value))

    def test_operation_validation(self):
        replacements = {
            "id": ["", "a" * 65, "x.y", "x y", "é", 1],
            "label": ["", "x" * 121, "newline\n", "\x7f", None],
            "executable": ["id", "/", "/usr//bin/id", "/usr/./bin/id", "/usr/../bin/id",
                           "/usr/bin/a b", "/usr/bin/id\n", "/" + "x" * 1024],
            "args": [["x"] * 33, ["x" * 1025], ["\x00"], ["\n"], [1], "hello", ["\ud800"]],
            "timeoutSeconds": [0, 121, 1.0, True, "1"],
        }
        for key, values in replacements.items():
            for value in values:
                candidate = operation()
                candidate[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(runner.Invalid):
                    runner.parse_manifest(encode(manifest(candidate)))
        for candidate in ({**operation(), "env": {}}, {key: value for key, value in operation().items() if key != "label"}):
            with self.assertRaises(runner.Invalid):
                runner.parse_manifest(encode(manifest(candidate)))

    def test_duplicate_keys_encoding_and_oversize(self):
        duplicate = b'{"version":1,"version":1,"ttlSeconds":30,"operations":[]}'
        for value in [encode(duplicate), encode(b'{"version":NaN}'), encode(b'\xff'),
                      "abc=", "!", "", encode(b" " * 32769), "a" * 100000]:
            with self.subTest(length=len(value)), self.assertRaises(runner.Invalid):
                runner.parse_manifest(value)

    def test_string_and_operation_boundaries(self):
        entries = [operation(str(index), args=[""] * 32, timeout=120) for index in range(16)]
        result = runner.parse_manifest(encode(manifest(*entries, ttl=900)))
        self.assertEqual(len(result.operations), 16)
        self.assertEqual(result.ttl_seconds, 900)

    def test_arbitrary_permission_and_command_validation(self):
        value = {"version": 1, "ttlSeconds": 30, "operations": [], "allowAllCommands": True}
        self.assertTrue(runner.parse_manifest(encode(value)).allow_all_commands)
        self.assertFalse(runner.parse_manifest(encode(manifest())).allow_all_commands)
        for permission in (False, None, 1, "true"):
            with self.assertRaises(runner.Invalid):
                runner.parse_manifest(encode({**value, "allowAllCommands": permission}))
        base = {"type": "runCommand", "id": "r", "command": "true"}
        self.assertEqual(runner.validate_command(base), ("true", "/", 120))
        for patch in ({"command": ""}, {"command": "\u0000"}, {"command": "\ud800"},
                      {"command": "é" * 8193}, {"workdir": "relative"},
                      {"workdir": "/does-not-exist-dsh-test"}, {"workdir": "/usr/bin/bash"},
                      {"workdir": "/" + "é" * 2048}, {"env": {}},
                      *({"timeoutSeconds": x} for x in (0, 121, True, 1.0, "1", None))):
            with self.subTest(patch=patch), self.assertRaises(runner.Invalid):
                runner.validate_command({**base, **patch})

    def test_root_path_permissions(self):
        root_dir = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        root_file = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        unsafe_dir = os.stat_result((stat.S_IFDIR | 0o775, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        user_file = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 0, 1000, 1000, 0, 0, 0, 0))
        link = os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        with mock.patch.object(runner.os, "geteuid", return_value=0):
            with mock.patch.object(runner.os, "lstat", side_effect=[root_dir, root_dir, root_file]):
                runner.validate_executable("/usr/test")
            for stats in ([unsafe_dir], [root_dir, root_dir, user_file], [root_dir, link], [root_dir, root_dir, root_dir]):
                with mock.patch.object(runner.os, "lstat", side_effect=stats), self.assertRaises(runner.Invalid):
                    runner.validate_executable("/usr/test")


@unittest.skipIf(os.geteuid() == 0, "Integration tests must run as an unprivileged user")
class ProtocolTests(unittest.TestCase):
    def bridge(self, value=None):
        result = Bridge(value).ready()
        self.addCleanup(result.close)
        return result

    def assert_revoked(self, bridge, expected=65):
        self.assertEqual(bridge.process.wait(timeout=4), expected)
        self.assertEqual(bridge.process.stderr.read(), b"")
        self.assertEqual(bridge.process.stdout.read(), b"")

    def test_exact_argv_not_shell_and_fixed_result(self):
        text = "$(id); /usr/bin/false | & > ' quoted"
        bridge = self.bridge(manifest(operation(args=[text])))
        bridge.run()
        self.assertEqual(bridge.frame(), {"type": "result", "id": "request_1", "exitCode": 0,
                                         "stdout": text + "\n", "stderr": "", "truncated": False, "timedOut": False})
        bridge.run(request_id="request_2")
        self.assertEqual(bridge.frame()["id"], "request_2")

    def test_shell_pipeline_cwd_timeout_output_and_legacy_compatibility(self):
        bridge = self.bridge({**manifest(), "allowAllCommands": True})
        bridge.send({"type": "runCommand", "id": "shell1", "command": "printf one | tr o O; printf '\\n'; pwd; read x || printf eof", "workdir": "/tmp"})
        result = bridge.frame()
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["stdout"], "One\n/tmp\neof")
        bridge.run()
        self.assertEqual(bridge.frame()["stdout"], "hello\n")
        bridge.send({"type": "runCommand", "id": "shell2", "command": "head -c 100000 /dev/zero"})
        result = bridge.frame()
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), runner.MAX_OUTPUT_BYTES)
        bridge.send({"type": "runCommand", "id": "shell3", "command": "sleep 20", "timeoutSeconds": 1})
        self.assertTrue(bridge.frame()["timedOut"])
        bridge.send({"type": "runCommand", "id": "shell3", "command": "true"})
        self.assert_revoked(bridge)

    def test_shell_requires_manifest_permission_and_bad_frames_revoke(self):
        for permission in (None, False):
            value = manifest()
            if permission is not None:
                value["allowAllCommands"] = permission
            bridge = self.bridge(value)
            bridge.send({"type": "runCommand", "id": "r", "command": "true"})
            self.assert_revoked(bridge)
        for patch in ({"operationId": "example"}, {"timeoutSeconds": 121},
                      {"workdir": "relative"}, {"command": "x" * 16385}):
            bridge = self.bridge({**manifest(), "allowAllCommands": True})
            bridge.send({"type": "runCommand", "id": "r", "command": "true", **patch})
            self.assert_revoked(bridge)

    def test_shell_eof_revokes_running_process_group(self):
        bridge = self.bridge({**manifest(), "allowAllCommands": True})
        bridge.send({"type": "runCommand", "id": "r", "command": "sleep 20"})
        children_file = Path(f"/proc/{bridge.process.pid}/task/{bridge.process.pid}/children")
        deadline = time.monotonic() + 2
        children = []
        while not children and time.monotonic() < deadline:
            children = children_file.read_text().split()
            select.select([], [], [], 0.01)
        self.assertTrue(children)
        bridge.process.stdin.close()
        self.assertEqual(bridge.process.wait(timeout=3), 0)
        for child in children:
            self.assertFalse(Path(f"/proc/{child}").exists())

    def test_no_command_stdin_fixed_environment_and_cwd(self):
        code = "import os,json; print(json.dumps([os.getcwd(),os.read(0,1).decode(),dict(os.environ)]))"
        with mock.patch.dict(os.environ, {"DSH_TEST_SECRET": "not-in-child", "PYTHONPATH": "/fake"}):
            bridge = self.bridge(manifest(operation(executable=PYTHON, args=["-I", "-c", code])))
        bridge.run()
        cwd, stdin, env = json.loads(bridge.frame()["stdout"])
        self.assertEqual(cwd, "/")
        self.assertEqual(stdin, "")
        self.assertNotIn("DSH_TEST_SECRET", env)
        self.assertNotIn("PYTHONPATH", env)
        self.assertEqual(env["HOME"], "/root")
        self.assertEqual(env["PATH"], runner.SAFE_ENV["PATH"])

    def test_unknown_operation_or_override_revokes(self):
        cases = [{"type": "run", "id": "r", "operationId": "missing"},
                 {"type": "run", "id": "r", "operationId": "example", "args": ["bad"]},
                 {"type": "run", "id": "r", "operationId": "example", "executable": "/usr/bin/id"},
                 {"type": "init", "operations": []}, {"type": "lock", "ttlSeconds": 900},
                 {"type": "run", "id": "r\n", "operationId": "example"}]
        for frame in cases:
            with self.subTest(frame=frame):
                bridge = self.bridge()
                bridge.send(frame)
                self.assert_revoked(bridge)

    def test_malformed_duplicate_and_oversized_frames(self):
        cases = [b"password-must-not-echo\n", b"\n", b"[1,2]\n", b"\xff\n",
                 b'{"type":"lock","type":"run"}\n', b"x" * (runner.MAX_FRAME_BYTES + 1),
                 b'{"type":"lock"}\x00\n']
        for raw in cases:
            with self.subTest(raw=raw[:50]):
                bridge = self.bridge()
                bridge.process.stdin.write(raw)
                bridge.process.stdin.flush()
                self.assert_revoked(bridge)

    def test_fragmented_request(self):
        bridge = self.bridge()
        frame = json.dumps({"type": "run", "id": "r", "operationId": "example"}).encode() + b"\n"
        for byte in frame:
            bridge.process.stdin.write(bytes([byte]))
            bridge.process.stdin.flush()
        self.assertEqual(bridge.frame()["stdout"], "hello\n")

    def test_replay_and_request_count_limit(self):
        bridge = self.bridge()
        bridge.run()
        bridge.frame()
        bridge.run()
        self.assert_revoked(bridge)
        worker = runner.Worker(runner.parse_manifest(encode(manifest())), time.monotonic())
        self.addCleanup(worker.selector.close)
        worker.seen = {str(index) for index in range(runner.MAX_REQUESTS)}
        with self.assertRaises(runner.Invalid):
            worker._frame(b'{"type":"run","id":"next","operationId":"example"}')

    def test_concurrent_run_revokes(self):
        bridge = self.bridge(manifest(operation(executable="/usr/bin/sleep", args=["20"])))
        bridge.run()
        bridge.run(request_id="second")
        self.assert_revoked(bridge)

    def test_timeout_kills_sigterm_resistant_command(self):
        code = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(20)"
        bridge = self.bridge(manifest(operation(executable=PYTHON, args=["-I", "-c", code], timeout=1)))
        start = time.monotonic()
        bridge.run()
        result = bridge.frame()
        self.assertTrue(result["timedOut"])
        self.assertEqual(result["exitCode"], -signal.SIGKILL)
        self.assertLess(time.monotonic() - start, 3)

    def test_bounded_output_and_invalid_utf8(self):
        code = "import os; os.write(1,b'X'*100000); os.write(2,b'Y'*100000)"
        bridge = self.bridge(manifest(operation(executable=PYTHON, args=["-I", "-c", code])))
        bridge.run()
        result = bridge.frame()
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]) + len(result["stderr"]), runner.MAX_OUTPUT_BYTES)
        code = "import os; os.write(1,bytes([255,0,10])); os.write(2,b'err')"
        bridge = self.bridge(manifest(operation(executable=PYTHON, args=["-I", "-c", code])))
        bridge.run()
        result = bridge.frame()
        self.assertEqual(result["stdout"], "\ufffd\x00\n")
        self.assertEqual(result["stderr"], "err")

    def test_spawn_failure_and_symlink_revoke(self):
        for executable in ("/usr/bin/does-not-exist-admin-bridge", "/proc/self/exe"):
            with self.subTest(executable=executable):
                bridge = self.bridge(manifest(operation(executable=executable)))
                bridge.run()
                self.assert_revoked(bridge)

    def test_eof_lock_signal_and_broken_output_cleanup(self):
        for action in ("eof", "lock", "signal", "broken-output"):
            with self.subTest(action=action):
                bridge = self.bridge(manifest(operation(executable="/usr/bin/sleep", args=["20"])))
                bridge.run()
                # Wait for creation by observing only this test child's /proc tree.
                children_file = Path(f"/proc/{bridge.process.pid}/task/{bridge.process.pid}/children")
                deadline = time.monotonic() + 2
                children = []
                while not children and time.monotonic() < deadline:
                    children = children_file.read_text().split()
                    select.select([], [], [], 0.01)
                self.assertTrue(children)
                if action == "eof":
                    bridge.process.stdin.close()
                elif action == "lock":
                    bridge.send({"type": "lock"})
                elif action == "signal":
                    bridge.process.send_signal(signal.SIGTERM)
                else:
                    bridge.process.stdout.close()
                    bridge.send({"type": "lock"})
                self.assertEqual(bridge.process.wait(timeout=3), 0)
                for child in children:
                    self.assertFalse(Path(f"/proc/{child}").exists())

    def test_cleanup_descendant_after_leader_exit(self):
        code = "import os,time; p=os.fork(); print(p if p else os.getpid(),flush=True); time.sleep(20) if p==0 else None"
        bridge = self.bridge(manifest(operation(executable=PYTHON, args=["-I", "-c", code])))
        bridge.run()
        result = bridge.frame()
        self.assertEqual(result["exitCode"], 0)
        pids = {int(line) for line in result["stdout"].splitlines()}
        self.assertTrue(pids)
        for pid in pids:
            self.assertFalse(Path(f"/proc/{pid}").exists(), "descendant not reaped")

    def test_absolute_deadline_not_extended_by_execution(self):
        # Clock injection tests the exact pre-spawn path without a 30-second
        # integration delay. Constructor receives the actual start time in CLI.
        worker = runner.Worker(runner.parse_manifest(encode(manifest())), started=100)
        self.addCleanup(worker.selector.close)
        self.assertEqual(worker.deadline, 130)
        with mock.patch.object(runner.time, "monotonic", return_value=130), mock.patch.object(runner.subprocess, "Popen") as spawn:
            worker._frame(b'{"type":"run","id":"r","operationId":"example"}')
        self.assertTrue(worker.revoked)
        spawn.assert_not_called()
        self.assertEqual(worker.deadline, 130)

    def test_expiry_stops_active_job(self):
        worker = runner.Worker(runner.parse_manifest(encode(manifest())), started=100)
        self.addCleanup(worker.selector.close)
        process = mock.Mock(pid=12345)
        worker.job = runner.Job(process, "r", 140, {})
        with mock.patch.object(runner.time, "monotonic", return_value=130), mock.patch.object(runner.os, "killpg") as kill, mock.patch.object(runner.os, "waitid", return_value=None):
            worker._tick(130)
        self.assertTrue(worker.revoked)
        kill.assert_called_once_with(12345, signal.SIGTERM)
        self.assertEqual(worker.job.stopping_at, 130)

    def test_unexpected_tick_failure_kills_and_reaps_child(self):
        launcher = f"""
import importlib.util, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('test_worker', {str(RUNNER)!r})
worker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = worker
spec.loader.exec_module(worker)
original = worker.Worker._tick
def fail_after_spawn(self, now):
    if self.job is not None:
        # Test-only observation channel, not a production diagnostic.
        os.write(2, str(self.job.process.pid).encode() + b'\\n')
        raise RuntimeError('sensitive exception must not be printed')
    return original(self, now)
worker.Worker._tick = fail_after_spawn
raise SystemExit(worker.main())
"""
        bridge = Bridge(manifest(operation(executable="/usr/bin/sleep", args=["20"])), launcher=launcher).ready()
        self.addCleanup(bridge.close)
        bridge.run()
        self.assertEqual(bridge.process.wait(timeout=3), 65)
        observation = bridge.process.stderr.read()
        self.assertTrue(observation.strip().isdigit(), observation)
        self.assertFalse(Path(f"/proc/{int(observation)}").exists())
        self.assertEqual(bridge.process.stdout.read(), b"")

    def test_manifest_failure_has_no_ready_or_diagnostics(self):
        bridge = Bridge(b"password-do-not-echo")
        self.addCleanup(bridge.close)
        self.assert_revoked(bridge)


if __name__ == "__main__":
    unittest.main()
