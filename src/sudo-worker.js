import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { BridgeError, fail, isObject } from './policy.js';

const RUNNER = fileURLToPath(new URL('../helper/runner.py', import.meta.url));
const MAX_FRAME = 1024 * 1024;
const AUTH_MS = 45_000;
const safeEnvironment = Object.freeze({ PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' });

// Each worker owns private pipes. No shell, PTY, timestamp keepalive, or secret in argv/env.
export class SudoWorker {
  constructor(manifest, { spawnProcess = spawn, authMs = AUTH_MS, canProceed = () => true } = {}) {
    this.manifest = manifest;
    this.canProceed = () => { try { return canProceed() === true; } catch { return false; } };
    this.spawnProcess = spawnProcess;
    this.authMs = authMs;
    this.child = null;
    this.pending = null;
    this.ready = false;
    this.closed = false;
    this.onClose = () => {};
  }

  async authenticate(password) {
    if (this.child || this.closed) fail('closed', 'Administrator worker is unavailable.');
    if (!this.canProceed()) fail('policy_denied', 'Administrator authorization is no longer available.');
    if (typeof password !== 'string' || Buffer.byteLength(password) > 4096 || /[\r\n\0]/.test(password))
      fail('invalid_request', 'Invalid password input.');
    let secret = Buffer.from(password + '\n', 'utf8');
    password = undefined;
    let stderr = '';
    let stdout = Buffer.alloc(0);
    let sent = false;
    let settled = false;
    const prompt = `DSH_ADMIN_${randomUUID()}:`;
    const clearSecret = () => { if (secret) secret.fill(0); secret = null; };
    return new Promise((resolve, reject) => {
      const finishAuth = error => {
        if (settled) return;
        settled = true;
        clearTimeout(this.authTimer);
        clearSecret();
        stderr = '';
        error ? reject(error) : resolve(this);
      };
      this.authTimer = setTimeout(() => {
        finishAuth(new BridgeError('authentication_failed', 'Authentication failed or timed out.'));
        this.close();
      }, this.authMs);
      try {
        this.child = this.spawnProcess('/usr/bin/sudo', [
          '-S', '-k', '-p', prompt, '--', '/usr/bin/python3', '-I', RUNNER,
          Buffer.from(JSON.stringify(this.manifest)).toString('base64url'),
        ], { shell: false, cwd: '/', env: { ...safeEnvironment }, stdio: ['pipe', 'pipe', 'pipe'] });
      } catch {
        finishAuth(new BridgeError('authentication_failed', 'Could not start the administrator worker.'));
        this.close();
        return;
      }
      const child = this.child;
      child.stdin.on('error', () => this.close());
      child.stdout.on('error', () => this.close());
      child.stderr.on('error', () => this.close());
      child.stdout.on('end', () => this.close());
      child.stdout.on('close', () => this.close());
      child.on('error', () => {
        finishAuth(new BridgeError('authentication_failed', 'Could not start the administrator worker.'));
        this.close();
      });
      child.on('close', () => {
        finishAuth(new BridgeError('authentication_failed', 'Authentication failed or worker exited.'));
        this.close();
      });
      child.stderr.on('data', chunk => {
        // Never forward PAM/sudo diagnostics: they are not a public error channel.
        if (this.ready || this.closed) return;
        stderr += chunk.toString('utf8');
        if (stderr.length > 8192) { this.close(); return; }
        const at = stderr.indexOf(prompt);
        if (at < 0) return;
        if (sent || !this.canProceed()) { this.close(); return; } // One attempt; recheck before password delivery.
        sent = true;
        stderr = stderr.slice(at + prompt.length);
        child.stdin.write(secret, () => clearSecret());
        if (stderr.includes(prompt)) this.close();
      });
      child.stdout.on('data', chunk => {
        if (this.closed) return;
        stdout = Buffer.concat([stdout, chunk]);
        if (stdout.length > MAX_FRAME) { this.close(); return; }
        let end;
        while ((end = stdout.indexOf(10)) >= 0 && !this.closed) {
          const line = stdout.subarray(0, end);
          stdout = stdout.subarray(end + 1);
          let frame;
          try { frame = JSON.parse(line.toString('utf8')); } catch { this.close(); return; }
          if (!this.ready) {
            if (!isObject(frame) || frame.type !== 'ready' || frame.uid !== 0 || Object.keys(frame).length !== 2) {
              this.close(); return;
            }
            this.ready = true;
            // A NOPASSWD rule may start the helper without asking for any password.
            finishAuth();
            continue;
          }
          if (!isObject(frame) || Object.keys(frame).length !== 7 || frame.type !== 'result' || !this.pending || frame.id !== this.pending.id ||
              !Number.isInteger(frame.exitCode) || frame.exitCode < -255 || frame.exitCode > 255 || typeof frame.stdout !== 'string' ||
              typeof frame.stderr !== 'string' || typeof frame.truncated !== 'boolean' ||
              typeof frame.timedOut !== 'boolean') { this.close(); return; }
          const pending = this.pending;
          this.pending = null;
          clearTimeout(pending.timer);
          pending.resolve({ exitCode: frame.exitCode, stdout: frame.stdout, stderr: frame.stderr,
            truncated: frame.truncated, timedOut: frame.timedOut });
        }
      });
      this.failAuth = () => finishAuth(new BridgeError('authentication_failed', 'Authentication failed or was cancelled.'));
    });
  }

  run(operationId) {
    if (!this.ready || this.closed) fail('locked', 'Administrator access is locked.');
    if (this.pending) fail('busy', 'Another administrator operation is running.');
    const op = this.manifest.operations.find(item => item.id === operationId);
    if (!op) fail('not_authorized', 'This operation is not in the authorized set.');
    return new Promise((resolve, reject) => {
      const id = randomUUID();
      const timer = setTimeout(() => this.close(), (op.timeoutSeconds + 3) * 1000);
      this.pending = { id, resolve, reject, timer };
      this.child.stdin.write(JSON.stringify({ type: 'run', id, operationId }) + '\n');
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.ready = false;
    clearTimeout(this.authTimer);
    this.failAuth?.();
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(new BridgeError('locked', 'Administrator access ended; operation outcome may be incomplete.'));
      this.pending = null;
    }
    // EOF is the primary root-worker revocation signal; it kills its own root process group.
    // An unprivileged Node parent cannot reliably signal the root helper directly.
    if (this.child) {
      this.child.stdin.end();
      this.child.kill('SIGTERM'); // Also terminates a sudo process still waiting for authentication.
    }
    this.onClose();
  }
}
