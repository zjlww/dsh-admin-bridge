import { randomUUID, timingSafeEqual } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { SudoWorker } from './sudo-worker.js';
import { BridgeError, fail, identifier, integer, selectManifest, validateCommand, validateOperations } from './policy.js';

export class AdminBridge {
  constructor({ operations = [], maxTtlSeconds = 300, allowAllCommands = true } = {}, dependencies = {}) {
    this.operations = validateOperations(operations);
    if (typeof allowAllCommands !== 'boolean') fail('invalid_config', 'allowAllCommands must be a boolean.');
    Object.defineProperty(this, 'allowAllCommands', { value: allowAllCommands, enumerable: true });
    if (!integer(maxTtlSeconds, 30, 900)) fail('invalid_config', 'Maximum lease duration must be 30–900 seconds.');
    this.maxTtlSeconds = maxTtlSeconds;
    this.workerFactory = dependencies.workerFactory ?? ((manifest, canProceed) => new SudoWorker(manifest, { canProceed }));
    this.now = dependencies.now ?? (() => performance.now());
    this.requestTimeoutMs = dependencies.requestTimeoutMs ?? 90_000;
    this.sessions = new Map();
    // Also revoke without waiting for the next tool/API call when policy changes.
    this.sweep = setInterval(() => {
      for (const id of this.sessions.keys()) this.check(id);
    }, 250);
    this.sweep.unref();
  }

  registerSession(sessionId, canApprove, onLock) {
    if (!identifier(sessionId) || typeof canApprove !== 'function' ||
        (onLock !== undefined && typeof onLock !== 'function') || this.sessions.has(sessionId))
      fail('invalid_session', 'Cannot attach administrator access to this session.');
    const record = { canApprove, onLock, lease: null, cooldownUntil: 0 };
    this.sessions.set(sessionId, record);
    return () => {
      if (this.sessions.get(sessionId) !== record) return;
      this.lock(sessionId);
      this.sessions.delete(sessionId);
    };
  }

  allowed(record) {
    try { return record.canApprove() === true; } catch { return false; }
  }

  check(sessionId) {
    const record = this.sessions.get(sessionId);
    if (!record) return;
    if (record.lease && (!this.allowed(record) || this.now() >= record.lease.deadline)) this.lock(sessionId);
    return record;
  }

  requireAllowed(sessionId) {
    const record = this.check(sessionId);
    if (!record || !this.allowed(record)) fail('policy_denied', 'Session approvals must be enabled; administrator access is denied.');
    return record;
  }

  describe(sessionId) {
    const record = this.check(sessionId);
    if (!record) return { state: 'unavailable', operations: [], allowAllCommands: this.allowAllCommands, maxTtlSeconds: this.maxTtlSeconds };
    const enabled = this.allowed(record);
    const lease = record.lease;
    return {
      state: enabled ? (lease?.state ?? 'locked') : 'disabled',
      operations: this.operations,
      allowAllCommands: lease ? lease.manifest.allowAllCommands === true : this.allowAllCommands,
      maxTtlSeconds: this.maxTtlSeconds,
      ...(lease ? {
        selectedOperations: lease.manifest.operations,
        ttlSeconds: lease.manifest.ttlSeconds,
        expiresAt: Date.now() + Math.max(0, lease.deadline - this.now()),
        ...(lease.state === 'pending' ? { requestId: lease.requestId } : {}),
      } : {}),
    };
  }

  manifest(operationIds, ttlSeconds) {
    const manifest = selectManifest(this.operations, operationIds, ttlSeconds, this.maxTtlSeconds, this.allowAllCommands);
    if (Buffer.byteLength(JSON.stringify(manifest)) > 32768) fail('invalid_config', 'Selected operation manifest exceeds 32 KiB.');
    return manifest;
  }

  // Trusted adapter only: creates a pending intent, never an authenticated grant.
  requestUnlock(sessionId, manifest, signal) {
    const record = this.requireAllowed(sessionId);
    if (signal?.aborted) fail('cancelled', 'Administrator request was cancelled.');
    if (record.lease) fail('busy', 'Lock the current administrator request or lease before opening another.');
    if (this.now() < record.cooldownUntil) fail('rate_limited', 'Wait before requesting authentication again.');
    if (manifest?.allowAllCommands === true && !this.allowAllCommands)
      fail('not_authorized', 'Arbitrary commands are disabled by configuration.');
    manifest = selectManifest(this.operations, manifest?.operations?.map(op => op.id),
      manifest?.ttlSeconds, this.maxTtlSeconds, manifest?.allowAllCommands ?? false);
    if (Buffer.byteLength(JSON.stringify(manifest)) > 32768) fail('invalid_config', 'Selected operation manifest exceeds 32 KiB.');
    const lease = {
      state: 'pending', manifest, requestId: randomUUID(), worker: null,
      deadline: this.now() + this.requestTimeoutMs,
    };
    record.lease = lease;
    return new Promise((resolve, reject) => {
      lease.resolve = resolve;
      lease.reject = reject;
      const abort = () => { if (record.lease === lease) this.lock(sessionId); };
      signal?.addEventListener('abort', abort, { once: true });
      lease.detach = () => signal?.removeEventListener('abort', abort);
      lease.timer = setTimeout(abort, this.requestTimeoutMs);
    });
  }

  async authenticate(sessionId, requestId, password) {
    const record = this.requireAllowed(sessionId);
    const lease = record.lease;
    if (!lease || lease.state !== 'pending' || typeof requestId !== 'string' ||
        Buffer.byteLength(requestId) !== Buffer.byteLength(lease.requestId) ||
        !timingSafeEqual(Buffer.from(requestId), Buffer.from(lease.requestId)))
      fail('stale_request', 'This authentication request is stale or unavailable.');
    if (typeof password !== 'string' || Buffer.byteLength(password) > 4096 || /[\r\n\0]/.test(password))
      fail('invalid_request', 'Invalid password input.');
    lease.state = 'authenticating'; // Claim once before the first asynchronous boundary.
    record.cooldownUntil = this.now() + 10_000;
    try {
      lease.worker = this.workerFactory(lease.manifest, () =>
        record.lease === lease && this.allowed(record) && this.now() < lease.deadline);
      lease.worker.onClose = () => { if (record.lease === lease) this.lock(sessionId); };
      const authentication = lease.worker.authenticate(password);
      password = undefined;
      await authentication;
      // Policy and cancellation can change while PAM is prompting.
      this.requireAllowed(sessionId);
      if (record.lease !== lease) fail('cancelled', 'Administrator request was cancelled.');
      clearTimeout(lease.timer);
      lease.detach();
      lease.state = 'unlocked';
      // Successful password authentication is not a failed-attempt throttle.
      // Reentry still needs a new worker/password; failed and cancelled attempts
      // retain their cooldown so repeated mode selection cannot bypass it.
      record.cooldownUntil = 0;
      // Root deadline started before ready; host starts here and can never extend root authority.
      lease.deadline = this.now() + lease.manifest.ttlSeconds * 1000;
      lease.timer = setTimeout(() => { if (record.lease === lease) this.lock(sessionId); }, lease.manifest.ttlSeconds * 1000);
      lease.resolve({ state: 'unlocked', operationIds: lease.manifest.operations.map(op => op.id), ttlSeconds: lease.manifest.ttlSeconds });
      lease.resolve = lease.reject = null;
      return { state: 'unlocked' };
    } catch (error) {
      if (record.lease === lease) this.lock(sessionId);
      else lease.worker?.close();
      if (error instanceof BridgeError && error.code === 'password_required')
        throw new BridgeError('password_required', 'Sudo access requires password-based sudo authentication; passwordless sudo is not supported.');
      throw new BridgeError('authentication_failed', 'Authentication failed, expired, or was cancelled.');
    }
  }

  async run(sessionId, operationId, signal) {
    const record = this.requireAllowed(sessionId);
    const lease = record.lease;
    if (!lease || lease.state !== 'unlocked') fail('locked', 'Authenticate an approved administrator request first.');
    if (!lease.manifest.operations.some(op => op.id === operationId)) fail('not_authorized', 'This operation is not in the authorized set.');
    if (signal?.aborted) { this.lock(sessionId); fail('cancelled', 'Administrator operation was cancelled.'); }
    const abort = () => { if (record.lease === lease) this.lock(sessionId); };
    signal?.addEventListener('abort', abort, { once: true });
    try { return await lease.worker.run(operationId); }
    finally { signal?.removeEventListener('abort', abort); }
  }

  async runCommand(sessionId, request, signal) {
    const record = this.requireAllowed(sessionId);
    const lease = record.lease;
    if (!lease || lease.state !== 'unlocked') fail('locked', 'Authenticate a Sudo access request first.');
    if (lease.manifest.allowAllCommands !== true) fail('not_authorized', 'Arbitrary commands are not authorized by this lease.');
    const command = validateCommand(request);
    if (signal?.aborted) { this.lock(sessionId); fail('cancelled', 'Administrator command was cancelled.'); }
    const abort = () => { if (record.lease === lease) this.lock(sessionId); };
    signal?.addEventListener('abort', abort, { once: true });
    try { return await lease.worker.runCommand(command); }
    finally { signal?.removeEventListener('abort', abort); }
  }

  cancelRequest(sessionId, requestId) {
    if (this.sessions.get(sessionId)?.lease?.requestId === requestId) this.lock(sessionId);
  }

  lock(sessionId, reason = 'locked') {
    const record = this.sessions.get(sessionId);
    const lease = record?.lease;
    if (!lease) return { state: 'locked' };
    record.lease = null; // Clear authority before closing to prevent callback/reentrancy reuse.
    clearTimeout(lease.timer);
    lease.detach?.();
    lease.reject?.(new BridgeError('locked', 'Administrator request was cancelled, expired, or denied.'));
    try { lease.worker?.close(); }
    finally {
      // A composition owner may restore nonprivileged session state on every
      // termination path. Its failure can never retain or resurrect authority.
      try { record.onLock?.({ requestId: lease.requestId, reason }); } catch {}
    }
    return { state: 'locked' };
  }

  dispose() {
    clearInterval(this.sweep);
    for (const id of this.sessions.keys()) this.lock(id);
    this.sessions.clear();
  }
}
