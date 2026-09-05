import { randomUUID } from 'node:crypto';
import { AdminBridge } from './bridge.js';
import { SudoWorker } from './sudo-worker.js';
import { BridgeError, exactKeys, fail } from './policy.js';

export const SUDO_MODE = 'sudo-access';
export const SUDO_MODE_EVENT = 'admin-bridge/sudo-mode';
const SANDBOXES = ['read-only', 'workspace-write', 'danger-full-access'];
const HOOKS = ['capture', 'commitFull', 'restore', 'isUnchanged', 'isFull', 'isLive', 'audit'];

function snapshot(value) {
  exactKeys(value, ['preset', 'sandbox', 'approval']);
  if (typeof value.preset !== 'string' || !value.preset || value.preset === SUDO_MODE ||
      !SANDBOXES.includes(value.sandbox) || !['ask', 'never'].includes(value.approval))
    fail('invalid_session', 'Cannot capture this session’s native permission mode.');
  return Object.freeze({ preset: value.preset, sandbox: value.sandbox, approval: value.approval });
}

// Knob writes and private rollback journal updates must be synchronous.
function sync(callback, ...args) {
  const result = callback(...args);
  if (result && typeof result.then === 'function') {
    Promise.resolve(result).catch(() => {});
    fail('invalid_session', 'Sudo mode callbacks must be synchronous.');
  }
  return result;
}

/**
 * Ephemeral Sudo capability over the existing Full access preset. Neither the
 * preset nor the recovery journal grants root: only this exact live record and
 * its authenticated helper do. The raw bridge is deliberately not exported.
 *
 * Trusted command/tool adapters may prepare begin() intents. Only the protected
 * GUI password route authenticates them; no tool, preset or intent grants root.
 */
export class SudoMode {
  #bridge;
  #sessions = new Map();
  #closed = false;

  constructor(config = {}, dependencies = {}) {
    this.#bridge = new AdminBridge(config, {
      ...dependencies,
      workerFactory: dependencies.workerFactory ?? ((manifest, canProceed) =>
        new SudoWorker(manifest, { canProceed, requirePassword: true })),
    });
  }

  get operations() { return this.#bridge.operations; }
  get allowAllCommands() { return this.#bridge.allowAllCommands; }
  get maxTtlSeconds() { return this.#bridge.maxTtlSeconds; }
  manifest(ids, ttlSeconds) { return this.#bridge.manifest(ids, ttlSeconds); }

  /** Register the exact live agent identity and synchronous host-owned adapters. */
  registerSession(sessionId, hooks) {
    if (this.#closed || !hooks || !hooks.identity ||
        !['object', 'function'].includes(typeof hooks.identity) ||
        HOOKS.some(name => typeof hooks[name] !== 'function') ||
        (hooks.isDelegated !== undefined && typeof hooks.isDelegated !== 'function') ||
        this.#sessions.has(sessionId)) fail('invalid_session', 'An exact live session adapter is required.');
    const record = { hooks: { ...hooks }, mode: null, ownWrites: 0, retiring: false,
      restorationPending: false };
    const detach = this.#bridge.registerSession(sessionId,
      () => this.#allowed(record), info => this.#ended(record, info));
    this.#sessions.set(sessionId, record);
    return () => {
      if (this.#sessions.get(sessionId) !== record) return;
      record.retiring = true;
      this.lock(sessionId, 'session-disposed');
      detach();
      this.#sessions.delete(sessionId);
    };
  }

  register(sessionId, hooks) { return this.registerSession(sessionId, hooks); }

  #live(record) {
    try { return sync(record.hooks.isLive) === true; } catch { return false; }
  }

  #allowed(record) {
    const mode = record.mode;
    if (!mode || record.retiring || !this.#live(record)) return false;
    // A journal or preset replay never creates mode. This narrow suppression is
    // only for our own synchronous knob writes, never an asynchronous auth gap.
    if (record.ownWrites) return true;
    try {
      return mode.phase === 'active' ? sync(record.hooks.isFull) === true
        : sync(record.hooks.isUnchanged, mode.previous) === true;
    } catch { return false; }
  }

  #write(record, callback) {
    record.ownWrites++;
    try { return callback(); } finally { record.ownWrites--; }
  }

  #audit(record, mode, action, reason) {
    sync(record.hooks.audit, SUDO_MODE_EVENT, Object.freeze({
      action, generation: mode.generation, previous: mode.previous,
      ...(reason === undefined ? {} : { reason }),
    }));
  }

  /**
   * Create one password intent, not authority. identity cannot be supplied by a
   * JSON/model caller; the adapter supplies its captured, exact receiving agent.
   * The complete frozen operator scope and configured TTL are noneditable.
   */
  begin(sessionId, intent) {
    const record = this.#sessions.get(sessionId);
    if (!record || record.retiring || !this.#live(record) ||
        !['permission-command', 'agent-tool'].includes(intent?.source) || intent.identity !== record.hooks.identity)
      fail('invalid_session', 'Select Sudo access in this live session’s permission picker.');
    if (record.hooks.isDelegated && sync(record.hooks.isDelegated) !== false)
      fail('policy_denied', 'Delegated sessions cannot enter Sudo access.');
    if (record.restorationPending)
      fail('restoration_pending', 'Root access is off, but prior permission restoration could not be confirmed. Recover the session before entering Sudo access again.');
    // Every explicit selection is a fresh entry, not renewal: remove old root,
    // restore the prior native mode, and obtain a new nonce/password. A failed
    // or cancelled password attempt still obeys the bridge's cooldown.
    if (record.mode) this.lock(sessionId, 'reentry');
    const previous = snapshot(sync(record.hooks.capture));
    const manifest = this.manifest(this.operations.map(op => op.id), this.maxTtlSeconds);
    const mode = { phase: 'pending', previous, generation: randomUUID(), requestId: null,
      touched: false, preserveNative: false };
    record.mode = mode;
    try {
      const pending = this.#bridge.requestUnlock(sessionId, manifest);
      // The legacy bridge resolves this promise after authentication. Our own
      // authenticate() separately commits the permission transition first.
      pending.catch(() => {});
      mode.requestId = this.#bridge.describe(sessionId).requestId;
      if (!mode.requestId) fail('cancelled', 'Sudo access request was cancelled.');
      return this.describe(sessionId);
    } catch (error) {
      this.lock(sessionId, 'entry-failed');
      throw error;
    }
  }

  async authenticate(sessionId, requestId, password) {
    const record = this.#sessions.get(sessionId);
    const mode = record?.mode;
    if (!mode || mode.phase !== 'pending' || mode.requestId !== requestId)
      fail('stale_request', 'This authentication request is stale or unavailable.');
    mode.phase = 'authenticating';
    try {
      const pending = this.#bridge.authenticate(sessionId, requestId, password);
      password = undefined;
      await pending;
      if (record.mode !== mode || !this.#allowed(record))
        fail('cancelled', 'The permission selection changed during authentication.');
      this.#write(record, () => {
        // Persist rollback information BEFORE changing either native knob. A
        // crash after this update is recovery work, never a remembered grant.
        this.#audit(record, mode, 'enter');
        mode.touched = true;
        sync(record.hooks.commitFull, mode.previous);
        if (record.mode !== mode || !this.#live(record) || sync(record.hooks.isFull) !== true)
          fail('cancelled', 'Could not commit the Full access permission transition.');
        // The adapter records its post-write session.seq cutoff durably before
        // the root wrapper becomes active. Failure follows the same rollback path.
        this.#audit(record, mode, 'commit');
        if (record.mode !== mode || !this.#live(record) || sync(record.hooks.isFull) !== true)
          fail('cancelled', 'Could not finalize the Full access permission transition.');
        mode.phase = 'active'; // Publish authority last, after all synchronous writes.
      });
      // Expiry/worker close can occur during any callback. The public projection
      // must not return success if checking the raw lease revokes this generation.
      const status = this.describe(sessionId);
      if (!status.modeActive) fail('cancelled', 'Sudo access ended before activation.');
      return { state: 'unlocked', modeActive: true };
    } catch (error) {
      if (record.mode === mode) this.lock(sessionId, 'authentication-failed');
      if (error instanceof BridgeError && error.code === 'password_required')
        throw new BridgeError('password_required', 'Sudo access requires password-based sudo authentication; passwordless sudo is not supported.');
      throw new BridgeError('authentication_failed', 'Authentication failed, expired, or was cancelled.');
    } finally { password = undefined; }
  }

  async run(sessionId, operationId, signal) {
    const record = this.#sessions.get(sessionId);
    if (!record || record.mode?.phase !== 'active' || !this.describe(sessionId).modeActive)
      fail('locked', 'Use admin_request or select Sudo access, then authenticate in the GUI first.');
    return this.#bridge.run(sessionId, operationId, signal);
  }

  async runCommand(sessionId, request, signal) {
    const record = this.#sessions.get(sessionId);
    if (!record || record.mode?.phase !== 'active' || !this.describe(sessionId).modeActive)
      fail('locked', 'Use admin_request or select Sudo access, then authenticate in the GUI first.');
    return this.#bridge.runCommand(sessionId, request, signal);
  }

  describe(sessionId) {
    const record = this.#sessions.get(sessionId);
    const value = this.#bridge.describe(sessionId); // Rechecks independent deadline.
    const mode = record?.mode;
    const modeActive = mode?.phase === 'active' && value.state === 'unlocked';
    return {
      ...value,
      state: value.state === 'disabled' ? 'locked'
        : value.state === 'unlocked' && !modeActive ? 'authenticating' : value.state,
      modeActive,
      ...(record?.restorationPending ? { restorationPending: true } : {}),
      ...(mode ? { previousPreset: mode.previous.preset } : {}),
    };
  }

  /** Every ordinary permission selection calls lock BEFORE its original handler. */
  lock(sessionId, reason = 'locked') {
    const record = this.#sessions.get(sessionId);
    if (record?.mode) {
      const mode = record.mode;
      // Invalidate the wrapper before closing the helper or invoking restoration.
      record.mode = null;
      try { this.#bridge.lock(sessionId, reason); }
      finally { this.#restore(record, mode, reason); }
    } else this.#bridge.lock(sessionId, reason);
    return { state: 'locked', modeActive: false };
  }

  /** Match only the exact browser request, so stale disconnects cannot revoke a new entry. */
  cancelRequest(sessionId, requestId) {
    if (this.#sessions.get(sessionId)?.mode?.requestId === requestId)
      this.lock(sessionId, 'cancelled');
  }

  /** External native writes revoke root but preserve the newer native user choice. */
  observeNativeChange(sessionId) {
    const record = this.#sessions.get(sessionId);
    if (!record?.mode || record.ownWrites) return;
    record.mode.preserveNative = true;
    this.lock(sessionId, 'native-change');
  }

  #ended(record, { requestId, reason }) {
    const mode = record.mode;
    if (!mode || mode.requestId !== requestId) return;
    record.mode = null;
    this.#restore(record, mode, reason);
  }

  #restore(record, mode, reason) {
    if (!mode.touched) return; // Pending intent never changed native permissions.
    try {
      this.#write(record, () => {
        // A missed notification must not overwrite a newer native selection.
        if (mode.phase === 'active' && sync(record.hooks.isFull) !== true)
          mode.preserveNative = true;
        if (!mode.preserveNative) sync(record.hooks.restore, mode.previous);
        this.#audit(record, mode, 'exit', reason);
      });
    } catch (error) {
      // Root is already gone. Keep the unmatched journal for recovery and make
      // failed restoration visible rather than silently claiming a safe mode.
      record.restorationPending = true;
      throw error;
    }
  }

  dispose() {
    if (this.#closed) return;
    this.#closed = true;
    for (const [id, record] of this.#sessions) {
      record.retiring = true;
      try { this.lock(id, 'plugin-disposed'); } catch {}
    }
    this.#bridge.dispose();
    this.#sessions.clear();
  }
}
