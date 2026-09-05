import test from 'node:test';
import assert from 'node:assert/strict';
import { SudoMode, SUDO_MODE_EVENT } from '../src/mode.js';
import { AdminBridge } from '../src/bridge.js';
import { BridgeError } from '../src/policy.js';

// Injected workers ONLY: no sudo process, real authentication or policy mutation.
const SECRET = 'synthetic-mode-test-secret';
const full = { preset: 'danger-full-access', sandbox: 'danger-full-access', approval: 'never' };
const readOnly = { preset: 'read-only', sandbox: 'read-only', approval: 'ask' };
const workspace = { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask' };
const operations = [
  { id: 'inspect', label: 'Inspect', executable: '/usr/bin/id', args: ['-u'], timeoutSeconds: 2 },
  { id: 'other', label: 'Other', executable: '/usr/bin/id', args: ['-g'], timeoutSeconds: 2 },
];
const code = expected => error => error instanceof BridgeError && error.code === expected;
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const observe = promise => promise.then(value => ({ value }), error => ({ error }));

function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  let now = 1000;
  const workers = [];
  const states = new Map();
  const mode = new SudoMode({ operations: options.operations ?? operations, allowAllCommands: options.allowAllCommands, maxTtlSeconds: 30 }, {
    now: () => now, requestTimeoutMs: 2000,
    workerFactory: (manifest, canProceed) => {
      const worker = {
        manifest, canProceed, calls: [], closeCount: 0,
        authenticate(password) {
          assert.equal(password, SECRET);
          return options.authentication?.promise ?? Promise.resolve();
        },
        run(id) { this.calls.push(id); return Promise.resolve({ exitCode: 0, stdout: 'ok' }); },
        runCommand(request) { this.calls.push(request); return Promise.resolve({ exitCode: 0, stdout: 'shell-ok' }); },
        close() { this.closeCount++; this.onClose?.(); },
      };
      workers.push(worker);
      return worker;
    },
  });
  t.after(() => mode.dispose());
  const add = (id, initial = workspace, overrides = {}) => {
    const state = { native: { ...initial }, identity: {}, live: true, delegated: false,
      restores: [], journal: [], commits: 0 };
    states.set(id, state);
    const hooks = {
      identity: state.identity,
      capture: () => state.native,
      isLive: () => state.live,
      isDelegated: () => state.delegated,
      isUnchanged: previous => JSON.stringify(state.native) === JSON.stringify(previous),
      isFull: () => JSON.stringify(state.native) === JSON.stringify(full),
      commitFull(previous) {
        state.commits++;
        assert.deepEqual(state.journal.at(-1), { event: SUDO_MODE_EVENT,
          data: { action: 'enter', generation: state.journal.at(-1).data.generation, previous } });
        state.native = { ...full };
        mode.observeNativeChange(id); // Own canonical writer events must be suppressed.
      },
      restore(previous) {
        state.restores.push(previous);
        state.native = { ...previous };
        mode.observeNativeChange(id);
      },
      audit(event, data) {
        if (data.action === 'commit') {
          assert.deepEqual(state.native, full);
          assert.equal(state.live, true);
          assert.equal(mode.describe(id).modeActive, false);
          assert.equal(state.journal.at(-1).data.action, 'enter');
          assert.equal(data.generation, state.journal.at(-1).data.generation);
        }
        state.journal.push({ event, data });
      },
      ...overrides,
    };
    state.detach = mode.registerSession(id, hooks);
    state.begin = () => mode.begin(id, { source: 'permission-command', identity: state.identity });
    return state;
  };
  const state = add('a', options.initial ?? workspace, options.hooks);
  return { mode, workers, states, state, add,
    advance(ms) { now += ms; t.mock.timers.tick(ms); },
    async enter(id = 'a') {
      const pending = states.get(id).begin();
      assert.equal(pending.modeActive, false);
      return mode.authenticate(id, pending.requestId, SECRET);
    },
  };
}

test('idle never policy is locked, not disabled, and no capability exists by default', async t => {
  const f = fixture(t, { initial: full });
  assert.deepEqual(f.state.native, full);
  assert.equal(f.mode.describe('a').state, 'locked');
  assert.equal(f.mode.describe('a').modeActive, false);
  assert.equal(f.mode.describe('absent').state, 'unavailable');
  await assert.rejects(f.mode.run('a', 'inspect'), code('locked'));
  await assert.rejects(f.mode.authenticate('a', 'fake', SECRET), code('stale_request'));
  assert.equal(f.workers.length, 0);
});

test('only the exact captured human-command identity may prepare a password intent', t => {
  const f = fixture(t);
  for (const intent of [undefined, {}, { source: 'tool', identity: f.state.identity },
    { source: 'permission-command', identity: {} },
    { source: 'permission-command', identity: 'a' }]) {
    assert.throws(() => f.mode.begin('a', intent), code('invalid_session'));
  }
  f.state.delegated = true;
  assert.throws(() => f.state.begin(), code('policy_denied'));
  f.state.delegated = false;
  f.state.live = false;
  assert.throws(() => f.state.begin(), code('invalid_session'));
  assert.equal(f.workers.length, 0);
});

test('begin fixes the entire allowlist and TTL without changing either native knob', async t => {
  const f = fixture(t, { initial: readOnly });
  const pending = f.state.begin();
  assert.equal(pending.state, 'pending');
  assert.equal(pending.modeActive, false);
  assert.equal(pending.previousPreset, 'read-only');
  assert.equal(pending.ttlSeconds, 30);
  assert.deepEqual(pending.selectedOperations, operations);
  assert.equal(typeof pending.requestId, 'string');
  assert.deepEqual(f.state.native, readOnly);
  assert.deepEqual(f.state.journal, []);
  await assert.rejects(f.mode.run('a', 'inspect'), code('locked'));
  const replacement = f.state.begin();
  assert.notEqual(replacement.requestId, pending.requestId);
  assert.equal(f.workers.length, 0);
  f.mode.cancelRequest('a', pending.requestId);
  assert.equal(f.mode.describe('a').state, 'pending');
  f.mode.cancelRequest('a', replacement.requestId);
  assert.equal(f.mode.describe('a').state, 'locked');
  assert.deepEqual(f.state.restores, []);
});

test('empty restricted operator allowlist cannot open an authentication request', t => {
  const f = fixture(t, { operations: [], allowAllCommands: false });
  assert.throws(() => f.state.begin(), code('invalid_request'));
  assert.equal(f.mode.describe('a').state, 'locked');
  assert.equal(f.workers.length, 0);
});

test('agent intent permits all commands only after GUI authentication and native commit', async t => {
  const f = fixture(t, { operations: [] });
  assert.equal(f.mode.allowAllCommands, true);
  assert.equal(f.mode.describe('a').allowAllCommands, true);
  const intent = { source: 'agent-tool', identity: f.state.identity };
  f.state.delegated = true;
  assert.throws(() => f.mode.begin('a', intent), code('policy_denied'));
  f.state.delegated = false;
  assert.throws(() => f.mode.begin('a', { ...intent, identity: {} }), code('invalid_session'));
  const pending = f.mode.begin('a', intent);
  assert.equal(pending.allowAllCommands, true);
  assert.deepEqual(f.state.native, workspace);
  await assert.rejects(f.mode.runCommand('a', { command: 'printf test' }), code('locked'));
  await f.mode.authenticate('a', pending.requestId, SECRET);
  assert.equal(f.workers[0].manifest.allowAllCommands, true);
  assert.equal(Object.isFrozen(f.workers[0].manifest), true);
  assert.equal((await f.mode.runCommand('a', { command: 'printf test' })).stdout, 'shell-ok');
  assert.deepEqual(f.workers[0].calls, [{ command: 'printf test', workdir: '/', timeoutSeconds: 120 }]);
  f.add('other-session', full);
  await assert.rejects(f.mode.runCommand('other-session', { command: 'true' }), code('locked'));
  f.mode.lock('a');
  await assert.rejects(f.mode.runCommand('a', { command: 'true' }), code('locked'));
  assert.deepEqual(f.state.native, workspace);
});

test('restricted mode permits legacy IDs but refuses arbitrary commands', async t => {
  const f = fixture(t, { allowAllCommands: false });
  await f.enter();
  assert.equal(f.mode.describe('a').allowAllCommands, false);
  assert.equal(f.workers[0].manifest.allowAllCommands, false);
  await f.mode.run('a', 'inspect');
  await assert.rejects(f.mode.runCommand('a', { command: 'true' }), code('not_authorized'));
  assert.deepEqual(f.workers[0].calls, ['inspect']);
});

test('successful password entry commits Full access plus capability, never ask policy', async t => {
  const f = fixture(t, { initial: readOnly });
  assert.deepEqual(await f.enter(), { state: 'unlocked', modeActive: true });
  assert.deepEqual(f.state.native, full);
  assert.equal(f.state.commits, 1);
  const active = f.mode.describe('a');
  assert.equal(active.modeActive, true);
  assert.equal(active.requestId, undefined);
  assert.equal(active.previousPreset, 'read-only');
  assert.equal(JSON.stringify(active).includes(SECRET), false);
  assert.equal(JSON.stringify(f.state.journal).includes(SECRET), false);
  await f.mode.run('a', 'inspect');
  await f.mode.run('a', 'other');
  await assert.rejects(f.mode.run('a', 'inspect;id'), code('not_authorized'));
  assert.deepEqual(f.workers[0].calls, ['inspect', 'other']);
  assert.deepEqual(f.mode.lock('a'), { state: 'locked', modeActive: false });
  assert.deepEqual(f.state.native, readOnly);
  assert.equal(f.state.restores.length, 1);
  assert.deepEqual(f.state.journal.map(row => row.data.action), ['enter', 'commit', 'exit']);
  for (const row of f.state.journal) {
    assert.equal(row.event, SUDO_MODE_EVENT);
    assert.equal(row.data.generation, f.state.journal[0].data.generation);
    assert.deepEqual(row.data.previous, readOnly);
  }
  f.mode.lock('a');
  assert.equal(f.state.restores.length, 1);
});

test('all three prior modes restore exactly, including already Full access', async t => {
  const f = fixture(t);
  for (const [index, initial] of [readOnly, workspace, full].entries()) {
    const id = `s${index}`;
    const state = f.add(id, initial);
    await f.enter(id);
    f.mode.lock(id);
    assert.deepEqual(state.native, initial);
    assert.equal(state.restores.length, 1);
    assert.equal(f.mode.describe(id).modeActive, false);
  }
});

test('raw helper readiness cannot expose unlocked state or admit runs before commit', async t => {
  const f = fixture(t);
  const state = f.add('checking', workspace, {
    commitFull() {
      const during = f.mode.describe('checking');
      assert.equal(during.state, 'authenticating');
      assert.equal(during.modeActive, false);
      const denied = f.mode.run('checking', 'inspect');
      denied.catch(() => {});
      state.denied = denied;
      state.native = { ...full };
    },
  });
  await f.enter('checking');
  await assert.rejects(state.denied, code('locked'));
  assert.deepEqual(f.workers[0].calls, []);
});

test('each new entry requires a fresh nonce and a fresh authentication worker', async t => {
  const f = fixture(t);
  const first = f.state.begin();
  await f.mode.authenticate('a', first.requestId, SECRET);
  const second = f.state.begin(); // Explicit repeated selection, not lease renewal.
  assert.equal(f.workers[0].closeCount, 1);
  assert.deepEqual(f.state.native, workspace);
  assert.equal(f.mode.describe('a').modeActive, false);
  assert.notEqual(second.requestId, first.requestId);
  f.mode.cancelRequest('a', first.requestId);
  assert.equal(f.mode.describe('a').state, 'pending');
  await assert.rejects(f.mode.authenticate('a', first.requestId, SECRET), code('stale_request'));
  await f.mode.authenticate('a', second.requestId, SECRET);
  assert.equal(f.workers.length, 2);
});

test('concurrent authentication claims an intent once and state stays unchanged until ready', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.state.begin();
  const auth = f.mode.authenticate('a', pending.requestId, SECRET);
  assert.equal(f.mode.describe('a').state, 'authenticating');
  assert.deepEqual(f.state.native, workspace);
  await assert.rejects(f.mode.authenticate('a', pending.requestId, SECRET), code('stale_request'));
  authentication.resolve();
  await auth;
  assert.equal(f.workers.length, 1);
});

test('authentication failure does not change permissions or journal a successful entry', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.state.begin();
  const auth = observe(f.mode.authenticate('a', pending.requestId, SECRET));
  authentication.reject(new Error('synthetic PAM failure'));
  assert.equal((await auth).error.code, 'authentication_failed');
  assert.deepEqual(f.state.native, workspace);
  assert.deepEqual(f.state.restores, []);
  assert.deepEqual(f.state.journal, []);
  assert.equal(f.mode.describe('a').modeActive, false);
});

test('native selection during authentication cancels entry and preserves the newer choice', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.state.begin();
  const auth = observe(f.mode.authenticate('a', pending.requestId, SECRET));
  f.state.native = { ...readOnly };
  f.mode.observeNativeChange('a');
  authentication.resolve();
  assert.equal((await auth).error.code, 'authentication_failed');
  assert.deepEqual(f.state.native, readOnly);
  assert.deepEqual(f.state.restores, []);
  assert.equal(f.mode.describe('a').state, 'locked');
});

test('unobserved native mutation before helper readiness still fails the live gate', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.state.begin();
  const auth = observe(f.mode.authenticate('a', pending.requestId, SECRET));
  f.state.native = { ...readOnly };
  assert.equal(f.workers[0].canProceed(), false);
  authentication.resolve();
  assert.equal((await auth).error.code, 'authentication_failed');
  assert.deepEqual(f.state.native, readOnly);
});

test('external native changes revoke active root without restoring stale permissions', async t => {
  const f = fixture(t, { initial: workspace });
  await f.enter();
  f.state.native = { ...readOnly };
  f.mode.observeNativeChange('a');
  assert.deepEqual(f.state.native, readOnly);
  assert.deepEqual(f.state.restores, []);
  assert.equal(f.state.journal[2].data.reason, 'native-change');
  await assert.rejects(f.mode.run('a', 'inspect'), code('locked'));
  assert.equal(f.workers[0].closeCount, 1);
});

test('expiry and worker failure revoke and restore even without a new API call', async t => {
  const f = fixture(t, { initial: readOnly });
  await f.enter();
  f.advance(30_000);
  assert.deepEqual(f.state.native, readOnly);
  assert.equal(f.state.restores.length, 1);
  assert.equal(f.mode.describe('a').modeActive, false);
  await f.enter();
  f.workers[1].close();
  assert.deepEqual(f.state.native, readOnly);
  assert.equal(f.state.restores.length, 2);
  await assert.rejects(f.mode.run('a', 'inspect'), code('locked'));
});

test('partial knob commit failure rolls back from the write-ahead journal', async t => {
  const f = fixture(t);
  const state = f.add('broken', readOnly, {
    commitFull() {
      state.native = { ...readOnly, sandbox: 'danger-full-access' };
      throw new Error('synthetic append failure');
    },
  });
  await assert.rejects(f.enter('broken'), code('authentication_failed'));
  assert.deepEqual(state.native, readOnly);
  assert.equal(state.restores.length, 1);
  assert.deepEqual(state.journal.map(row => row.data.action), ['enter', 'exit']);
  assert.equal(f.workers[0].closeCount, 1);
});

test('commit audit failure revokes root before restoring prior native permissions', async t => {
  const f = fixture(t);
  const calls = [];
  const state = f.add('audit-failure', readOnly, {
    audit(event, data) {
      assert.equal(event, SUDO_MODE_EVENT);
      calls.push(data.action);
      if (data.action === 'commit') {
        assert.deepEqual(state.native, full);
        assert.equal(f.mode.describe('audit-failure').modeActive, false);
        throw new Error('synthetic private journal fsync failure');
      }
      state.journal.push({ event, data });
    },
    restore(previous) {
      assert.equal(f.workers[0].closeCount, 1);
      assert.equal(f.mode.describe('audit-failure').modeActive, false);
      state.restores.push(previous);
      state.native = { ...previous };
    },
  });
  await assert.rejects(f.enter('audit-failure'), error => {
    assert.equal(error.code, 'authentication_failed');
    assert.equal(error.message.includes('fsync'), false);
    return true;
  });
  assert.deepEqual(calls, ['enter', 'commit', 'exit']);
  assert.deepEqual(state.native, readOnly);
  assert.equal(state.restores.length, 1);
  assert.equal(f.mode.describe('audit-failure').state, 'locked');
  assert.equal(f.workers[0].closeCount, 1);
  await assert.rejects(f.mode.run('audit-failure', 'inspect'), code('locked'));
});

test('commit audit is skipped unless native Full access and liveness validate', async t => {
  const f = fixture(t);
  for (const failure of ['native', 'live']) {
    const state = f.add(failure, readOnly, {
      commitFull() {
        state.native = failure === 'native' ? { ...workspace } : { ...full };
        state.live = failure !== 'live';
      },
    });
    await assert.rejects(f.enter(failure), code('authentication_failed'));
    assert.deepEqual(state.journal.map(row => row.data.action), ['enter', 'exit']);
    assert.deepEqual(state.native, readOnly);
    assert.equal(f.mode.describe(failure).modeActive, false);
  }
});

test('commit audit cannot publish authority early or after synchronous cancellation', async t => {
  const f = fixture(t);
  let denied;
  const state = f.add('audit-cancel', workspace, {
    audit(event, data) {
      state.journal.push({ event, data });
      if (data.action !== 'commit') return;
      assert.equal(f.mode.describe('audit-cancel').state, 'authenticating');
      denied = observe(f.mode.run('audit-cancel', 'inspect'));
      f.mode.lock('audit-cancel', 'cancel-during-audit');
    },
  });
  await assert.rejects(f.enter('audit-cancel'), code('authentication_failed'));
  assert.equal((await denied).error.code, 'locked');
  assert.deepEqual(state.native, workspace);
  assert.deepEqual(state.journal.map(row => row.data.action), ['enter', 'commit', 'exit']);
  assert.equal(state.restores.length, 1);
  assert.equal(f.workers[0].closeCount, 1);
  assert.equal(f.mode.describe('audit-cancel').modeActive, false);
});

test('asynchronous commit audit is rejected and rolls back rather than granting root', async t => {
  const f = fixture(t);
  const state = f.add('async-audit', workspace, {
    audit(event, data) {
      state.journal.push({ event, data });
      if (data.action === 'commit') return Promise.resolve();
    },
  });
  await assert.rejects(f.enter('async-audit'), code('authentication_failed'));
  assert.deepEqual(state.native, workspace);
  assert.equal(f.workers[0].closeCount, 1);
  assert.equal(f.mode.describe('async-audit').modeActive, false);
});

test('restoration failure cannot retain root and leaves recovery journal unmatched', async t => {
  const f = fixture(t);
  const state = f.add('broken', workspace, {
    restore() { throw new Error('synthetic restore failure'); },
  });
  await f.enter('broken');
  assert.throws(() => f.mode.lock('broken'), /synthetic restore failure/);
  assert.equal(f.mode.describe('broken').modeActive, false);
  await assert.rejects(f.mode.run('broken', 'inspect'), code('locked'));
  assert.deepEqual(state.journal.map(row => row.data.action), ['enter', 'commit']);
  assert.equal(f.mode.describe('broken').restorationPending, true);
  assert.throws(() => state.begin(), code('restoration_pending'));
  assert.equal(f.workers[0].closeCount, 1);
});

test('sessions, disposed identities, replacements, forks and replay never inherit authority', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const old = f.state;
  const pending = old.begin();
  const auth = observe(f.mode.authenticate('a', pending.requestId, SECRET));
  old.detach();
  const replacement = f.add('a', full);
  old.detach();
  authentication.resolve();
  assert.equal((await auth).error.code, 'authentication_failed');
  const fork = f.add('fork', full);
  fork.journal = [...old.journal]; // An audit record is never a lease/capability.
  await assert.rejects(f.mode.run('a', 'inspect'), code('locked'));
  await assert.rejects(f.mode.run('fork', 'inspect'), code('locked'));
  assert.equal(f.mode.describe('a').state, 'locked');
  assert.equal(f.mode.describe('fork').modeActive, false);
  assert.deepEqual(replacement.restores, []);
});

test('detach and plugin disposal restore once and withdraw every active capability', async t => {
  const f = fixture(t);
  await f.enter();
  f.state.detach();
  assert.deepEqual(f.state.native, workspace);
  assert.equal(f.mode.describe('a').state, 'unavailable');
  const other = f.add('b', readOnly);
  await f.enter('b');
  f.mode.dispose();
  assert.deepEqual(other.native, readOnly);
  assert.equal(f.mode.describe('b').state, 'unavailable');
  f.mode.dispose();
  assert.equal(other.restores.length, 1);
});

test('bridge optional lifecycle observer runs once after authority removal and contains failures', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  const bridge = new AdminBridge({ operations, maxTtlSeconds: 30 }, {
    workerFactory: () => ({ authenticate: async () => {}, run: async () => {}, close() {} }),
  });
  t.after(() => bridge.dispose());
  let ended = 0;
  bridge.registerSession('a', () => true, ({ requestId, reason }) => {
    ended++;
    assert.equal(requestId, nonce);
    assert.equal(reason, 'test-end');
    assert.equal(bridge.describe('a').state, 'locked');
    throw new Error('observer must not resurrect authority');
  });
  const request = bridge.requestUnlock('a', bridge.manifest(['inspect'], 30));
  const nonce = bridge.describe('a').requestId;
  await bridge.authenticate('a', nonce, SECRET);
  await request;
  assert.deepEqual(bridge.lock('a', 'test-end'), { state: 'locked' });
  bridge.lock('a');
  assert.equal(ended, 1);
});

test('failed and cancelled authentication retain throttling across repeated selections', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const first = f.state.begin();
  const auth = observe(f.mode.authenticate('a', first.requestId, SECRET));
  assert.throws(() => f.state.begin(), code('rate_limited'));
  assert.equal(f.mode.describe('a').state, 'locked');
  authentication.resolve();
  assert.equal((await auth).error.code, 'authentication_failed');
  assert.deepEqual(f.state.native, workspace);
  assert.equal(f.workers.length, 1);
  f.advance(10_000);
  const next = f.state.begin();
  assert.notEqual(next.requestId, first.requestId);
});

test('a missed external knob notification still preserves the newer native selection', async t => {
  const f = fixture(t);
  await f.enter();
  f.state.native = { ...readOnly };
  f.advance(250); // Independent bridge sweep sees isFull false.
  assert.deepEqual(f.state.native, readOnly);
  assert.equal(f.state.restores.length, 0);
  assert.equal(f.mode.describe('a').modeActive, false);
  assert.equal(f.state.journal.at(-1).data.action, 'exit');
});

test('synchronous cancellation during the permission commit cannot publish late authority', async t => {
  const f = fixture(t);
  const state = f.add('cancel', workspace, {
    commitFull() {
      state.native = { ...full };
      f.mode.lock('cancel', 'cancel-during-commit');
    },
  });
  await assert.rejects(f.enter('cancel'), code('authentication_failed'));
  assert.deepEqual(state.native, workspace);
  assert.equal(state.restores.length, 1);
  assert.equal(f.mode.describe('cancel').state, 'locked');
  assert.equal(f.mode.describe('cancel').modeActive, false);
});

test('the safe password-required failure is preserved, never raw worker diagnostics', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const first = f.state.begin();
  const auth = observe(f.mode.authenticate('a', first.requestId, SECRET));
  authentication.reject(new BridgeError('password_required', 'unsafe diagnostic must not be relayed'));
  const { error } = await auth;
  assert.equal(error.code, 'password_required');
  assert.equal(error.message, 'Sudo access requires password-based sudo authentication; passwordless sudo is not supported.');
  assert.equal(f.mode.describe('a').modeActive, false);
  assert.deepEqual(f.state.native, workspace);
  assert.throws(() => f.state.begin(), code('rate_limited'));
});
