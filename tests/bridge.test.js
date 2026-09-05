import test from 'node:test';
import assert from 'node:assert/strict';
import { AdminBridge } from '../src/bridge.js';
import { BridgeError, publicError, selectManifest, validateCommand, validateOperations } from '../src/policy.js';

// Only synthetic credentials and injected workers are used; these tests never spawn sudo.
const SECRET = 'synthetic-unit-test-secret';
const operations = () => [
  { id: 'inspect', label: 'Inspect service', executable: '/usr/bin/systemctl', args: ['status', 'example.service'], timeoutSeconds: 2 },
  { id: 'restart', label: 'Restart service', executable: '/usr/bin/systemctl', args: ['restart', 'example.service'], timeoutSeconds: 3 },
];
const code = expected => error => {
  assert.ok(error instanceof BridgeError);
  assert.equal(error.code, expected);
  return true;
};
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
// Observe rejection immediately, even if the adversarial action precedes the assertion.
const observe = promise => promise.then(value => ({ value }), error => ({ error }));
async function rejected(outcome, expected) {
  const { error } = await outcome;
  assert.ok(error, 'expected the operation to reject');
  code(expected)(error);
}
function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  let now = 1000;
  let approvals = true;
  const workers = [];
  const bridge = new AdminBridge({ operations: operations(), maxTtlSeconds: 60 }, {
    now: () => now,
    requestTimeoutMs: 2000,
    workerFactory: (manifest, canProceed) => {
      if (options.factoryError) throw options.factoryError;
      const worker = {
        manifest, canProceed, closeCount: 0, authCalls: [], runCalls: [], pendingRun: null,
        authenticate(password) {
          this.authCalls.push(password);
          return options.authentication?.promise ?? Promise.resolve();
        },
        run(operationId) {
          this.runCalls.push(operationId);
          if (options.holdRun) {
            this.pendingRun = deferred();
            return this.pendingRun.promise;
          }
          return Promise.resolve({ exitCode: 0, stdout: 'ok', stderr: '', truncated: false, timedOut: false });
        },
        runCommand(request) { return this.run(request); },
        close() {
          this.closeCount++;
          this.pendingRun?.reject(new BridgeError('locked', 'Worker closed.'));
          this.onClose?.();
        },
      };
      workers.push(worker);
      return worker;
    },
  });
  const detach = bridge.registerSession('session-a', () => approvals);
  bridge.registerSession('session-b', () => true);
  t.after(() => bridge.dispose());
  return {
    bridge, workers, detach,
    policy: value => { approvals = value; },
    advance(ms) { now += ms; t.mock.timers.tick(ms); },
    start(sessionId = 'session-a', signal, ids = ['inspect'], ttlSeconds = 30) {
      const manifest = bridge.manifest(ids, ttlSeconds);
      const outcome = observe(bridge.requestUnlock(sessionId, manifest, signal));
      return { outcome, requestId: bridge.describe(sessionId).requestId, manifest };
    },
  };
}
async function unlock(f, options = {}) {
  const request = f.start(options.sessionId, options.signal, options.ids, options.ttlSeconds);
  assert.deepEqual(await f.bridge.authenticate(options.sessionId ?? 'session-a', request.requestId, SECRET), { state: 'unlocked' });
  assert.equal((await request.outcome).value.state, 'unlocked');
  return request;
}

test('policy validates immutable fixed argv and rejects invalid definitions and lifetime/scope requests', () => {
  const input = operations();
  const validated = validateOperations(input);
  input[0].args.push('injected');
  assert.equal(validated[0].args.length, 2);
  assert.ok(Object.isFrozen(validated));
  assert.ok(Object.isFrozen(validated[0]));
  assert.ok(Object.isFrozen(validated[0].args));
  const valid = operations()[0];
  for (const value of [null, {}, Array(17).fill(valid), [valid, valid],
    [{ ...valid, executable: 'systemctl' }], [{ ...valid, executable: '/bin/tool\nother' }],
    [{ ...valid, args: ['bad\0arg'] }], [{ ...valid, args: ['bad\rarg'] }],
    [{ ...valid, args: Array(33).fill('x') }], [{ ...valid, args: ['x'.repeat(1025)] }],
    [{ ...valid, timeoutSeconds: 0 }], [{ ...valid, timeoutSeconds: 121 }],
    [{ ...valid, timeoutSeconds: 1.5 }], [{ ...valid, label: '\u001b[31m' }],
    [{ ...valid, id: '../inspect' }]]) {
    assert.throws(() => validateOperations(value), code('invalid_config'));
  }
  assert.throws(() => validateOperations([{ ...valid, command: 'unrestricted' }]), code('invalid_request'));
  for (const ttl of [undefined, 0, 29, 61, 900, 30.5, '30', NaN, Infinity]) {
    assert.throws(() => selectManifest(validated, ['inspect'], ttl, 60), code('invalid_request'));
  }
  for (const ids of [[], ['missing'], ['inspect', 'inspect'], ['inspect;id'], 'inspect', [{ id: 'inspect' }]]) {
    assert.throws(() => selectManifest(validated, ids, 30, 60), code('invalid_request'));
  }
  for (const ttl of [30, 60]) {
    const manifest = selectManifest(validated, ['inspect'], ttl, 60);
    assert.deepEqual(manifest.operations.map(op => op.id), ['inspect']);
    assert.ok(Object.isFrozen(manifest));
    assert.ok(Object.isFrozen(manifest.operations));
  }
});

test('arbitrary command validation bounds Unicode bytes, cwd, shape and timeout', () => {
  assert.deepEqual(validateCommand({ command: 'echo one\necho two' }),
    { command: 'echo one\necho two', workdir: '/', timeoutSeconds: 120 });
  for (const request of [null, {}, { command: '' }, { command: '  \n' }, { command: 1 },
    { command: '\0' }, { command: '\ud800' }, { command: 'é'.repeat(8193) },
    { command: 'true', workdir: 'relative' }, { command: 'true', workdir: '/a\n' },
    { command: 'true', workdir: '/' + 'é'.repeat(2048) },
    ...[0, 121, true, 1.5, '1', null].map(timeoutSeconds => ({ command: 'true', timeoutSeconds })),
    { command: 'true', operationId: 'inspect' }, { command: 'true', env: {} }]) {
    assert.throws(() => validateCommand(request), code('invalid_request'));
  }
  assert.ok(Object.isFrozen(validateCommand({ command: 'x'.repeat(16384), workdir: '/tmp', timeoutSeconds: 1 })));
  for (const allowAllCommands of [null, 1, 'true', {}])
    assert.throws(() => new AdminBridge({ allowAllCommands }), code('invalid_config'));
});

test('arbitrary command cancellation and expiry revoke the same authenticated lease', async t => {
  const f = fixture(t, { holdRun: true });
  await unlock(f);
  const controller = new AbortController();
  const running = observe(f.bridge.runCommand('session-a', { command: 'sleep 10', timeoutSeconds: 2 }, controller.signal));
  controller.abort();
  await rejected(running, 'locked');
  assert.equal(f.workers[0].closeCount, 1);
  await unlock(f);
  const next = observe(f.bridge.runCommand('session-a', { command: 'sleep 10' }));
  f.advance(30000);
  await rejected(next, 'locked');
  await assert.rejects(f.bridge.runCommand('session-a', { command: 'true' }), code('locked'));
});

test('legacy manifest cannot acquire shell permission through config or later mutation', async t => {
  const f = fixture(t);
  const manifest = { version: 1, ttlSeconds: 30, operations: operations().slice(0, 1) };
  const pending = observe(f.bridge.requestUnlock('session-a', manifest));
  manifest.allowAllCommands = true;
  await f.bridge.authenticate('session-a', f.bridge.describe('session-a').requestId, SECRET);
  await pending;
  assert.equal(f.bridge.describe('session-a').allowAllCommands, false);
  await assert.rejects(f.bridge.runCommand('session-a', { command: 'true' }), code('not_authorized'));
});

test('configuration rejects excessive manifests and invalid maximum TTL', t => {
  for (const ttl of [0, 29, 901, '300', 30.5]) {
    assert.throws(() => new AdminBridge({ maxTtlSeconds: ttl }), code('invalid_config'));
  }
  const bridge = new AdminBridge({ operations: [
    { ...operations()[0], args: Array(32).fill('x'.repeat(1024)) },
  ] });
  t.after(() => bridge.dispose());
  assert.throws(() => bridge.manifest(['inspect'], 30), code('invalid_config'));
});

test('missing, disabled, unavailable, and non-boolean approval policy fail closed', async t => {
  const f = fixture(t);
  const manifest = f.bridge.manifest(['inspect'], 30);
  assert.equal(f.bridge.describe('missing').state, 'unavailable');
  assert.throws(() => f.bridge.requestUnlock('missing', manifest), code('policy_denied'));
  await assert.rejects(f.bridge.run('missing', 'inspect'), code('policy_denied'));
  await assert.rejects(f.bridge.authenticate('missing', 'nonce', SECRET), code('policy_denied'));
  for (const policy of [false, undefined, null, 1, 'true', {}, Promise.resolve(true)]) {
    f.policy(policy);
    assert.equal(f.bridge.describe('session-a').state, 'disabled');
    assert.throws(() => f.bridge.requestUnlock('session-a', manifest), code('policy_denied'));
    await assert.rejects(f.bridge.run('session-a', 'inspect'), code('policy_denied'));
  }
  f.bridge.registerSession('throws', () => { throw new Error('policy unavailable'); });
  assert.throws(() => f.bridge.requestUnlock('throws', manifest), code('policy_denied'));
  assert.equal(f.workers.length, 0);
  assert.throws(() => f.bridge.registerSession('session-a', () => true), code('invalid_session'));
  assert.throws(() => f.bridge.registerSession('../session', () => true), code('invalid_session'));
  assert.throws(() => f.bridge.registerSession('new', undefined), code('invalid_session'));
});

test('lease is scoped to its session and exact configured operation IDs, never shell commands', async t => {
  const f = fixture(t);
  await unlock(f);
  assert.deepEqual(f.workers[0].manifest.operations.map(op => op.id), ['inspect']);
  assert.deepEqual(await f.bridge.run('session-a', 'inspect'), {
    exitCode: 0, stdout: 'ok', stderr: '', truncated: false, timedOut: false,
  });
  for (const operationId of ['restart', 'id', 'inspect; /bin/sh', '/bin/sh', { command: 'id' }, ['inspect']]) {
    await assert.rejects(f.bridge.run('session-a', operationId), code('not_authorized'));
  }
  await assert.rejects(f.bridge.run('session-b', 'inspect'), code('locked'));
  assert.deepEqual(f.workers[0].runCalls, ['inspect']);
  const status = f.bridge.describe('session-a');
  assert.equal(status.requestId, undefined);
  assert.equal(JSON.stringify(status).includes(SECRET), false);
  assert.equal(JSON.stringify(status).includes('worker'), false);
});

test('nonce rejects wrong session, wrong length, stale and replayed authentication', async t => {
  const f = fixture(t);
  const pending = f.start();
  const wrongSameLength = `${pending.requestId[0] === 'a' ? 'b' : 'a'}${pending.requestId.slice(1)}`;
  for (const nonce of ['', null, undefined, 42, 'x'.repeat(10000), wrongSameLength]) {
    await assert.rejects(f.bridge.authenticate('session-a', nonce, SECRET), code('stale_request'));
  }
  await assert.rejects(f.bridge.authenticate('session-b', pending.requestId, SECRET), code('stale_request'));
  f.bridge.cancelRequest('session-a', wrongSameLength);
  assert.equal(f.bridge.describe('session-a').state, 'pending');
  assert.equal(f.workers.length, 0);
  await f.bridge.authenticate('session-a', pending.requestId, SECRET);
  await pending.outcome;
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, SECRET), code('stale_request'));
  assert.equal(f.workers.length, 1);
  f.bridge.lock('session-a');
  f.advance(10000);
  const next = f.start();
  assert.notEqual(next.requestId, pending.requestId);
  f.bridge.cancelRequest('session-a', pending.requestId);
  assert.equal(f.bridge.describe('session-a').state, 'pending');
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, SECRET), code('stale_request'));
  f.bridge.cancelRequest('session-a', next.requestId);
  await rejected(next.outcome, 'locked');
});

test('invalid password never starts a worker or consumes the authentication nonce', async t => {
  const f = fixture(t);
  const pending = f.start();
  for (const password of [null, 123, {}, 'line\nbreak', 'line\rbreak', 'nul\0byte', 'x'.repeat(4097), 'é'.repeat(2049)]) {
    await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, password), code('invalid_request'));
  }
  assert.equal(f.workers.length, 0);
  assert.equal(f.bridge.describe('session-a').requestId, pending.requestId);
  await f.bridge.authenticate('session-a', pending.requestId, '');
  assert.equal((await pending.outcome).value.state, 'unlocked');
});

test('concurrent authentication claims the nonce exactly once before awaiting the worker', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.start();
  const first = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  assert.equal(f.bridge.describe('session-a').state, 'authenticating');
  assert.equal(f.bridge.describe('session-a').requestId, undefined);
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, 'different-synthetic-secret'), code('stale_request'));
  assert.equal(f.workers.length, 1);
  assert.deepEqual(f.workers[0].authCalls, [SECRET]);
  authentication.resolve();
  assert.deepEqual((await first).value, { state: 'unlocked' });
  assert.equal((await pending.outcome).value.state, 'unlocked');
});

test('policy revocation while authentication awaits PAM cannot grant a lease (TOCTOU)', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.start();
  const auth = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  assert.equal(f.workers[0].canProceed(), true);
  f.policy(false);
  assert.equal(f.workers[0].canProceed(), false, 'the password-delivery guard reads live policy before the next sweep');
  authentication.resolve();
  await rejected(auth, 'authentication_failed');
  await rejected(pending.outcome, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'disabled');
  assert.ok(f.workers[0].closeCount >= 1);
  await assert.rejects(f.bridge.run('session-a', 'inspect'), code('policy_denied'));
  f.policy(true);
  assert.equal(f.bridge.describe('session-a').state, 'locked');
});

test('detaching and replacing a session while authenticating cannot inherit authority', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.start();
  const auth = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  f.detach();
  f.bridge.registerSession('session-a', () => true);
  f.detach(); // An old cleanup callback must not remove the replacement record.
  authentication.resolve();
  await rejected(auth, 'authentication_failed');
  await rejected(pending.outcome, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
  await assert.rejects(f.bridge.run('session-a', 'inspect'), code('locked'));
});

test('policy sweep immediately revokes an active lease and an in-flight operation', async t => {
  const f = fixture(t, { holdRun: true });
  await unlock(f);
  const run = observe(f.bridge.run('session-a', 'inspect'));
  f.policy(false);
  f.advance(250);
  assert.equal(f.workers[0].closeCount, 1);
  await rejected(run, 'locked');
  await assert.rejects(f.bridge.run('session-a', 'inspect'), code('policy_denied'));
});

test('TTL expires at the exact monotonic deadline and cannot be extended by use', async t => {
  const f = fixture(t);
  await unlock(f);
  f.advance(29999);
  assert.equal(f.bridge.describe('session-a').state, 'unlocked');
  await f.bridge.run('session-a', 'inspect');
  f.advance(1);
  assert.equal(f.bridge.describe('session-a').state, 'locked');
  assert.equal(f.workers[0].closeCount, 1);
  await assert.rejects(f.bridge.run('session-a', 'inspect'), code('locked'));
});

test('pending and in-flight authentication expire without granting late authority', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.start();
  const auth = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  f.advance(2000);
  await rejected(pending.outcome, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
  authentication.resolve();
  await rejected(auth, 'authentication_failed');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
});

test('unanswered request timeout clears the nonce and settles its waiting request', async t => {
  const f = fixture(t);
  const pending = f.start();
  f.advance(2000);
  await rejected(pending.outcome, 'locked');
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, SECRET), code('stale_request'));
  assert.equal(f.workers.length, 0);
});

test('pre-aborted and pending request cancellation never creates a worker', async t => {
  const f = fixture(t);
  const controller = new AbortController();
  controller.abort();
  assert.throws(() => f.start('session-a', controller.signal), code('cancelled'));
  assert.equal(f.bridge.describe('session-a').state, 'locked');
  const next = new AbortController();
  const pending = f.start('session-a', next.signal);
  next.abort();
  await rejected(pending.outcome, 'locked');
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, SECRET), code('stale_request'));
  assert.equal(f.workers.length, 0);
});

test('abort during authentication closes the worker and defeats late success', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const controller = new AbortController();
  const pending = f.start('session-a', controller.signal);
  const auth = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  controller.abort();
  await rejected(pending.outcome, 'locked');
  assert.ok(f.workers[0].closeCount >= 1);
  authentication.resolve();
  await rejected(auth, 'authentication_failed');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
});

test('pre-aborted operation revokes the lease without dispatching any command', async t => {
  const f = fixture(t);
  await unlock(f);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(f.bridge.run('session-a', 'inspect', controller.signal), code('cancelled'));
  assert.deepEqual(f.workers[0].runCalls, []);
  assert.equal(f.bridge.describe('session-a').state, 'locked');
});

test('in-flight operation abort revokes authority and a completed request signal is detached', async t => {
  const f = fixture(t, { holdRun: true });
  const requestController = new AbortController();
  await unlock(f, { signal: requestController.signal });
  requestController.abort();
  assert.equal(f.bridge.describe('session-a').state, 'unlocked');
  const controller = new AbortController();
  const run = observe(f.bridge.run('session-a', 'inspect', controller.signal));
  controller.abort();
  await rejected(run, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
  assert.equal(f.workers[0].closeCount, 1);
});

test('worker errors are sanitized, revoke the lease, and enforce authentication cooldown', async t => {
  const authentication = deferred();
  const f = fixture(t, { authentication });
  const pending = f.start();
  const auth = observe(f.bridge.authenticate('session-a', pending.requestId, SECRET));
  authentication.reject(new Error(`PAM diagnostic ${SECRET}`));
  const result = await auth;
  code('authentication_failed')(result.error);
  assert.equal(JSON.stringify(publicError(result.error)).includes(SECRET), false);
  await rejected(pending.outcome, 'locked');
  assert.throws(() => f.start(), code('rate_limited'));
  f.advance(9999);
  assert.throws(() => f.start(), code('rate_limited'));
  f.advance(1);
  const next = f.start();
  f.bridge.lock('session-a');
  await rejected(next.outcome, 'locked');
});

test('worker construction failure is sanitized and does not strand a pending lease', async t => {
  const f = fixture(t, { factoryError: new Error(`spawn failure ${SECRET}`) });
  const pending = f.start();
  await assert.rejects(f.bridge.authenticate('session-a', pending.requestId, SECRET), error => {
    code('authentication_failed')(error);
    assert.equal(error.message.includes(SECRET), false);
    return true;
  });
  await rejected(pending.outcome, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'locked');
});

test('lock clears authority before reentrant worker close and disposal is idempotent', async t => {
  const f = fixture(t);
  await unlock(f);
  let stateAtClose;
  const close = f.workers[0].close;
  f.workers[0].close = function () {
    stateAtClose = f.bridge.describe('session-a').state;
    close.call(this);
  };
  assert.deepEqual(f.bridge.lock('session-a'), { state: 'locked' });
  assert.equal(stateAtClose, 'locked');
  f.bridge.lock('session-a');
  assert.equal(f.workers[0].closeCount, 1);
  const pending = f.start('session-b');
  f.bridge.dispose();
  f.bridge.dispose();
  await rejected(pending.outcome, 'locked');
  assert.equal(f.bridge.describe('session-a').state, 'unavailable');
});
