import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import { SudoWorker } from '../src/sudo-worker.js';
import { BridgeError } from '../src/policy.js';

// Every process is a local EventEmitter double. No child_process invocation is permitted.
const SECRET = 'synthetic-sudo-unit-test-secret';
const manifest = () => ({ version: 1, ttlSeconds: 30, operations: [
  { id: 'inspect', label: 'Inspect fixture', executable: '/usr/bin/printf', args: ['fixed argument'], timeoutSeconds: 2 },
] });
const observe = promise => promise.then(value => ({ value }), error => ({ error }));
async function rejected(outcome, code) {
  const result = await outcome;
  assert.ok(result.error instanceof BridgeError, 'expected a sanitized BridgeError rejection');
  assert.equal(result.error.code, code);
  assert.equal(result.error.message.includes(SECRET), false);
  return result.error;
}
function fakeChild({ flushWrites = true } = {}) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = new EventEmitter();
  child.writes = [];
  child.writeCallbacks = [];
  child.endCount = 0;
  child.signals = [];
  child.stdin.write = (data, callback) => {
    child.writes.push({ bytes: Buffer.from(data), source: data });
    if (callback) {
      if (flushWrites) callback();
      else child.writeCallbacks.push(callback);
    }
    return true;
  };
  child.stdin.end = () => { child.endCount++; };
  child.kill = signal => { child.signals.push(signal); return true; };
  child.flush = () => { for (const callback of child.writeCallbacks.splice(0)) callback(); };
  child.frame = value => child.stdout.emit('data', Buffer.from(`${JSON.stringify(value)}\n`));
  return child;
}
function fixture(t, options = {}) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const child = fakeChild(options);
  const spawns = [];
  const worker = new SudoWorker(manifest(), {
    authMs: 500,
    ...(Object.hasOwn(options, 'canProceed') ? { canProceed: options.canProceed } : {}),
    spawnProcess(...args) {
      spawns.push(args);
      if (options.spawnError) throw options.spawnError;
      return child;
    },
  });
  let closeCount = 0;
  worker.onClose = () => { closeCount++; };
  t.after(() => worker.close());
  return {
    child, worker, spawns,
    closeCount: () => closeCount,
    authenticate(password = SECRET) { return observe(worker.authenticate(password)); },
    prompt() {
      assert.equal(spawns.length, 1);
      const argv = spawns[0][1];
      return argv[argv.indexOf('-p') + 1];
    },
  };
}
async function ready(f, password = SECRET) {
  const authentication = f.authenticate(password);
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal((await authentication).value, f.worker);
  assert.equal(f.worker.ready, true);
}
function commandFrame(f) {
  return JSON.parse(f.child.writes.at(-1).bytes.toString('utf8'));
}
function resultFor(command, overrides = {}) {
  return { type: 'result', id: command.id, exitCode: 0, stdout: 'fixture output', stderr: '', truncated: false, timedOut: false, ...overrides };
}
function assertClosed(f) {
  assert.equal(f.worker.closed, true);
  assert.equal(f.worker.ready, false);
  assert.equal(f.worker.pending, null);
  assert.equal(f.child.endCount, 1, 'close must signal root-worker revocation through stdin EOF');
  assert.deepEqual(f.child.signals, ['SIGTERM']);
  assert.equal(f.closeCount(), 1);
}

test('sudo argv and environment never contain the password and execute only the fixed isolated helper', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  assert.equal(f.spawns.length, 1);
  const [executable, argv, options] = f.spawns[0];
  assert.equal(executable, '/usr/bin/sudo');
  assert.equal(options.shell, false);
  assert.equal(options.cwd, '/');
  assert.deepEqual(options.stdio, ['pipe', 'pipe', 'pipe']);
  assert.deepEqual(options.env, { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' });
  assert.equal(JSON.stringify(f.spawns).includes(SECRET), false);
  assert.equal(argv.length, 9);
  assert.deepEqual(argv.slice(0, 3), ['-S', '-k', '-p']);
  assert.match(argv[3], /^DSH_ADMIN_[0-9a-f-]{36}:$/);
  assert.deepEqual(argv.slice(4, 8), ['--', '/usr/bin/python3', '-I', fileURLToPath(new URL('../helper/runner.py', import.meta.url))]);
  assert.deepEqual(JSON.parse(Buffer.from(argv.at(-1), 'base64url').toString('utf8')), manifest());
  assert.equal(argv.includes('-c'), false);
  assert.equal(argv.includes('-E'), false);
  assert.equal(f.child.writes.length, 0, 'do not send the password before the private prompt');
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal((await authentication).value, f.worker);
});

test('invalid credentials reject before spawn, including CR/LF/NUL and UTF-8 byte overflow', async t => {
  const f = fixture(t);
  for (const value of [undefined, null, {}, 1, Buffer.from('secret'), 'bad\nline', 'bad\rline', 'bad\0line', 'x'.repeat(4097), 'é'.repeat(2049)]) {
    await assert.rejects(f.worker.authenticate(value), error => error.code === 'invalid_request');
  }
  assert.equal(f.spawns.length, 0);
});

test('live authorization denies spawn when disabled, missing, throwing, or not strictly true', async t => {
  for (const value of [false, undefined, null, 1, 'true', {}, Promise.resolve(true), new Error('policy unavailable')]) {
    await t.test(String(value), async t => {
      const f = fixture(t, { canProceed: () => {
        if (value instanceof Error) throw value;
        return value;
      } });
      await rejected(f.authenticate(), 'policy_denied');
      assert.equal(f.spawns.length, 0);
      assert.equal(f.child.writes.length, 0);
    });
  }
});

test('authorization revoked between spawn and private prompt prevents password delivery (TOCTOU)', async t => {
  let allowed = true;
  const f = fixture(t, { canProceed: () => allowed });
  const authentication = f.authenticate();
  assert.equal(f.spawns.length, 1);
  const prompt = f.prompt();
  f.child.stderr.emit('data', Buffer.from(prompt.slice(0, 10)));
  allowed = false;
  f.child.stderr.emit('data', Buffer.from(prompt.slice(10)));
  await rejected(authentication, 'authentication_failed');
  assert.equal(f.child.writes.length, 0);
  assertClosed(f);
});

test('late stderr and stdout after cancellation cannot write a cleared secret or restore authority', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  const prompt = f.prompt();
  f.worker.close();
  await rejected(authentication, 'authentication_failed');
  assert.doesNotThrow(() => f.child.stderr.emit('data', Buffer.from(prompt)));
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal(f.child.writes.length, 0);
  assertClosed(f);
});

test('one split private prompt writes the password exactly once, then zeroes the original buffer', async t => {
  const f = fixture(t, { flushWrites: false });
  const authentication = f.authenticate();
  const prompt = f.prompt();
  f.child.stderr.emit('data', Buffer.from(`untrusted PAM text ${SECRET} [sudo] password:`));
  assert.equal(f.child.writes.length, 0);
  f.child.stderr.emit('data', Buffer.from(prompt.slice(0, 12)));
  assert.equal(f.child.writes.length, 0);
  f.child.stderr.emit('data', Buffer.from(prompt.slice(12)));
  assert.equal(f.child.writes.length, 1);
  assert.equal(f.child.writes[0].bytes.toString(), `${SECRET}\n`);
  assert.ok(Buffer.isBuffer(f.child.writes[0].source));
  f.child.flush();
  assert.ok(f.child.writes[0].source.every(byte => byte === 0));
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal((await authentication).value, f.worker);
  assert.equal(f.child.writes.length, 1);
  assert.equal(JSON.stringify(f.spawns).includes(SECRET), false);
});

test('second prompt in the same chunk closes authentication without a second password write', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  const prompt = f.prompt();
  f.child.stderr.emit('data', Buffer.from(`${prompt}${prompt}`));
  await rejected(authentication, 'authentication_failed');
  assert.equal(f.child.writes.length, 1);
  assert.ok(f.child.writes[0].source.every(byte => byte === 0));
  assertClosed(f);
});

test('a repeated split prompt cannot replay the password', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  const prompt = f.prompt();
  f.child.stderr.emit('data', Buffer.from(prompt));
  f.child.stderr.emit('data', Buffer.from(prompt.slice(0, 8)));
  f.child.stderr.emit('data', Buffer.from(prompt.slice(8)));
  await rejected(authentication, 'authentication_failed');
  assert.equal(f.child.writes.length, 1);
  assertClosed(f);
});

test('NOPASSWD ready discards unused secret and later stderr cannot request it', async t => {
  const f = fixture(t);
  await ready(f);
  f.child.stderr.emit('data', Buffer.from(`${f.prompt()}${f.prompt()}`));
  assert.equal(f.child.writes.length, 0);
  const running = observe(f.worker.run('inspect'));
  const command = commandFrame(f);
  assert.deepEqual(Object.keys(command).sort(), ['id', 'operationId', 'type']);
  assert.equal(command.type, 'run');
  assert.equal(command.operationId, 'inspect');
  assert.equal(JSON.stringify(command).includes(SECRET), false);
  f.child.frame(resultFor(command));
  assert.equal((await running).value.stdout, 'fixture output');
  f.worker.close();
  assertClosed(f);
});

test('empty NOPASSWD input is allowed and a real prompt writes only its single newline', async t => {
  const f = fixture(t);
  const authentication = f.authenticate('');
  f.child.stderr.emit('data', Buffer.from(f.prompt()));
  assert.equal(f.child.writes.length, 1);
  assert.equal(f.child.writes[0].bytes.toString(), '\n');
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal((await authentication).value, f.worker);
});

test('close while a password write is pending zeroes the buffer and settles authentication', async t => {
  const f = fixture(t, { flushWrites: false });
  const authentication = f.authenticate();
  f.child.stderr.emit('data', Buffer.from(f.prompt()));
  assert.equal(f.child.writes[0].source.toString(), `${SECRET}\n`);
  f.worker.close();
  await rejected(authentication, 'authentication_failed');
  assert.ok(f.child.writes[0].source.every(byte => byte === 0));
  f.child.flush(); // Delayed write callback remains harmless after revocation.
  f.worker.close();
  assertClosed(f);
});

test('non-root, malformed, extra-field, and premature result frames cannot authenticate', async t => {
  for (const frame of [
    { type: 'ready', uid: 1000 }, { type: 'ready', uid: '0' }, { type: 'ready', uid: -1 },
    { type: 'ready' }, { type: 'ready', uid: 0, extra: 'untrusted' },
    { type: 'result', id: 'nonce', exitCode: 0 }, null, [], true, 'ready',
  ]) {
    await t.test(JSON.stringify(frame), async t => {
      const f = fixture(t);
      const authentication = f.authenticate();
      f.child.frame(frame);
      await rejected(authentication, 'authentication_failed');
      assert.equal(f.child.writes.length, 0);
      assertClosed(f);
    });
  }
});

test('ready frame may be split across chunks but an invalid JSON line fails closed', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  f.child.stdout.emit('data', Buffer.from('{"type":"rea'));
  assert.equal(f.worker.ready, false);
  f.child.stdout.emit('data', Buffer.from('dy","uid":0}\n'));
  assert.equal((await authentication).value, f.worker);
  f.child.stdout.emit('data', Buffer.from(`invalid ${SECRET}\n`));
  assertClosed(f);
});

test('concurrent authenticate on one worker never spawns a second sudo process', async t => {
  const f = fixture(t);
  const first = f.authenticate();
  await assert.rejects(f.worker.authenticate('other-synthetic-secret'), error => error.code === 'closed');
  assert.equal(f.spawns.length, 1);
  f.child.frame({ type: 'ready', uid: 0 });
  assert.equal((await first).value, f.worker);
  await assert.rejects(f.worker.authenticate(SECRET), error => error.code === 'closed');
});

test('run requires ready, exact manifest IDs, and a single outstanding command; never arbitrary argv', async t => {
  const f = fixture(t);
  assert.throws(() => f.worker.run('inspect'), error => error.code === 'locked');
  await ready(f);
  for (const operationId of ['id', '/bin/sh', 'inspect; id', { command: 'id' }, ['inspect'], undefined]) {
    assert.throws(() => f.worker.run(operationId), error => error.code === 'not_authorized');
  }
  assert.equal(f.child.writes.length, 0);
  const running = observe(f.worker.run('inspect'));
  assert.throws(() => f.worker.run('inspect'), error => error.code === 'busy');
  assert.equal(f.child.writes.length, 1);
  const command = commandFrame(f);
  assert.deepEqual(Object.keys(command).sort(), ['id', 'operationId', 'type']);
  assert.match(command.id, /^[0-9a-f-]{36}$/);
  f.child.frame(resultFor(command, { exitCode: 7, stdout: 'out', stderr: 'err', truncated: true, timedOut: true }));
  assert.deepEqual((await running).value, { exitCode: 7, stdout: 'out', stderr: 'err', truncated: true, timedOut: true });
  assert.equal(f.worker.pending, null);
});

test('stale result nonce cannot satisfy a pending operation', async t => {
  const f = fixture(t);
  await ready(f);
  const running = observe(f.worker.run('inspect'));
  const command = commandFrame(f);
  const wrong = `${command.id[0] === 'a' ? 'b' : 'a'}${command.id.slice(1)}`;
  f.child.frame(resultFor(command, { id: wrong }));
  await rejected(running, 'locked');
  assertClosed(f);
});

test('replayed result cannot satisfy a later operation with a fresh nonce', async t => {
  const f = fixture(t);
  await ready(f);
  const first = observe(f.worker.run('inspect'));
  const oldCommand = commandFrame(f);
  const oldResult = resultFor(oldCommand);
  f.child.frame(oldResult);
  await first;
  const second = observe(f.worker.run('inspect'));
  assert.notEqual(commandFrame(f).id, oldCommand.id);
  f.child.frame(oldResult);
  await rejected(second, 'locked');
  assertClosed(f);
});

test('unsolicited result or duplicate ready after authentication revokes authority', async t => {
  for (const frame of [{ type: 'ready', uid: 0 }, resultFor({ id: 'unsolicited' })]) {
    await t.test(frame.type, async t => {
      const f = fixture(t);
      await ready(f);
      f.child.frame(frame);
      assertClosed(f);
    });
  }
});

test('malformed result types, exit codes, missing fields, and unexpected fields reject the pending run', async t => {
  const variants = [
    { exitCode: '0' }, { exitCode: 0.5 }, { exitCode: 256 }, { exitCode: -256 },
    { stdout: {} }, { stderr: null }, { truncated: 0 }, { timedOut: 'false' },
    { extra: SECRET }, { type: 'other' }, { stdout: undefined }, { id: undefined },
  ];
  for (const overrides of variants) {
    await t.test(JSON.stringify(overrides), async t => {
      const f = fixture(t);
      await ready(f);
      const running = observe(f.worker.run('inspect'));
      f.child.frame(resultFor(commandFrame(f), overrides));
      await rejected(running, 'locked');
      assertClosed(f);
    });
  }
});

test('stdout is bounded before newline during authentication and while an operation is pending', async t => {
  for (const authenticated of [false, true]) {
    await t.test(authenticated ? 'operation' : 'authentication', async t => {
      const f = fixture(t);
      let pending;
      if (authenticated) { await ready(f); pending = observe(f.worker.run('inspect')); }
      else pending = f.authenticate();
      f.child.stdout.emit('data', Buffer.alloc(1024 * 1024, 120));
      assert.equal(f.worker.closed, false);
      f.child.stdout.emit('data', Buffer.from('x'));
      await rejected(pending, authenticated ? 'locked' : 'authentication_failed');
      assertClosed(f);
    });
  }
});

test('oversized complete output frame cannot return unbounded operation data', async t => {
  const f = fixture(t);
  await ready(f);
  const running = observe(f.worker.run('inspect'));
  f.child.frame(resultFor(commandFrame(f), { stdout: 'x'.repeat(1024 * 1024) }));
  await rejected(running, 'locked');
  assertClosed(f);
});

test('pre-auth stderr is bounded and PAM diagnostics are never returned', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  f.child.stderr.emit('data', Buffer.from('x'.repeat(8192)));
  assert.equal(f.worker.closed, false);
  f.child.stderr.emit('data', Buffer.from(SECRET));
  const error = await rejected(authentication, 'authentication_failed');
  assert.equal(error.message.includes('xxxx'), false);
  assert.equal(f.child.writes.length, 0);
  assertClosed(f);
});

test('authentication timeout settles promptly, closes stdin, and clears remaining authority', async t => {
  const f = fixture(t);
  const authentication = f.authenticate();
  t.mock.timers.tick(499);
  assert.equal(f.worker.closed, false);
  t.mock.timers.tick(1);
  await rejected(authentication, 'authentication_failed');
  assertClosed(f);
  t.mock.timers.tick(100000);
  assertClosed(f);
});

test('ready cancels the authentication timer and a completed operation cancels its timer', async t => {
  const f = fixture(t);
  await ready(f);
  t.mock.timers.tick(500);
  assert.equal(f.worker.closed, false);
  const running = observe(f.worker.run('inspect'));
  f.child.frame(resultFor(commandFrame(f)));
  await running;
  t.mock.timers.tick(5000);
  assert.equal(f.worker.closed, false);
});

test('operation watchdog rejects a stalled run and signals EOF once', async t => {
  const f = fixture(t);
  await ready(f);
  const running = observe(f.worker.run('inspect'));
  t.mock.timers.tick(4999);
  assert.equal(f.worker.closed, false);
  t.mock.timers.tick(1);
  await rejected(running, 'locked');
  assertClosed(f);
});

test('spawn throw and child errors are sanitized and cancel authentication', async t => {
  await t.test('spawn throws', async t => {
    const f = fixture(t, { spawnError: new Error(`spawn ${SECRET}`) });
    await rejected(f.authenticate(), 'authentication_failed');
    assert.equal(f.worker.closed, true);
    assert.equal(f.child.endCount, 0);
    assert.equal(f.closeCount(), 1);
  });
  for (const event of ['error', 'close']) {
    await t.test(`child ${event}`, async t => {
      const f = fixture(t);
      const authentication = f.authenticate();
      f.child.emit(event, new Error(`PAM ${SECRET}`));
      await rejected(authentication, 'authentication_failed');
      assertClosed(f);
    });
  }
});

test('protocol stdout EOF and stream errors immediately revoke pending authentication', async t => {
  for (const [stream, event] of [['stdout', 'end'], ['stdout', 'close'], ['stdout', 'error'], ['stderr', 'error'], ['stdin', 'error']]) {
    await t.test(`${stream} ${event}`, async t => {
      const f = fixture(t);
      const authentication = f.authenticate();
      f.child[stream].emit(event, new Error(`transport ${SECRET}`));
      // Assert synchronously before awaiting, so a missing EOF handler fails instead of hanging.
      assert.equal(f.worker.closed, true);
      await rejected(authentication, 'authentication_failed');
      assertClosed(f);
    });
  }
});

test('protocol EOF and child exit reject in-flight operations and cleanup is idempotent', async t => {
  for (const event of ['stdout-end', 'stdout-close', 'child-close']) {
    await t.test(event, async t => {
      const f = fixture(t);
      await ready(f);
      const running = observe(f.worker.run('inspect'));
      if (event === 'child-close') f.child.emit('close', 0);
      else f.child.stdout.emit(event === 'stdout-end' ? 'end' : 'close');
      assert.equal(f.worker.closed, true);
      await rejected(running, 'locked');
      f.worker.close();
      f.child.emit('close', 0);
      assertClosed(f);
      assert.throws(() => f.worker.run('inspect'), error => error.code === 'locked');
      await assert.rejects(f.worker.authenticate(SECRET), error => error.code === 'closed');
    });
  }
});

test('close before authentication never spawns and late stdout cannot restore authority', async t => {
  const f = fixture(t);
  f.worker.close();
  f.worker.close();
  await assert.rejects(f.worker.authenticate(SECRET), error => error.code === 'closed');
  assert.equal(f.spawns.length, 0);
  assert.equal(f.closeCount(), 1);
});
