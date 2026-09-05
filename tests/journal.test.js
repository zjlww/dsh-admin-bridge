import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RestoreJournal } from '../src/journal.js';
import { BridgeError } from '../src/policy.js';

// Synthetic rollback metadata in temporary directories only. No credentials,
// sudo, chown, network, live config, or adversarial-filesystem containment claim.
const sessionId = 'session-test_1';
const entry = (overrides = {}) => ({
  generation: 'generation-1',
  previous: { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask' },
  startSeq: 12, commitSeq: null, sessionCreatedAt: 1700000000000,
  ...overrides,
});
const envelope = (value = entry(), overrides = {}) => ({ version: 1, sessionId, ...value, ...overrides });
const code = expected => error => {
  assert.ok(error instanceof BridgeError);
  assert.equal(error.code, expected);
  assert.equal(error.cause, undefined);
  assert.equal(error.message, expected === 'invalid_journal'
    ? 'The permission rollback journal is invalid or unsafe; Sudo access was not granted.'
    : 'The permission rollback journal could not be durably updated; Sudo access was not granted.');
  return true;
};
function fixture(t) {
  const base = fs.mkdtempSync(join(fs.realpathSync(tmpdir()), 'dsh-journal-test-'));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const directory = join(base, 'rollback');
  const journal = new RestoreJournal(directory);
  const path = join(directory, `${sessionId}.json`);
  return { base, directory, path, journal,
    raw(bytes) { fs.writeFileSync(path, bytes, { mode: 0o600 }); },
    disk(value) { this.raw(JSON.stringify(value)); },
  };
}

test('roundtrip, durable commit, reopen and remove return only frozen rollback fields', t => {
  const f = fixture(t);
  assert.equal(f.journal.read(sessionId), undefined);
  f.journal.remove(sessionId);
  const intent = entry();
  f.journal.write(sessionId, intent);
  intent.previous.preset = 'changed-in-caller';
  const saved = f.journal.read(sessionId);
  assert.deepEqual(saved, entry());
  assert.deepEqual(Object.keys(saved).sort(), ['commitSeq', 'generation', 'previous', 'sessionCreatedAt', 'startSeq']);
  assert.ok(Object.isFrozen(saved));
  assert.ok(Object.isFrozen(saved.previous));
  assert.throws(() => { saved.previous.sandbox = 'danger-full-access'; }, TypeError);
  assert.deepEqual(JSON.parse(fs.readFileSync(f.path, 'utf8')), envelope());
  const committed = entry({ commitSeq: 15 });
  f.journal.write(sessionId, committed);
  f.journal.write(sessionId, committed); // Exact durable replay is idempotent.
  const reopened = new RestoreJournal(f.directory);
  assert.deepEqual(reopened.read(sessionId), committed);
  reopened.remove(sessionId, committed.generation);
  assert.equal(f.journal.read(sessionId), undefined);
  reopened.remove(sessionId, committed.generation);
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('directory and records are owned by this uid with exactly 0700 and 0600 modes', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  for (const [path, mode] of [[f.directory, 0o700], [f.path, 0o600]]) {
    const stat = fs.lstatSync(path);
    assert.equal(stat.mode & 0o7777, mode);
    assert.equal(stat.uid, process.getuid());
  }
  assert.equal(fs.lstatSync(f.path).nlink, 1);
});

test('write fsyncs contents before rename and directory after rename; removal syncs directory', t => {
  const f = fixture(t);
  const actions = [];
  const sync = fs.fsyncSync;
  const rename = fs.renameSync;
  const unlink = fs.unlinkSync;
  t.mock.method(fs, 'fsyncSync', fd => {
    actions.push(fs.fstatSync(fd).isDirectory() ? 'directory-sync' : 'file-sync');
    return sync(fd);
  });
  t.mock.method(fs, 'renameSync', (from, to) => {
    actions.push('rename');
    assert.equal(fs.lstatSync(from).mode & 0o7777, 0o600);
    assert.equal(to, f.path);
    return rename(from, to);
  });
  t.mock.method(fs, 'unlinkSync', path => { actions.push('unlink'); return unlink(path); });
  f.journal.write(sessionId, entry());
  assert.deepEqual(actions, ['file-sync', 'rename', 'directory-sync']);
  actions.length = 0;
  f.journal.remove(sessionId);
  assert.deepEqual(actions, ['unlink', 'directory-sync']);
});

test('invalid directories and path-like session IDs fail without creating records', t => {
  const f = fixture(t);
  for (const path of [undefined, null, {}, '', 'relative', '/', `${f.base}/../other`,
    `${f.base}/./other`, `${f.base}/bad\0path`, `${f.base}/bad\ud800`]) {
    assert.throws(() => new RestoreJournal(path), code('invalid_journal'));
  }
  for (const id of [undefined, null, {}, '', '.', '..', '../escape', '/escape', 'a/b', 'a\\b',
    'a.json', 'a\0b', 'a\nb', 'a\n', 'a\r', 'é', 'x'.repeat(65)]) {
    assert.throws(() => f.journal.read(id), code('invalid_journal'));
    assert.throws(() => f.journal.write(id, entry()), code('invalid_journal'));
    assert.throws(() => f.journal.remove(id), code('invalid_journal'));
  }
  assert.deepEqual(fs.readdirSync(f.directory), []);
  const maxId = 'a'.repeat(64);
  f.journal.write(maxId, entry({ generation: 'g'.repeat(64) }));
  assert.equal(f.journal.read(maxId).generation.length, 64);
});

test('only exact nonsecret entry and previous fields are accepted in memory and on disk', t => {
  const f = fixture(t);
  const valid = entry();
  const invalid = [null, [], {}, { ...valid, previous: null }, { ...valid, previous: [] }];
  for (const key of Object.keys(valid)) {
    const value = { ...valid };
    delete value[key];
    invalid.push(value);
  }
  for (const key of ['password', 'nonce', 'authority', 'lease', 'expiresAt', 'requestId', 'version', 'sessionId']) {
    invalid.push({ ...entry(), [key]: 'synthetic-forbidden-value' });
    invalid.push(entry({ previous: { ...entry().previous, [key]: 'synthetic-forbidden-value' } }));
  }
  for (const value of invalid) assert.throws(() => f.journal.write(sessionId, value), code('invalid_journal'));
  assert.deepEqual(fs.readdirSync(f.directory), []);
  for (const key of ['password', 'nonce', 'authority', 'lease', '__proto__']) {
    f.disk(envelope(entry(), { [key]: 'synthetic-forbidden-value' }));
    assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
    assert.throws(() => f.journal.remove(sessionId), code('invalid_journal'));
    assert.ok(fs.existsSync(f.path));
    f.disk(envelope(entry({ previous: { ...entry().previous, [key]: 'synthetic-forbidden-value' } })));
    assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
  }
});

test('nonenumerable, symbol, inherited and accessor fields cannot hide extra input data', t => {
  const f = fixture(t);
  const hidden = Object.defineProperty(entry(), 'password', { value: 'synthetic' });
  const symbol = { ...entry(), [Symbol('authority')]: true };
  const inherited = Object.assign(Object.create({ nonce: 'synthetic' }), entry());
  let accessed = false;
  const accessor = Object.defineProperty(entry(), 'generation', {
    enumerable: true, get() { accessed = true; throw new Error('synthetic diagnostic'); },
  });
  for (const value of [hidden, symbol, inherited, accessor])
    assert.throws(() => f.journal.write(sessionId, value), code('invalid_journal'));
  assert.equal(accessed, false);
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('invalid sequences, timestamp, generation and previous snapshots are rejected', t => {
  const f = fixture(t);
  const invalid = [];
  for (const key of ['startSeq', 'sessionCreatedAt']) {
    for (const value of [-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, '12'])
      invalid.push(entry({ [key]: value }));
  }
  for (const commitSeq of [-1, -0, 11, 12.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '15', undefined])
    invalid.push(entry({ commitSeq }));
  for (const generation of ['', 'bad/id', 'g\n', 'g'.repeat(65), null]) invalid.push(entry({ generation }));
  for (const preset of ['', 'sudo-access', 'x'.repeat(129), 'bad\0name', 'bad\nname', '\ud800', 3])
    invalid.push(entry({ previous: { ...entry().previous, preset } }));
  invalid.push(entry({ previous: { ...entry().previous, sandbox: 'sudo-access' } }));
  invalid.push(entry({ previous: { ...entry().previous, approval: 'always' } }));
  for (const value of invalid) {
    assert.throws(() => f.journal.write(sessionId, value), code('invalid_journal'));
    // JSON normalizes -0 and nonfinite values; test those exact bytes separately.
    if (Object.values(value).some(item => Object.is(item, -0) || !Number.isFinite(item) && typeof item === 'number')) continue;
    f.disk(envelope(value));
    assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
  }
  fs.rmSync(f.path, { force: true });
  f.journal.write(sessionId, entry({ startSeq: 0, commitSeq: 0, sessionCreatedAt: 0 }));
  assert.equal(f.journal.read(sessionId).commitSeq, 0);
  f.journal.remove(sessionId);
  f.journal.write(sessionId, entry({ startSeq: Number.MAX_SAFE_INTEGER, commitSeq: Number.MAX_SAFE_INTEGER,
    sessionCreatedAt: Number.MAX_SAFE_INTEGER }));
  assert.equal(f.journal.read(sessionId).startSeq, Number.MAX_SAFE_INTEGER);
});

test('malformed UTF-8, malformed JSON, duplicate keys, BOM and oversize files reject safely', t => {
  const f = fixture(t);
  const valid = JSON.stringify(envelope());
  const bad = ['', '{', 'null', '[]', `${valid} trailing`, valid.replace('"startSeq":12', '"startSeq":-0'),
    valid.replace('"sessionCreatedAt":1700000000000', '"sessionCreatedAt":-0'),
    valid.replace('"commitSeq":null', '"commitSeq":-0'),
    valid.replace('"version":1', '"version":2'), valid.replace('"version":1', '"version":1,"version":1'),
    valid.replace('"generation":', '"gener\\u0061tion":"other","generation":'),
    valid.replace('"approval":"ask"', '"approval":"never","approval":"ask"'),
    valid.replace(`"sessionId":"${sessionId}"`, '"sessionId":"other"'),
    Buffer.from([0xff, 0xfe, 0xc0, 0x80]),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(valid)]),
    // Invalid UTF-8 inside an otherwise valid JSON string.
    Buffer.concat([Buffer.from(valid.slice(0, valid.indexOf('workspace-write'))), Buffer.from([0xc3, 0x28]),
      Buffer.from(valid.slice(valid.indexOf('workspace-write') + 'workspace-write'.length))]),
    `${valid}${' '.repeat(4097)}`];
  for (const bytes of bad) {
    f.raw(bytes);
    assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
    assert.throws(() => f.journal.write(sessionId, entry()), code('invalid_journal'));
    assert.throws(() => f.journal.remove(sessionId), code('invalid_journal'));
  }
  f.raw(valid + ' '.repeat(4096 - Buffer.byteLength(valid)));
  assert.deepEqual(f.journal.read(sessionId), entry());
});

test('bounded reads reject growth past 4096 bytes even when the initial stat is small', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  let reads = 0;
  t.mock.method(fs, 'readSync', (_fd, buffer, offset, length, position) => {
    reads++;
    assert.equal(buffer.length, 4097);
    assert.equal(offset, 0);
    assert.equal(position, 0);
    buffer.fill(0x20);
    return length;
  });
  assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
  assert.equal(reads, 1);
});

test('symlink leaf, final directory and directory ancestor are rejected without following', t => {
  const f = fixture(t);
  const outside = join(f.base, 'untouched.json');
  fs.writeFileSync(outside, JSON.stringify(envelope()), { mode: 0o600 });
  fs.symlinkSync(outside, f.path);
  for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
    () => f.journal.remove(sessionId)]) assert.throws(operation, code('invalid_journal'));
  assert.ok(fs.lstatSync(f.path).isSymbolicLink());
  assert.deepEqual(JSON.parse(fs.readFileSync(outside, 'utf8')), envelope());
  const alias = join(f.base, 'alias');
  fs.symlinkSync(f.directory, alias);
  assert.throws(() => new RestoreJournal(alias), code('invalid_journal'));
  assert.throws(() => new RestoreJournal(join(alias, 'child')), code('invalid_journal'));
  assert.equal(fs.existsSync(join(f.directory, 'child')), false);
  fs.unlinkSync(f.path);
  fs.rmdirSync(f.directory);
  const target = join(f.base, 'replacement');
  fs.mkdirSync(target, { mode: 0o700 });
  fs.symlinkSync(target, f.directory);
  assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
  assert.throws(() => f.journal.write(sessionId, entry()), code('invalid_journal'));
  assert.throws(() => f.journal.remove(sessionId), code('invalid_journal'));
  assert.deepEqual(fs.readdirSync(target), []);
});

test('hardlinked files and directory leaves are not read, replaced or removed', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  const alias = join(f.base, 'hardlink');
  fs.linkSync(f.path, alias);
  for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
    () => f.journal.remove(sessionId)]) assert.throws(operation, code('invalid_journal'));
  assert.equal(fs.lstatSync(f.path).nlink, 2);
  fs.unlinkSync(alias);
  f.journal.remove(sessionId);
  fs.mkdirSync(f.path, { mode: 0o700 });
  for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
    () => f.journal.remove(sessionId)]) assert.throws(operation, code('invalid_journal'));
});

test('existing wrong permission bits are rejected, never silently chmodded', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  for (const mode of [0o644, 0o400, 0o660, 0o1600]) {
    fs.chmodSync(f.path, mode);
    for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
      () => f.journal.remove(sessionId)]) assert.throws(operation, code('invalid_journal'));
    assert.equal(fs.lstatSync(f.path).mode & 0o7777, mode);
  }
  fs.chmodSync(f.path, 0o600);
  for (const mode of [0o755, 0o750, 0o1700, 0o2700]) {
    fs.chmodSync(f.directory, mode);
    assert.throws(() => new RestoreJournal(f.directory), code('invalid_journal'));
    assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
    assert.equal(fs.lstatSync(f.directory).mode & 0o7777, mode);
  }
  fs.chmodSync(f.directory, 0o700);
});

test('foreign ownership is rejected using mocked stat metadata only, without chown', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  const lstat = fs.lstatSync;
  let foreign = f.path;
  t.mock.method(fs, 'lstatSync', (...args) => {
    const stat = lstat(...args);
    if (args[0] === foreign) stat.uid = process.getuid() + 1;
    return stat;
  });
  for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
    () => f.journal.remove(sessionId)]) assert.throws(operation, code('invalid_journal'));
  foreign = f.directory;
  assert.throws(() => new RestoreJournal(f.directory), code('invalid_journal'));
  assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
  foreign = undefined;
  const fstat = fs.fstatSync;
  t.mock.method(fs, 'fstatSync', fd => { const stat = fstat(fd); stat.uid = process.getuid() + 1; return stat; });
  assert.throws(() => f.journal.read(sessionId), code('invalid_journal'));
});

test('immutable generation, creation timestamp, start sequence and previous knobs cannot change', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  for (const changed of [entry({ generation: 'generation-2' }), entry({ startSeq: 13 }),
    entry({ sessionCreatedAt: 1700000000001 }),
    ...Object.entries({ preset: 'custom', sandbox: 'read-only', approval: 'never' }).map(([key, value]) =>
      entry({ previous: { ...entry().previous, [key]: value } }))]) {
    assert.throws(() => f.journal.write(sessionId, changed), code('invalid_journal'));
    assert.deepEqual(f.journal.read(sessionId), entry());
  }
  const committed = entry({ commitSeq: 15 });
  f.journal.write(sessionId, committed);
  for (const commitSeq of [null, 14, 16]) {
    assert.throws(() => f.journal.write(sessionId, entry({ commitSeq })), code('invalid_journal'));
    assert.deepEqual(f.journal.read(sessionId), committed);
  }
  assert.deepEqual(fs.readdirSync(f.directory), [`${sessionId}.json`]);
});

test('generation-checked removal preserves a newer record and validates the expectation', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  f.journal.remove(sessionId, 'generation-1');
  const newer = entry({ generation: 'generation-2', sessionCreatedAt: 1700000000001 });
  f.journal.write(sessionId, newer);
  f.journal.remove(sessionId, 'generation-1');
  assert.deepEqual(f.journal.read(sessionId), newer);
  for (const expected of [null, '', '../bad', {}, 'x'.repeat(65)])
    assert.throws(() => f.journal.remove(sessionId, expected), code('invalid_journal'));
  assert.deepEqual(f.journal.read(sessionId), newer);
  f.journal.remove(sessionId, 'generation-2');
  assert.equal(f.journal.read(sessionId), undefined);
});

for (const method of ['writeFileSync', 'fsyncSync', 'renameSync', 'closeSync']) {
  test(`${method} failure is sanitized, preserves prior record and cleans temporary files`, t => {
    const f = fixture(t);
    f.journal.write(sessionId, entry());
    const original = fs[method];
    let failed = false;
    const mock = t.mock.method(fs, method, (...args) => {
      // read() closes the old record before write() opens the temporary file.
      const isTarget = method !== 'closeSync' || fs.readdirSync(f.directory).some(name => name.endsWith('.tmp'));
      if (!failed && isTarget) {
        failed = true;
        if (method === 'closeSync') original(...args); // No leaked descriptor in this simulation.
        throw new Error('synthetic-private-io-detail /private/path');
      }
      return original(...args);
    });
    assert.throws(() => f.journal.write(sessionId, entry({ commitSeq: 15 })), code('journal_unavailable'));
    mock.mock.restore();
    assert.equal(failed, true);
    assert.deepEqual(f.journal.read(sessionId), entry());
    assert.deepEqual(fs.readdirSync(f.directory), [`${sessionId}.json`]);
  });
}

test('exclusive no-follow opens never clean up a pre-existing temporary filename collision', t => {
  const f = fixture(t);
  const open = fs.openSync;
  let collision;
  const mock = t.mock.method(fs, 'openSync', (path, flags, mode) => {
    assert.ok(flags & fs.constants.O_NOFOLLOW);
    if (typeof path === 'string' && path.endsWith('.tmp')) {
      assert.ok(flags & fs.constants.O_CREAT);
      assert.ok(flags & fs.constants.O_EXCL);
      assert.equal(mode, 0o600);
      collision = path;
      const preexisting = open(path, flags, mode);
      try { fs.writeFileSync(preexisting, 'synthetic-preexisting-content'); }
      finally { fs.closeSync(preexisting); }
    }
    return open(path, flags, mode);
  });
  assert.throws(() => f.journal.write(sessionId, entry()), code('journal_unavailable'));
  mock.mock.restore();
  assert.equal(fs.readFileSync(collision, 'utf8'), 'synthetic-preexisting-content');
  assert.equal(f.journal.read(sessionId), undefined);
});

test('cleanup still unlinks temporary metadata when closing after a write error also fails', t => {
  const f = fixture(t);
  const close = fs.closeSync;
  const writeMock = t.mock.method(fs, 'writeFileSync', () => { throw new Error('synthetic write detail'); });
  const closeMock = t.mock.method(fs, 'closeSync', fd => { close(fd); throw new Error('synthetic close detail'); });
  assert.throws(() => f.journal.write(sessionId, entry()), code('journal_unavailable'));
  writeMock.mock.restore();
  closeMock.mock.restore();
  assert.deepEqual(fs.readdirSync(f.directory), []);
});

test('read close failure and unavailable directories return only safe errors', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  const close = fs.closeSync;
  const mock = t.mock.method(fs, 'closeSync', fd => { close(fd); throw new Error('synthetic close detail'); });
  assert.throws(() => f.journal.read(sessionId), code('journal_unavailable'));
  mock.mock.restore();
  fs.rmSync(f.directory, { recursive: true });
  for (const operation of [() => f.journal.read(sessionId), () => f.journal.write(sessionId, entry()),
    () => f.journal.remove(sessionId)]) assert.throws(operation, code('journal_unavailable'));
});

test('post-rename directory fsync failure is reported and leaves only valid recoverable metadata', t => {
  const f = fixture(t);
  f.journal.write(sessionId, entry());
  const sync = fs.fsyncSync;
  const mock = t.mock.method(fs, 'fsyncSync', fd => {
    if (fs.fstatSync(fd).isDirectory()) throw new Error('synthetic directory fsync detail');
    return sync(fd);
  });
  const committed = entry({ commitSeq: 15 });
  assert.throws(() => f.journal.write(sessionId, committed), code('journal_unavailable'));
  mock.mock.restore();
  assert.deepEqual(f.journal.read(sessionId), committed);
  assert.deepEqual(fs.readdirSync(f.directory), [`${sessionId}.json`]);
  f.journal.write(sessionId, committed);
  f.journal.remove(sessionId, committed.generation);
});
