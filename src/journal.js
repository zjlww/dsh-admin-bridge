import fs from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BridgeError, exactKeys, identifier } from './policy.js';

const LIMIT = 4096;
const SANDBOXES = ['read-only', 'workspace-write', 'danger-full-access'];
const invalid = () => new BridgeError('invalid_journal', 'The permission rollback journal is invalid or unsafe; Sudo access was not granted.');
const ioFailure = () => new BridgeError('journal_unavailable', 'The permission rollback journal could not be durably updated; Sudo access was not granted.');

function validateSessionId(sessionId) {
  if (!identifier(sessionId)) throw invalid();
}
function journalKeys(value, keys) {
  exactKeys(value, keys);
  // Only plain, enumerable data fields belong in this nonsecret disk format.
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== keys.length || keys.some(key => {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return !descriptor.enumerable || !Object.hasOwn(descriptor, 'value');
      })) throw invalid();
}
function validateEntry(entry) {
  try {
    journalKeys(entry, ['generation', 'previous', 'startSeq', 'commitSeq', 'sessionCreatedAt']);
    journalKeys(entry.previous, ['preset', 'sandbox', 'approval']);
  } catch { throw invalid(); }
  const previous = entry.previous;
  if (!identifier(entry.generation) || typeof previous.preset !== 'string' ||
      previous.preset.length < 1 || previous.preset.length > 128 || previous.preset === 'sudo-access' ||
      !previous.preset.isWellFormed() || /[\x00-\x1f\x7f]/.test(previous.preset) ||
      !SANDBOXES.includes(previous.sandbox) || !['ask', 'never'].includes(previous.approval) ||
      !Number.isSafeInteger(entry.sessionCreatedAt) || entry.sessionCreatedAt < 0 || Object.is(entry.sessionCreatedAt, -0) ||
      !Number.isSafeInteger(entry.startSeq) || entry.startSeq < 0 || Object.is(entry.startSeq, -0) ||
      (entry.commitSeq !== null && (!Number.isSafeInteger(entry.commitSeq) ||
        entry.commitSeq < entry.startSeq || Object.is(entry.commitSeq, -0)))) throw invalid();
  return Object.freeze({ generation: entry.generation,
    previous: Object.freeze({ preset: previous.preset, sandbox: previous.sandbox, approval: previous.approval }),
    startSeq: entry.startSeq, commitSeq: entry.commitSeq, sessionCreatedAt: entry.sessionCreatedAt });
}
function parseRecord(bytes) {
  try {
    // Retain any BOM so JSON.parse rejects it, and reject lossy UTF-8 decoding.
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    const value = JSON.parse(text);
    // JSON.parse validates grammar but silently accepts duplicate object keys.
    // Scan only structural tokens after parsing, including escaped key spellings.
    const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}:]/g) ?? [];
    const objects = [];
    for (const [index, token] of tokens.entries()) {
      if (token === '{') objects.push(new Set());
      else if (token === '}') objects.pop();
      else if (token === ':') {
        const key = JSON.parse(tokens[index - 1]);
        const keys = objects.at(-1);
        if (keys.has(key)) throw invalid();
        keys.add(key);
      }
    }
    journalKeys(value, ['version', 'sessionId', 'generation', 'previous', 'startSeq', 'commitSeq', 'sessionCreatedAt']);
    return value;
  } catch { throw invalid(); }
}
function maybeStat(path) {
  try { return fs.lstatSync(path); }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}

/**
 * Private NONSECRET rollback metadata, never an authentication/lease store.
 * startSeq is the session's next seq BEFORE native entry writes; commitSeq is
 * its next seq AFTER those writes, or null while the transition is incomplete.
 * Native events at seq >= commitSeq therefore supersede a completed transition.
 *
 * Operations are synchronous: write/commit is fsync-durable before a caller
 * changes native permissions or publishes root authority. All files are owned
 * by the Harness uid, not root; this is not protection from same-uid processes.
 */
export class RestoreJournal {
  #directory;
  #uid;

  constructor(directory) {
    if (typeof directory !== 'string' || !isAbsolute(directory) || !directory.isWellFormed() ||
        directory.includes('\0') || directory.split(sep).some(part => part === '.' || part === '..') ||
        typeof process.getuid !== 'function') throw invalid();
    this.#directory = resolve(directory);
    this.#uid = process.getuid();
    try {
      // Do not follow any symlink while creating the dedicated directory. System
      // ancestors may be root-owned; the final directory must be ours and 0700.
      const root = parse(this.#directory).root;
      let current = root;
      const parts = this.#directory.slice(root.length).split(sep).filter(Boolean);
      if (parts.length === 0) throw invalid();
      for (const part of parts) {
        current = join(current, part);
        let stat = maybeStat(current);
        if (!stat) {
          try { fs.mkdirSync(current, { mode: 0o700 }); }
          catch (error) { if (error.code !== 'EEXIST') throw error; }
          stat = fs.lstatSync(current);
        }
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw invalid();
      }
      this.#checkDirectory();
      this.#syncDirectory();
      // Persist creation of the final directory itself as well as its contents.
      const parent = fs.openSync(dirname(this.#directory), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
    } catch (error) { throw error instanceof BridgeError ? error : ioFailure(); }
  }

  #checkDirectory() {
    const stat = fs.lstatSync(this.#directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== this.#uid ||
        (stat.mode & 0o7777) !== 0o700) throw invalid();
  }

  #checkFile(stat) {
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== this.#uid ||
        (stat.mode & 0o7777) !== 0o600 || stat.nlink !== 1 || stat.size > LIMIT) throw invalid();
  }

  #path(sessionId) {
    validateSessionId(sessionId);
    return join(this.#directory, `${sessionId}.json`);
  }

  #syncDirectory() {
    this.#checkDirectory();
    const fd = fs.openSync(this.#directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isDirectory() || stat.uid !== this.#uid || (stat.mode & 0o7777) !== 0o700) throw invalid();
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
  }

  /** Read one bounded validated record; absence is not authority or an error. */
  read(sessionId) {
    const path = this.#path(sessionId);
    let fd;
    try {
      this.#checkDirectory();
      const before = maybeStat(path);
      if (!before) return undefined;
      this.#checkFile(before);
      fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      const stat = fs.fstatSync(fd);
      this.#checkFile(stat);
      if (stat.dev !== before.dev || stat.ino !== before.ino) throw invalid();
      // Fixed allocation/read bound even if another same-uid process grows it.
      const bytes = Buffer.alloc(LIMIT + 1);
      let used = 0;
      while (used < bytes.length) {
        const count = fs.readSync(fd, bytes, used, bytes.length - used, used);
        if (count === 0) break;
        used += count;
      }
      if (used > LIMIT) throw invalid();
      const envelope = parseRecord(bytes.subarray(0, used));
      if (envelope.version !== 1 || envelope.sessionId !== sessionId) throw invalid();
      return validateEntry({ generation: envelope.generation, previous: envelope.previous,
        startSeq: envelope.startSeq, commitSeq: envelope.commitSeq, sessionCreatedAt: envelope.sessionCreatedAt });
    } catch (error) { throw error instanceof BridgeError ? error : ioFailure(); }
    finally {
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { throw ioFailure(); }
      }
    }
  }

  /** Atomically write a new rollback intent or complete that exact generation. */
  write(sessionId, entry) {
    const path = this.#path(sessionId);
    const value = validateEntry(entry);
    let temporary;
    let fd;
    try {
      this.#checkDirectory();
      const existing = this.read(sessionId);
      if (existing && (existing.generation !== value.generation || existing.startSeq !== value.startSeq ||
          existing.sessionCreatedAt !== value.sessionCreatedAt ||
          JSON.stringify(existing.previous) !== JSON.stringify(value.previous) ||
          (existing.commitSeq !== null && existing.commitSeq !== value.commitSeq))) throw invalid();
      const bytes = Buffer.from(JSON.stringify({ version: 1, sessionId, ...value }) + '\n');
      if (bytes.length > LIMIT) throw invalid();
      const candidate = join(this.#directory, `.${sessionId}.${randomUUID()}.tmp`);
      fd = fs.openSync(candidate, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
      temporary = candidate; // Only clean up a temporary file we actually created.
      this.#checkFile(fs.fstatSync(fd));
      fs.writeFileSync(fd, bytes);
      fs.fsyncSync(fd);
      const writtenFd = fd; fd = undefined;
      fs.closeSync(writtenFd);
      this.#checkDirectory();
      const target = maybeStat(path);
      if (target) this.#checkFile(target);
      fs.renameSync(temporary, path);
      temporary = undefined;
      this.#syncDirectory();
    } catch (error) { throw error instanceof BridgeError ? error : ioFailure(); }
    finally {
      let closeFailed = false;
      if (fd !== undefined) {
        try { fs.closeSync(fd); } catch { closeFailed = true; }
      }
      if (temporary !== undefined) {
        try { fs.unlinkSync(temporary); } catch { /* No secret or authority exists in a temp record. */ }
      }
      if (closeFailed) throw ioFailure();
    }
  }

  /** Remove only AFTER restoration/supersession; a stale generation is a no-op. */
  remove(sessionId, expectedGeneration) {
    const path = this.#path(sessionId);
    if (expectedGeneration !== undefined && !identifier(expectedGeneration)) throw invalid();
    try {
      this.#checkDirectory();
      // Validate the envelope too: never silently erase an unrecognized record.
      const existing = this.read(sessionId);
      if (!existing || (expectedGeneration !== undefined && existing.generation !== expectedGeneration)) return;
      // The comparison serializes our synchronous callbacks, not hostile same-uid
      // filesystem writers; this user-owned journal is not an authority boundary.
      fs.unlinkSync(path);
      this.#syncDirectory();
    } catch (error) { throw error instanceof BridgeError ? error : ioFailure(); }
  }
}
