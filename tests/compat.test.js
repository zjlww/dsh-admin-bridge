import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import { patches, transform, run, PACKAGE, VERSION, BACKUP_SUFFIX } from '../compat/permission-slot.mjs';

function fixture(patch) { return '// untouched native icons, three presets, and command handler\n' + patch.edits.map(edit => edit.before).join('\n'); }
async function installation(t) {
  const runtime = await mkdtemp(path.join(os.tmpdir(), 'admin-bridge-compat-'));
  t.after(() => rm(runtime, { recursive: true, force: true }));
  const root = path.join(runtime, 'node_modules', PACKAGE);
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: PACKAGE, version: VERSION }));
  for (const patch of patches) {
    const file = path.join(root, patch.file);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, fixture(patch));
  }
  return { runtime, root };
}

test('compat adds exactly one child seat and native fallback without changing icons', () => {
  const patch = patches[0];
  const source = fixture(patch);
  const result = transform(patch.file, source);
  assert.equal(result.state, 'unpatched');
  assert.match(result.output, /renderSlot\("conversation.input.permission"/);
  assert.match(result.output, /fallback: \(0, react_jsx_runtime.jsx\)\(PermissionSelect/);
  assert.match(result.output, /untouched native icons, three presets, and command handler/);
  assert.equal(transform(patch.file, result.output).state, 'patched');
  assert.equal(transform(patch.file, result.output).output, result.output);
});

test('compat rejects missing, duplicate, and partial anchors', () => {
  for (const patch of patches) {
    const source = fixture(patch);
    assert.throws(() => transform(patch.file, source.replace(patch.edits[0].before, 'changed')), /anchor/);
    assert.throws(() => transform(patch.file, source + patch.edits[0].before), /anchor/);
    assert.throws(() => transform(patch.file, source.replace(patch.edits[0].before, patch.edits[0].after)), /Partial|anchor/);
  }
});

test('compat check is read-only, apply is idempotent, backups support exact revert', async t => {
  const { root, runtime } = await installation(t);
  assert.equal((await run(runtime)).files[0].after, 'unpatched');
  for (const patch of patches) await assert.rejects(readFile(path.join(root, patch.file) + BACKUP_SUFFIX), { code: 'ENOENT' });
  assert.equal((await run(runtime, 'apply')).files[0].after, 'patched');
  assert.equal((await run(runtime, 'apply')).files[0].before, 'patched');
  for (const patch of patches) assert.equal(await readFile(path.join(root, patch.file) + BACKUP_SUFFIX, 'utf8'), fixture(patch));
  await run(runtime, 'revert');
  for (const patch of patches) assert.equal(await readFile(path.join(root, patch.file), 'utf8'), fixture(patch));
  await run(runtime, 'apply');
});

test('compat fails closed for another version and preflights all targets', async t => {
  const { root, runtime } = await installation(t);
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: PACKAGE, version: '0.1.2' }));
  await assert.rejects(run(runtime, 'apply'), /Only/);
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: PACKAGE, version: VERSION }));
  await writeFile(path.join(root, patches[1].file), 'foreign build');
  await assert.rejects(run(runtime, 'apply'), /anchor/);
  assert.equal(await readFile(path.join(root, patches[0].file), 'utf8'), fixture(patches[0]));
  await assert.rejects(readFile(path.join(root, patches[0].file) + BACKUP_SUFFIX), { code: 'ENOENT' });
});

test('direct CLI invocation through a symlinked checkout executes instead of silently doing nothing', async t => {
  const { runtime } = await installation(t);
  const cli = path.join(runtime, 'linked-cli.mjs');
  await symlink(fileURLToPath(new URL('../compat/permission-slot.mjs', import.meta.url)), cli);
  const output = execFileSync(process.execPath, [cli, '--apply', '--runtime', runtime], { encoding: 'utf8' });
  assert.equal(JSON.parse(output).files[0].after, 'patched');
  assert.equal((await run(runtime)).files[0].after, 'patched');
});

test('compat refuses a mismatched backup rather than overwriting it', async t => {
  const { root, runtime } = await installation(t);
  await run(runtime, 'apply');
  await writeFile(path.join(root, patches[0].file) + BACKUP_SUFFIX, 'foreign original');
  await assert.rejects(run(runtime, 'revert'), /anchor|Backup/);
});
