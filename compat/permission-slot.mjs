#!/usr/bin/env node
/** Explicit, version-guarded compatibility patch; importing this module never writes. */
import { readFile, writeFile, lstat, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';

export const VERSION = '0.1.2-rc.1';
export const PACKAGE = '@deepseek-ai/dsh-client-ui-conversation';
export const BACKUP_SUFFIX = '.admin-bridge-permission-slot.rc1.bak';
const slot = 'conversation.input.permission';
export const patches = [
  { file: 'lib/client.js', edits: [
    { before: '\t\t\tconst accessSelect = command === void 0 ? null : (0, react_jsx_runtime.jsx)(PermissionSelect, {\n\t\t\t\tvalue: permissions,\n\t\t\t\tlocked,\n\t\t\t\tcommand,\n\t\t\t\tt\n\t\t\t}, sessionId);',
      after: '\t\t\t// admin-bridge rc.1 compatibility: optional permission seat; native fallback stays unchanged.\n\t\t\tconst accessSelect = command === void 0 || sessionId === void 0 ? null : renderSlot("conversation.input.permission", { value: permissions, locked, command }, {\n\t\t\t\tfallback: (0, react_jsx_runtime.jsx)(PermissionSelect, {\n\t\t\t\t\tvalue: permissions,\n\t\t\t\t\tlocked,\n\t\t\t\t\tcommand,\n\t\t\t\t\tt\n\t\t\t\t}, sessionId)\n\t\t\t});' },
    { before: '\t\t\t\t\t"conversation.input.left": {\n\t\t\t\t\t\tkind: "list",\n\t\t\t\t\t\tscope: "session"\n\t\t\t\t\t},',
      after: '\t\t\t\t\t"conversation.input.permission": {\n\t\t\t\t\t\tkind: "single",\n\t\t\t\t\t\tscope: "session"\n\t\t\t\t\t},\n\t\t\t\t\t"conversation.input.left": {\n\t\t\t\t\t\tkind: "list",\n\t\t\t\t\t\tscope: "session"\n\t\t\t\t\t},' },
  ] },
  { file: 'lib/types/client/contract/slots.d.ts', edits: [
    { before: "import type { ReactNode, RefObject } from 'react';",
      after: "import type { ReactNode, RefObject } from 'react';\nimport type { PermissionSelect as PermissionSelectValue } from '@deepseek-ai/dsh-permission-presets/client';\n/** Optional current-session permission renderer (admin-bridge rc.1 compatibility). */\nexport interface PermissionControlOwnerProps {\n    value: PermissionSelectValue | undefined;\n    locked: boolean;\n    command: (line: string) => Promise<boolean>;\n}" },
    { before: "        /** Compact controls at the left of the composer tool row. */",
      after: "        /** Optional replacement; absence retains the native permission picker. */\n        'conversation.input.permission': {\n            kind: 'single';\n            scope: 'session';\n            owner: PermissionControlOwnerProps;\n        };\n        /** Compact controls at the left of the composer tool row. */" },
    { before: "PropsRenderSlots<'conversation.input.attachments' | 'conversation.input.overlay' | 'conversation.input.left'",
      after: "PropsRenderSlots<'conversation.input.permission' | 'conversation.input.attachments' | 'conversation.input.overlay' | 'conversation.input.left'" },
  ] },
];
const occurrences = (text, search) => text.split(search).length - 1;
const digest = text => createHash('sha256').update(text).digest('hex');

export function transform(file, source) {
  const patch = patches.find(item => item.file === file);
  if (!patch) throw new Error(`Unrecognized patch target: ${file}`);
  const applied = patch.edits.every(edit => occurrences(source, edit.after) === 1);
  if (applied) return { state: 'patched', output: source };
  if (source.includes(slot) || patch.edits.some(edit => source.includes(edit.after)))
    throw new Error(`Partial or foreign permission slot patch: ${file}`);
  let output = source;
  for (const edit of patch.edits) {
    if (occurrences(output, edit.before) !== 1) throw new Error(`Expected exactly one rc.1 anchor: ${file}`);
    output = output.replace(edit.before, edit.after);
  }
  return { state: 'unpatched', output };
}

async function regularFile(file) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Expected regular file: ${file}`);
  return stat;
}
async function existing(file) {
  try { await regularFile(file); return await readFile(file, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}
async function replace(file, content, mode) {
  const temporary = `${file}.admin-bridge-${process.pid}.tmp`;
  await writeFile(temporary, content, { flag: 'wx', mode });
  try { await rename(temporary, file); } finally { await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}

export async function run(runtime, action = 'check') {
  if (!['check', 'apply', 'revert'].includes(action)) throw new Error('Expected check, apply, or revert');
  const root = path.resolve(runtime, 'node_modules', PACKAGE);
  const metadata = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  if (metadata.name !== PACKAGE || metadata.version !== VERSION) throw new Error(`Only ${PACKAGE}@${VERSION} is supported`);
  const plan = [];
  // Validate every target and backup before any writes. No best-effort partial application.
  for (const patch of patches) {
    const file = path.join(root, patch.file);
    const stat = await regularFile(file);
    const source = await readFile(file, 'utf8');
    const result = transform(patch.file, source);
    const backup = file + BACKUP_SUFFIX;
    const saved = await existing(backup);
    if (saved !== undefined) {
      const original = transform(patch.file, saved);
      if (original.state !== 'unpatched' || original.output !== result.output) throw new Error(`Backup does not match this target: ${file}`);
    }
    if (action === 'revert' && result.state === 'patched' && saved === undefined) throw new Error(`Cannot revert without original backup: ${file}`);
    plan.push({ file, source, ...result, backup, saved, mode: stat.mode & 0o777 });
  }
  if (new Set(plan.map(item => item.state)).size !== 1) throw new Error('Partial installation: targets disagree; restore audited originals before proceeding');
  if (action === 'apply') {
    for (const item of plan) if (item.state === 'unpatched' && item.saved === undefined)
      await writeFile(item.backup, item.source, { flag: 'wx', mode: item.mode });
  }
  const written = [];
  try {
    for (const item of plan) {
      const next = action === 'apply' ? item.output : action === 'revert' ? item.saved ?? item.source : item.source;
      if (next !== item.source) { await replace(item.file, next, item.mode); written.push(item); }
    }
  } catch (error) {
    for (const item of written.reverse()) await replace(item.file, item.source, item.mode);
    throw error;
  }
  return { package: PACKAGE, version: VERSION, action, files: plan.map(item => ({
    path: item.file, before: item.state,
    after: action === 'apply' ? 'patched' : action === 'revert' ? 'unpatched' : item.state,
    sha256: digest(action === 'apply' ? item.output : action === 'revert' ? item.saved ?? item.source : item.source),
  })) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 3 || !['--check', '--apply', '--revert'].includes(args[0]) || args[1] !== '--runtime')
      throw new Error('Usage: node compat/permission-slot.mjs --check|--apply|--revert --runtime /absolute/runtime');
    if (!path.isAbsolute(args[2])) throw new Error('--runtime must be an explicit absolute directory');
    console.log(JSON.stringify(await run(args[2], args[0].slice(2)), null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
