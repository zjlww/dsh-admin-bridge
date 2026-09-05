import test from 'node:test';
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime from '@deepseek-ai/dsh-tools';
import CommandRuntime from '@deepseek-ai/dsh-commands';
import { createScope } from '@deepseek-ai/dsh-scope';
import { Session } from '@deepseek-ai/dsh-session';
import * as plugin from '../src/index.js';
import { MODE_EVENT, recoverMode } from '../src/session.js';

const operation = { id: 'test-op', label: 'Never executed by these tests', executable: '/usr/bin/true', args: [], timeoutSeconds: 1 };
const table = {
  'read-only': { sandbox: 'read-only', approval: 'ask' },
  'workspace-write': { sandbox: 'workspace-write', approval: 'ask' },
  'danger-full-access': { sandbox: 'danger-full-access', approval: 'never' },
};
const signal = () => new AbortController().signal;

async function fixture(t) {
  const ctx = new Context();
  const agents = [];
  const scopes = [];
  const routes = new Map();
  const workers = [];
  const notices = [];
  const originalCalls = [];
  const journalRecords = new Map();
  const journalActions = [];
  const journal = {
    read: id => journalRecords.get(id),
    write(id, entry) { journalRecords.set(id, structuredClone(entry)); journalActions.push('write'); },
    remove(id, generation) {
      if (journalRecords.has(id)) assert.equal(journalRecords.get(id).generation, generation);
      journalRecords.delete(id); journalActions.push('remove');
    },
  };
  const state = session => {
    const value = { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask' };
    for (const event of session.events) {
      if (event.type === 'permission/preset') value.preset = event.data.preset;
      if (event.type === 'sandbox/mode') value.sandbox = event.data.mode;
      if (event.type === 'approval/policy') value.approval = event.data.policy;
    }
    return value;
  };
  const approval = { config: { policy: 'ask' }, overrideOf: session => state(session).approval,
    request() { throw new Error('Mode entry must not ask an agent-driven approval question.'); },
    setPolicy(agent, policy) {
      if (state(agent.session).approval !== policy) {
        agent.session.append('approval/policy', { policy });
        notices.push(policy);
      }
    } };
  const presets = {
    names: Object.keys(table),
    resolve(name) { if (!table[name]) throw new Error('Unknown preset'); return table[name]; },
    current(session) {
      const s = state(session);
      const matches = spec => spec?.sandbox === s.sandbox && spec?.approval === s.approval;
      return matches(table[s.preset]) ? s.preset : Object.keys(table).find(key => matches(table[key])) ?? 'custom';
    },
    set(session, name) {
      const spec = this.resolve(name);
      if (this.current(session) !== name) session.append('permission/preset', { preset: name });
      if (state(session).sandbox !== spec.sandbox) session.append('sandbox/mode', { mode: spec.sandbox });
      if (state(session).approval !== spec.approval) session.append('approval/policy', { policy: spec.approval });
    },
  };
  const fixtures = await ctx.plugin({ apply(c) {
    c.provide('systemPrompt', { tools() { return () => {}; } });
    c.provide('agents', { list: () => agents, get: id => agents.find(agent => agent.session.id === id) });
    c.provide('approval', approval);
    c.provide('permissionPresets', presets);
    c.provide('sandboxPolicy', { resolve: ({ session }) => ({ mode: state(session).sandbox }) });
    c.provide('connection', { requestRejection: () => 401 });
    c.provide('webServer', { register(route) { routes.set(route.path, route); return () => routes.delete(route.path); } });
  } });
  const registry = await ctx.plugin(ToolRuntime, {});
  const commandRegistry = await ctx.plugin(CommandRuntime, {});
  const commands = ctx.get('commands');
  const commandOwner = await ctx.plugin({ inject: ['commands'], apply(c) {
    c.commands.register({ name: 'permission', description: 'Native permission fixture', handler: invocation => {
      originalCalls.push(invocation.rawInput.trim());
      const name = invocation.rawInput.trim();
      if (!table[name]) return { kind: 'error', text: 'Unknown preset.' };
      presets.set(invocation.agent.session, name);
      return { kind: 'success', text: `preset ${name}` };
    } });
  } });
  const addAgent = (id, initial = 'danger-full-access', announce = false, meta = {}) => {
    const session = { id, header: { id, createdAt: 1, ...meta }, events: [], seq: 0, publishing: false,
      eventAt(seq) { return this.events[seq]; },
      append(type, data) {
        if (this.publishing) throw new Error('Native Session forbids append reentrancy.');
        const event = { seq: this.seq++, type, data: structuredClone(data) };
        this.events.push(event);
        this.publishing = true;
        try { ctx.emit('session/event', this, event); }
        finally { this.publishing = false; }
        return event;
      } };
    presets.set(session, initial);
    const agent = { session };
    const scope = createScope(ctx, agent);
    scopes.push(scope);
    agent.ctx = scope.ctx.extend({ agent });
    agents.push(agent);
    if (announce) ctx.emit('agent/created', { agent });
    return agent;
  };
  const first = addAgent('fixture-one');
  let host;
  t.after(async () => {
    await host?.dispose();
    for (const scope of scopes) await scope.dispose();
    await commandOwner.dispose(); await commandRegistry.dispose();
    await registry.dispose(); await fixtures.dispose(); await ctx.fiber.dispose();
  });
  host = await ctx.plugin({ ...plugin, apply(c, config) {
    return plugin.apply(c, config, { journal, workerFactory: () => {
      const worker = { closed: false, runs: 0,
        async authenticate(password) { assert.equal(password, 'synthetic-test-password'); return this; },
        async run() { this.runs++; return { exitCode: 0, stdout: '0\n', stderr: '', truncated: false, timedOut: false }; },
        async runCommand(request) { this.command = request; return this.run(); },
        close() { if (this.closed) return; this.closed = true; this.onClose?.(); },
      };
      workers.push(worker); return worker;
    } });
  } }, { operations: [operation], maxTtlSeconds: 30 });
  const second = addAgent('fixture-two', 'workspace-write', true);
  const mode = ctx.get('adminBridge');
  const tools = ctx.get('tools');
  let call = 0;
  const execute = (name, args = {}, agent = first) => tools.execute({ name, arguments: args, agent, signal: signal(), callId: `call-${++call}` });
  const command = (line, agent = first) => commands.execute(agent, line, [], signal());
  const enter = async (agent = first) => {
    await command('/permission sudo-access', agent);
    const pending = mode.describe(agent.session.id);
    assert.equal(pending.state, 'pending');
    await mode.authenticate(agent.session.id, pending.requestId, 'synthetic-test-password');
  };
  return { ctx, host, mode, tools, commands, first, second, addAgent, execute, command, enter,
    presets, approval, workers, notices, originalCalls, routes, state, journal, journalRecords, journalActions };
}

test('host adds four agent-scoped tools and restores command owner on unload', async t => {
  const f = await fixture(t);
  assert.deepEqual(f.tools.schemas().map(tool => tool.name), []);
  for (const agent of [f.first, f.second]) {
    assert.deepEqual(f.tools.schemas(agent).map(tool => tool.name), ['admin_request', 'admin_status', 'admin_run', 'admin_lock']);
    const result = await f.execute('admin_status', {}, agent);
    assert.equal(result.isError, false);
    assert.equal(result.value.ok, true);
    assert.equal(result.value.value.modeActive, false);
    assert.equal(result.value.value.state, 'locked');
  }
  assert.equal(f.routes.size, 1);
  await f.host.dispose();
  assert.equal(f.routes.size, 0);
  assert.equal(f.tools.schemas(f.first).length, 0);
  assert.equal(f.commands.find(f.first, 'permission').description, 'Native permission fixture');
});

test('Full access never policy can prepare a HUMAN mode intent, but it grants nothing before password auth', async t => {
  const f = await fixture(t);
  assert.equal(f.state(f.first.session).approval, 'never');
  const command = await f.command('/permission sudo-access');
  assert.equal(command.result.kind, 'success');
  assert.equal(f.workers.length, 0);
  assert.equal(f.state(f.first.session).approval, 'never');
  const status = await f.execute('admin_status');
  const browser = f.mode.describe(f.first.session.id);
  assert.equal(status.value.value.state, 'pending');
  assert.equal(Object.hasOwn(status.value.value, 'requestId'), false);
  assert.equal(JSON.stringify(status).includes(browser.requestId), false);
  assert.equal((await f.execute('admin_run', { operationId: 'test-op' })).value.ok, false);
  assert.equal(f.workers.length, 0);
  assert.equal(f.mode.describe(f.second.session.id).state, 'locked');
});

test('agent request opens a non-authorizing dialog and is idempotent without exposing its nonce', async t => {
  const f = await fixture(t);
  const before = f.state(f.first.session);
  const requested = await f.execute('admin_request');
  assert.equal(requested.value.ok, true);
  assert.equal(requested.value.value.state, 'pending');
  assert.equal(Object.hasOwn(requested.value.value, 'requestId'), false);
  const nonce = f.mode.describe(f.first.session.id).requestId;
  await f.execute('admin_request');
  assert.equal(f.mode.describe(f.first.session.id).requestId, nonce);
  assert.deepEqual(f.state(f.first.session), before);
  assert.equal(f.workers.length, 0);
  assert.equal((await f.execute('admin_run', { command: 'id -u' })).value.ok, false);
  await f.mode.authenticate(f.first.session.id, nonce, 'synthetic-test-password');
  await f.execute('admin_request');
  assert.equal(f.mode.describe(f.first.session.id).modeActive, true);
  assert.equal(f.workers.length, 1);
  assert.equal((await f.execute('admin_run', { command: 'id -u', workdir: '/tmp', timeoutSeconds: 5 })).value.value.stdout, '0\n');
  assert.deepEqual(f.workers[0].command, { command: 'id -u', workdir: '/tmp', timeoutSeconds: 5 });
  assert.equal((await f.execute('admin_run', { command: 'id -u', operationId: 'test-op' })).value.ok, false);
  assert.equal((await f.execute('admin_run', {})).value.ok, false);
  assert.equal((await f.execute('admin_run', { operationId: 'test-op', workdir: '/' })).value.ok, false);
  const child = f.addAgent('request-child', 'danger-full-access', true, { origin: 'subagent', delegationDepth: 1 });
  assert.equal((await f.execute('admin_request', {}, child)).value.ok, false);
});

test('one human mode authentication permits repeats, re-entry requires a new nonce, and leaving denies runs', async t => {
  const f = await fixture(t);
  await f.enter();
  assert.equal((await f.execute('admin_run', { operationId: 'test-op' })).value.value.stdout, '0\n');
  assert.equal((await f.execute('admin_run', { operationId: 'test-op' })).value.value.stdout, '0\n');
  assert.equal(f.workers.length, 1);
  await f.command('/permission sudo-access');
  assert.equal(f.workers[0].closed, true);
  assert.equal(f.mode.describe(f.first.session.id).state, 'pending');
  assert.equal((await f.execute('admin_run', { operationId: 'test-op' })).value.ok, false);
  await f.command('/permission danger-full-access');
  assert.equal(f.mode.describe(f.first.session.id).state, 'locked');
  assert.equal(f.originalCalls.at(-1), 'danger-full-access');
  assert.equal((await f.execute('admin_run', { operationId: 'test-op' })).value.ok, false);
});

test('successful entry changes knobs only after auth; explicit lock restores exact prior mode', async t => {
  const f = await fixture(t);
  await f.command('/permission sudo-access', f.second);
  assert.equal(f.presets.current(f.second.session), 'workspace-write');
  await f.mode.authenticate(f.second.session.id, f.mode.describe(f.second.session.id).requestId, 'synthetic-test-password');
  assert.equal(f.presets.current(f.second.session), 'danger-full-access');
  const result = await f.execute('admin_lock', {}, f.second);
  assert.equal(result.value.ok, true);
  assert.equal(f.presets.current(f.second.session), 'workspace-write');
  assert.deepEqual(f.notices, ['never', 'ask']);
  assert.equal(f.second.session.events.filter(event => event.type === MODE_EVENT).length, 0);
  assert.deepEqual(f.journalActions, ['write', 'write', 'remove']);
  assert.equal(f.journalRecords.size, 0);
  assert.equal(JSON.stringify(f.second.session.events).includes('synthetic-test-password'), false);
});

test('normal native selections keep their handler; bare or invalid selections do not activate sudo', async t => {
  const f = await fixture(t);
  const bare = await f.command('/permission');
  assert.match(bare.result.text, /sudo-access/);
  assert.equal(f.workers.length, 0);
  await f.command('/permission invalid');
  assert.equal(f.originalCalls.at(-1), 'invalid');
  await f.command('/permission read-only');
  assert.equal(f.presets.current(f.first.session), 'read-only');
  assert.equal(f.workers.length, 0);
});

test('actual Session.header delegation metadata and missing headers fail closed', async t => {
  const f = await fixture(t);
  const child = f.addAgent('fixture-child', 'danger-full-access', true, { origin: 'subagent', delegationDepth: 1 });
  const result = await f.command('/permission sudo-access', child);
  assert.equal(result.result.kind, 'error');
  assert.equal(f.mode.describe(child.session.id).modeActive, false);
  assert.equal(f.workers.length, 0);
  delete f.first.session.header;
  assert.equal((await f.command('/permission sudo-access')).result.kind, 'error');
  assert.equal(f.workers.length, 0);
});

test('external native change revokes root without overwriting the newer human setting', async t => {
  const f = await fixture(t);
  await f.enter();
  f.first.session.append('sandbox/mode', { mode: 'read-only' });
  assert.equal(f.workers[0].closed, true);
  assert.equal(f.state(f.first.session).sandbox, 'read-only');
  assert.equal(f.mode.describe(f.first.session.id).modeActive, false);
});

test('journal failure cannot prevent native-mode repair or scoped tool disposal', async t => {
  const f = await fixture(t);
  await f.enter();
  f.journal.remove = () => { throw new Error('synthetic-journal-failure'); };
  const choice = await f.command('/permission read-only');
  assert.equal(choice.result.kind, 'success');
  assert.equal(f.presets.current(f.first.session), 'read-only');
  assert.equal(f.workers[0].closed, true);
  assert.equal(f.mode.describe(f.first.session.id).restorationPending, true);
  f.ctx.emit('agent/disposed', { agent: f.first });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.tools.schemas(f.first).length, 0);
  assert.equal(f.commands.find(f.first, 'permission').description, 'Native permission fixture');
  assert.equal(f.tools.schemas(f.second).length, 4);
});

test('exact caller identity, strict tool fields, and raw error sanitization remain enforced', async t => {
  const f = await fixture(t);
  const definition = f.tools.get('admin_run', f.first);
  const mismatch = await definition.execute({ operationId: 'test-op' }, { agent: f.second, signal: signal() });
  assert.equal(mismatch.error.code, 'invalid_session');
  const extra = await f.execute('admin_run', { operationId: 'test-op', password: 'synthetic-secret' });
  assert.equal(extra.value.error.code, 'invalid_request');
  f.mode.run = async () => { throw new Error('synthetic-private-error'); };
  const result = await f.execute('admin_run', { operationId: 'test-op' });
  assert.equal(result.value.error.code, 'internal');
  assert.equal(JSON.stringify(result).includes('synthetic-private-error'), false);
});

const fullWrites = () => [
  { type: 'approval/policy', data: { policy: 'never' } },
  { type: 'permission/preset', data: { preset: 'danger-full-access' } },
  { type: 'sandbox/mode', data: { mode: 'danger-full-access' } },
];
const fullSnapshot = () => ({ preset: 'danger-full-access', sandbox: 'danger-full-access', approval: 'never' });
function recoverFixture({ events = fullWrites(), current = fullSnapshot(), commitSeq = 3,
  createdAt = 1, previous = { preset: 'read-only', sandbox: 'read-only', approval: 'ask' } } = {}) {
  const entry = { generation: 'journal-generation', previous, startSeq: 0, commitSeq, sessionCreatedAt: 1 };
  const session = { id: 'recovery-fixture', header: { createdAt }, seq: events.length, eventAt: seq => events[seq] };
  let restored = 0;
  let removed = 0;
  recoverMode(session, { capture: () => current, restore: value => { current = value; restored++; } }, {
    read: id => { assert.equal(id, session.id); return entry; },
    remove: (id, generation) => { assert.equal(id, session.id); assert.equal(generation, entry.generation); removed++; },
  });
  return { current, restored, removed, previous };
}

test('private rollback journal restores only native permissions and deletes matching generation', () => {
  const f = recoverFixture();
  assert.deepEqual(f.current, f.previous);
  assert.equal(f.restored, 1);
  assert.equal(f.removed, 1);
});

test('post-commit overlapping native choices are preserved rather than guessed as partial entry', () => {
  const current = { preset: 'custom', sandbox: 'read-only', approval: 'never' };
  const f = recoverFixture({ current,
    events: [...fullWrites(), { type: 'sandbox/mode', data: { mode: 'read-only' } }] });
  assert.deepEqual(f.current, current);
  assert.equal(f.restored, 0);
  assert.equal(f.removed, 1);
});

test('successful same-value native command supersedes a dangling rollback record', () => {
  const f = recoverFixture({ events: [...fullWrites(),
    { type: 'command/run', data: { commandId: 'choice', name: 'permission', args: ' danger-full-access' } },
    { type: 'command/done', data: { commandId: 'choice', kind: 'success' } },
  ] });
  assert.deepEqual(f.current, fullSnapshot());
  assert.equal(f.restored, 0);
});

test('prepared and ahead-of-buffered-log commits restore the previous mode', () => {
  for (const commitSeq of [null, 100]) {
    const f = recoverFixture({ commitSeq });
    assert.deepEqual(f.current, f.previous);
    assert.equal(f.restored, 1);
  }
});

test('prepared journal preserves an unexpected or repeated native write tail', () => {
  const f = recoverFixture({ commitSeq: null,
    events: [...fullWrites(), { type: 'approval/policy', data: { policy: 'never' } }] });
  assert.equal(f.restored, 0);
});

test('a reused session ID with another creation identity cannot consume the old rollback instruction', () => {
  const f = recoverFixture({ createdAt: 2 });
  assert.equal(f.restored, 0);
  assert.equal(f.removed, 1);
});

test('actual DSH Session snapshots contain only known native events and replay without a custom journal', () => {
  const session = Session.create('actual-session-fixture');
  for (const event of fullWrites()) session.append(event.type, event.data);
  const persisted = JSON.parse(JSON.stringify(session.snapshotEvents()));
  assert.equal(persisted.some(event => event.type === MODE_EVENT), false);
  const replay = Session.create(session.id, persisted, session.header);
  assert.equal(replay.eventAt(0).type, 'approval/policy');
  assert.equal(replay.header.createdAt, session.header.createdAt);
  const previous = { preset: 'workspace-write', sandbox: 'workspace-write', approval: 'ask' };
  let restored = 0;
  recoverMode(replay, { capture: fullSnapshot, restore(value) { assert.deepEqual(value, previous); restored++; } }, {
    read: () => ({ generation: 'actual-journal', previous, startSeq: 0,
      commitSeq: 3, sessionCreatedAt: replay.header.createdAt }),
    remove() {},
  });
  assert.equal(restored, 1);
});
