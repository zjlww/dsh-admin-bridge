import test from 'node:test';
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import ToolRuntime from '@deepseek-ai/dsh-tools';
import { createScope } from '@deepseek-ai/dsh-scope';
import * as plugin from '../src/index.js';

const operation = {
  id: 'test-op', label: 'Never executed by these tests', executable: '/usr/bin/true',
  args: ['\u202evisual-direction-test'], timeoutSeconds: 1,
};
const unlockArgs = { ids: ['test-op'], ttlSeconds: 30, explanation: 'Test the scoped approval gate.' };

async function fixture(t, { approvalPresent = true } = {}) {
  const ctx = new Context();
  const agents = [];
  const scopes = [];
  const requests = [];
  const overrides = new Map();
  const approval = {
    config: { policy: 'ask' },
    overrideOf: session => overrides.get(session),
    request: async request => { requests.push(request); return 'rejected'; },
  };
  const routes = new Map();
  const fixtures = await ctx.plugin({ apply(c) {
    c.provide('systemPrompt', { tools() { return () => {}; } });
    c.provide('agents', { list: () => agents });
    c.provide('connection', { requestRejection: () => 401 });
    c.provide('webServer', { register(route) {
      assert.equal(routes.has(route.path), false);
      routes.set(route.path, route);
      return () => routes.delete(route.path);
    } });
    if (approvalPresent) c.provide('approval', approval);
  } });
  const registry = await ctx.plugin(ToolRuntime, {});
  const addAgent = (id, announce = false) => {
    const agent = { session: { id } };
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
    await registry.dispose();
    await fixtures.dispose();
    await ctx.fiber.dispose();
  });
  host = await ctx.plugin(plugin, { operations: [operation] });
  const second = addAgent('fixture-two', true);
  const bridge = ctx.get('adminBridge');
  const tools = ctx.get('tools');
  let call = 0;
  const execute = (name, args = {}, agent = first, signal = new AbortController().signal) =>
    tools.execute({ name, arguments: args, agent, signal, callId: `call-${++call}` });
  return { ctx, host, bridge, tools, first, second, approval, overrides, requests, execute, routes };
}

// Uses the installed/public DSH registry and defineTool validator, not a fake
// schema helper. No real ApprovalService, HTTP listener, sudo, PAM, or credential
// store is constructed; fixtures provide only the capabilities under test.
test('host attaches four synchronous agent-local tools and validates output', async t => {
  const f = await fixture(t);
  assert.deepEqual(f.tools.schemas().map(tool => tool.name), []);
  for (const agent of [f.first, f.second]) {
    assert.deepEqual(f.tools.schemas(agent).map(tool => tool.name),
      ['admin_status', 'admin_unlock', 'admin_run', 'admin_lock']);
    const result = await f.execute('admin_status', {}, agent);
    assert.equal(result.isError, false);
    assert.equal(result.value.ok, true);
    assert.equal(result.value.value.state, 'locked');
    assert.deepEqual(JSON.parse(result.content[0].text), result.value);
  }
  assert.equal(f.routes.size, 1);
  await f.host.dispose();
  assert.equal(f.routes.size, 0);
  assert.equal(f.tools.schemas(f.first).length, 0);
  assert.equal(f.tools.schemas(f.second).length, 0);
  assert.equal(f.bridge.sessions.size, 0);
});

test('browser authentication nonce never appears in model-facing status', async t => {
  const f = await fixture(t);
  const waiting = f.bridge.requestUnlock(f.first.session.id,
    f.bridge.manifest(['test-op'], 30), new AbortController().signal);
  const settled = waiting.catch(() => {});
  const browser = f.bridge.describe(f.first.session.id);
  assert.equal(typeof browser.requestId, 'string');
  const result = await f.execute('admin_status');
  assert.equal(result.value.value.state, 'pending');
  assert.equal(Object.hasOwn(result.value.value, 'requestId'), false);
  assert.equal(JSON.stringify(result).includes(browser.requestId), false);
  assert.equal((await f.execute('admin_status', {}, f.second)).value.value.state, 'locked');
  f.bridge.lock(f.first.session.id);
  await settled;
});

test('unavailable approval fails closed even without the approval service', async t => {
  const f = await fixture(t, { approvalPresent: false });
  let unlocks = 0;
  f.bridge.requestUnlock = async () => { unlocks++; return {}; };
  assert.equal((await f.execute('admin_status')).value.value.state, 'disabled');
  const result = await f.execute('admin_unlock', unlockArgs);
  assert.equal(result.isError, false);
  assert.deepEqual(result.value, { ok: false, error: {
    code: 'policy_denied', message: 'Session approvals are disabled or unavailable.',
  } });
  assert.equal(unlocks, 0);
});

test('only allowed-once reaches unlock; policy overrides are live', async t => {
  const f = await fixture(t);
  let unlocks = 0;
  f.bridge.requestUnlock = async () => { unlocks++; return { state: 'unlocked' }; };
  for (const outcome of ['rejected', 'unavailable', 'cancelled', undefined]) {
    f.approval.request = async () => outcome;
    assert.equal((await f.execute('admin_unlock', unlockArgs)).value.ok, false);
  }
  assert.equal(unlocks, 0);
  let asked = 0;
  f.approval.request = async () => { asked++; return 'allowed-once'; };
  f.overrides.set(f.first.session, 'never');
  assert.equal((await f.execute('admin_unlock', unlockArgs)).value.error.code, 'policy_denied');
  assert.equal(asked, 0);
  f.overrides.delete(f.first.session);
  f.approval.request = async () => {
    f.approval.config.policy = 'never';
    return 'allowed-once';
  };
  assert.equal((await f.execute('admin_unlock', unlockArgs)).value.error.code, 'policy_denied');
  assert.equal(unlocks, 0);
});

test('grant binds frozen exact manifest, ASCII argv, duration, and caller identity', async t => {
  const f = await fixture(t);
  let request;
  let admission;
  f.approval.request = async value => { request = value; return 'allowed-once'; };
  f.bridge.requestUnlock = async (...args) => {
    admission = args;
    return { state: 'unlocked', operationIds: ['test-op'], ttlSeconds: 30 };
  };
  const signal = new AbortController().signal;
  const result = await f.execute('admin_unlock', unlockArgs, f.first, signal);
  assert.equal(result.isError, false);
  assert.equal(result.value.ok, true);
  assert.equal(request.agent, f.first);
  assert.equal(request.toolName, 'admin_unlock');
  assert.match(request.reason, /fixture-one/);
  assert.match(request.reason, /30 seconds/);
  assert.match(request.reason, /\\u202evisual-direction-test/);
  assert.equal(request.reason.includes('\u202e'), false);
  assert.equal(admission[0], f.first.session.id);
  assert.equal(Object.isFrozen(admission[1]), true);
  assert.equal(Object.isFrozen(admission[1].operations), true);
  assert.deepEqual(admission[1].operations, [operation]);
  assert.equal(admission[2].aborted, false);

  // Even direct access to a parent's definition cannot consume its lease.
  const parentDefinition = f.tools.get('admin_run', f.first);
  const mismatch = await parentDefinition.execute({ operationId: 'test-op' }, {
    agent: f.second, signal, callId: 'wrong-agent',
  });
  assert.equal(mismatch.ok, false);
  assert.equal(mismatch.error.code, 'invalid_session');
});

test('extra args and raw exceptions are contained without exposing input', async t => {
  const f = await fixture(t);
  const extra = await f.execute('admin_unlock', { ...unlockArgs, password: 'synthetic-not-a-secret' });
  assert.equal(extra.value.error.code, 'invalid_request');
  assert.equal(f.requests.length, 0);
  f.bridge.run = async () => { throw new Error('synthetic-private-diagnostic'); };
  const result = await f.execute('admin_run', { operationId: 'test-op' });
  assert.equal(result.isError, false);
  assert.equal(result.value.error.code, 'internal');
  assert.equal(JSON.stringify(result).includes('synthetic-private-diagnostic'), false);
});
