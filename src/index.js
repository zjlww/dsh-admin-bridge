import z from '@deepseek-ai/schemastery';
import { createScope } from '@deepseek-ai/dsh-scope';
import { AdminBridge } from './bridge.js';
import { attachHttp, validateOrigins } from './http.js';
import { exactKeys } from './policy.js';
import { mountSession } from './session.js';

export const name = 'admin-bridge';
// Approval is deliberately optional: absence keeps status/lock visible but
// canApprove() denies every lease. No plugin can make an absent answerer grant.
export const inject = ['agents', 'tools', 'webServer', 'connection'];
export const Config = z.object({
  operations: z.array(z.object({
    id: z.string(),
    label: z.string(),
    executable: z.string(),
    args: z.array(z.string()),
    timeoutSeconds: z.natural().min(1).max(120),
  })).max(16).default([]),
  maxTtlSeconds: z.natural().min(30).max(900).default(300),
  allowedOrigins: z.array(z.string()).max(16).default([]),
});

/** Host singleton plus synchronously registered per-agent child scopes. */
export function apply(ctx, config = {}) {
  exactKeys(config, [], ['operations', 'maxTtlSeconds', 'allowedOrigins']);
  const allowedOrigins = validateOrigins(config.allowedOrigins);
  const bridge = new AdminBridge({ operations: config.operations,
    maxTtlSeconds: config.maxTtlSeconds });
  const scopes = new Map();
  const retiring = new Set();
  let closing = false;

  const retire = (agent) => {
    const scope = scopes.get(agent);
    if (!scope) return;
    scopes.delete(agent);
    bridge.lock(agent.session.id);
    // createScope.dispose() follows quiescence even when the agent has already
    // claimed the raw child-fiber disposer. Contain errors without raw logging.
    const task = scope.dispose().catch(() => {});
    retiring.add(task);
    void task.finally(() => retiring.delete(task));
  };
  const attach = (agent) => {
    if (closing || scopes.has(agent)) return;
    const scope = createScope(agent.ctx, agent);
    scopes.set(agent, scope);
    try {
      // No asynchronous plugin load inside agent/created: its notification is
      // not awaitable. All four tools exist before this listener returns.
      mountSession(scope.ctx, agent, bridge);
    } catch (error) {
      retire(agent);
      throw error;
    }
  };

  return ctx.effect(function* () {
    yield () => bridge.dispose();
    yield ctx.provide('adminBridge', bridge);
    yield async () => {
      closing = true;
      for (const agent of [...scopes.keys()]) retire(agent);
      await Promise.all([...retiring]);
    };
    yield attachHttp(ctx, bridge, { allowedOrigins });
    yield ctx.on('agent/created', ({ agent }) => attach(agent));
    yield ctx.on('agent/disposed', ({ agent }) => retire(agent));
    // Support a late plugin load without sharing a lease with another agent.
    for (const agent of ctx.agents.list()) attach(agent);
  }, 'admin-bridge: host service, routes, and session scopes');
}
