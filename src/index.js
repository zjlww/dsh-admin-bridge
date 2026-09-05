import z from '@deepseek-ai/schemastery';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { RestoreJournal } from './journal.js';
import { createScope } from '@deepseek-ai/dsh-scope';
import { SudoMode } from './mode.js';
import { attachHttp, validateOrigins } from './http.js';
import { exactKeys } from './policy.js';
import { mountSession } from './session.js';

export const name = 'admin-bridge';
// The native permission services remain authoritative for ordinary modes.
// Sudo access adds an ephemeral, password-gated capability; no default grants it.
export const inject = ['agents', 'tools', 'commands', 'permissionPresets',
  'sandboxPolicy', 'approval', 'webServer', 'connection'];
export const Config = z.object({
  allowAllCommands: z.boolean().default(true),
  operations: z.array(z.object({
    id: z.string(),
    label: z.string(),
    executable: z.string(),
    args: z.array(z.string()),
    timeoutSeconds: z.natural().min(1).max(120),
  })).max(16).default([]),
  maxTtlSeconds: z.natural().min(30).max(900).default(300),
  allowedOrigins: z.array(z.string()).max(16).default([]),
  stateDirectory: z.string(),
});

/** Host singleton plus synchronously registered per-agent child scopes. */
export function apply(ctx, config = {}, dependencies = {}) {
  exactKeys(config, [], ['operations', 'maxTtlSeconds', 'allowedOrigins', 'stateDirectory', 'allowAllCommands']);
  const allowedOrigins = validateOrigins(config.allowedOrigins);
  const journal = dependencies.journal ?? new RestoreJournal(config.stateDirectory ??
    join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'state', 'admin-bridge'));
  const bridge = new SudoMode({ operations: config.operations, allowAllCommands: config.allowAllCommands,
    maxTtlSeconds: config.maxTtlSeconds }, dependencies);
  const scopes = new Map();
  const retiring = new Set();
  let closing = false;

  const retire = (agent) => {
    const scope = scopes.get(agent);
    if (!scope) return;
    scopes.delete(agent);
    try { bridge.lock(agent.session.id); }
    catch { /* Root is revoked; a failed native restore must not skip disposal. */ }
    finally {
      // createScope.dispose() follows quiescence even when the agent has already
      // claimed the raw child-fiber disposer. Contain errors without raw logging.
      const task = scope.dispose().catch(() => {});
      retiring.add(task);
      void task.finally(() => retiring.delete(task));
    }
  };
  const attach = (agent) => {
    if (closing || scopes.has(agent)) return;
    const scope = createScope(agent.ctx, agent);
    scopes.set(agent, scope);
    try {
      // No asynchronous plugin load inside agent/created: its notification is
      // not awaitable. All four tools exist before this listener returns.
      mountSession(scope.ctx, agent, bridge, journal);
    } catch (error) {
      retire(agent);
      throw error;
    }
  };

  return ctx.effect(function* () {
    yield () => bridge.dispose();
    yield ctx.provide('adminBridge', bridge);
    yield ctx.provide('adminBridgeJournal', journal);
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
    // A manual rc.1 compatibility rebuild must reach the serving revision
    // graph, not merely change disk bytes. This reads already-built artifacts;
    // it neither builds source nor promises browser HMR without a refresh.
    const modules = ctx.get('clientModules');
    if (modules && typeof modules.rebuilt === 'function') {
      modules.rebuilt('@deepseek-ai/dsh-client-ui-conversation');
      modules.rebuilt('dsh-admin-bridge');
    }
  }, 'admin-bridge: host service, routes, and session scopes');
}
