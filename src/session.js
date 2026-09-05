import { defineTool } from '@deepseek-ai/dsh-tools';
import { exactKeys, fail, publicError } from './policy.js';

// effectivePolicy() exists in DSH's JS but is private in its public declarations.
// Resolve only the public override + configured default, and fail closed if absent.
export function canApprove(ctx, agent) {
  try {
    const approval = ctx.get('approval');
    if (!approval || typeof approval.request !== 'function' ||
        typeof approval.overrideOf !== 'function' || !approval.config) return false;
    return (approval.overrideOf(agent.session) ?? approval.config.policy ?? 'ask') === 'ask';
  } catch { return false; }
}

const asciiJson = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g,
  character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);

const output = {
  schema: {
    oneOf: [
      { type: 'object', additionalProperties: false, properties: {
        ok: { type: 'boolean', const: true, required: true },
        value: { type: 'json', required: true },
      } },
      { type: 'object', additionalProperties: false, properties: {
        ok: { type: 'boolean', const: false, required: true },
        error: { type: 'object', additionalProperties: false, required: true, properties: {
          code: { type: 'string', required: true },
          message: { type: 'string', required: true },
        } },
      } },
    ],
  },
  render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
};

/** Synchronously populate an already-minted agent-owned child scope. */
export function mountSession(ctx, agent, bridge) {
  if (!agent || ctx.agent !== agent) fail('invalid_session', 'An exact live agent scope is required.');
  const session = agent.session;
  const sessionId = session.id;
  const tools = ctx.get('tools');
  if (!tools) fail('unavailable', 'The DSH tool registry is unavailable.');

  const register = (name, description, parameters, required, optional, run) => tools.register(defineTool({
    name, description, parameters, output,
    async execute(args, exec) {
      try {
        // Never accept a model-selected session id or an inherited parent lease.
        if (exec.agent !== agent || exec.agent.session !== session)
          fail('invalid_session', 'This tool belongs to a different live session.');
        exactKeys(args, required, optional);
        if (exec.signal.aborted) fail('cancelled', 'Administrator operation was cancelled.');
        return { ok: true, value: await run(args, exec) };
      } catch (error) { return { ok: false, error: publicError(error) }; }
    },
  }));

  // Yield exact registry disposers so Cordis adopts them into this effect and
  // unwinds tools before removing the session's authority. Nothing starts sudo.
  return ctx.effect(function* () {
    yield bridge.registerSession(sessionId, () => canApprove(ctx, agent));
    yield register('admin_status',
      'Read this session’s administrator lease status and operator-configured operations. Never send a password in chat or tool arguments.',
      {}, [], [], () => {
        const { requestId: _browserOnlyNonce, ...status } = bridge.describe(sessionId);
        return status;
      });
    yield register('admin_unlock',
      'Request human approval for a short administrator lease covering only named, operator-configured operations. After approval, the human authenticates in the dedicated Admin UI; never ask for or supply a password in chat or tools. Denied when session approvals are disabled.',
      {
        ids: { type: 'array', items: { type: 'string' }, required: true,
          description: 'Distinct operation IDs from admin_status; not commands or argv.' },
        ttlSeconds: { type: 'integer', required: true,
          description: 'Lease lifetime in seconds, from 30 through the configured maximum.' },
        explanation: { type: 'string', required: true,
          description: 'Brief explanation of why the exact listed operations are necessary; never include secrets.' },
      }, ['ids', 'ttlSeconds', 'explanation'], [], async (args, exec) => {
        if (typeof args.explanation !== 'string' || args.explanation.length < 1 ||
            args.explanation.length > 1000 || /[\x00-\x1f\x7f]/.test(args.explanation))
          fail('invalid_request', 'Provide a brief single-line explanation.');
        if (!canApprove(ctx, agent)) fail('policy_denied', 'Session approvals are disabled or unavailable.');
        const manifest = bridge.manifest(args.ids, args.ttlSeconds);
        const approval = ctx.get('approval');
        const reason = [
          `Create an administrator lease ONLY for session ${sessionId}.`,
          `Lifetime after authentication: ${manifest.ttlSeconds} seconds.`,
          'The listed operations may be repeated during this lease. No other command or arguments are authorized.',
          ...manifest.operations.map(op => `${op.id}: argv=${asciiJson([op.executable, ...op.args])}; per-run timeout=${op.timeoutSeconds}s`),
          `Agent explanation (not an expansion of the authorization): ${args.explanation}`,
          'Authenticate only in the dedicated Admin UI. Never put a password in chat.',
        ].join('\n');
        const outcome = await approval.request({ agent, toolName: 'admin_unlock',
          callId: exec.callId, reason, signal: exec.signal });
        if (outcome !== 'allowed-once') fail('approval_denied', 'The administrator lease was not approved.');
        if (exec.signal.aborted) fail('cancelled', 'Administrator request was cancelled.');
        if (!canApprove(ctx, agent)) fail('policy_denied', 'Session approvals changed; administrator access is denied.');
        return bridge.requestUnlock(sessionId, manifest, exec.signal);
      });
    yield register('admin_run',
      'Run exactly one operator-configured operation already authorized by this session’s unexpired administrator lease. Takes an operation ID, never shell syntax or command arguments.',
      { operationId: { type: 'string', required: true, description: 'An ID in this session’s authorized operation set.' } },
      ['operationId'], [], (args, exec) => bridge.run(sessionId, args.operationId, exec.signal));
    yield register('admin_lock',
      'Immediately revoke this session’s administrator lease or pending authentication. Does not affect any other session.',
      {}, [], [], () => bridge.lock(sessionId));
  }, 'admin-bridge: session tools and lease');
}

// Also usable by callers that control AgentRegistry.create({ setup }) and await
// their child plugin. A standing preset is not itself an individual agent.
export const inject = ['tools', 'adminBridge'];
export function apply(ctx) {
  return mountSession(ctx, ctx.agent, ctx.adminBridge);
}
