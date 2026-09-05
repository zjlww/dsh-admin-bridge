import { defineTool } from '@deepseek-ai/dsh-tools';
import { setSandboxMode } from '@deepseek-ai/dsh-sandbox-policy';
import { exactKeys, fail, publicError } from './policy.js';

export const MODE_EVENT = 'admin-bridge/sudo-mode';
const NATIVE_EVENTS = new Set(['permission/preset', 'sandbox/mode', 'approval/policy']);
const MODES = new Set(['read-only', 'workspace-write', 'danger-full-access']);
const sameKnobs = (a, b) => a.sandbox === b.sandbox && a.approval === b.approval;

const output = {
  schema: { oneOf: [
    { type: 'object', additionalProperties: false, properties: {
      ok: { type: 'boolean', const: true, required: true },
      value: { type: 'json', required: true },
    } },
    { type: 'object', additionalProperties: false, properties: {
      ok: { type: 'boolean', const: false, required: true },
      error: { type: 'object', additionalProperties: false, required: true, properties: {
        code: { type: 'string', required: true }, message: { type: 'string', required: true },
      } },
    } },
  ] },
  render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
};

function validPrevious(value) {
  return value && typeof value === 'object' && Object.keys(value).length === 3 &&
    typeof value.preset === 'string' && value.preset.length > 0 && value.preset.length <= 128 &&
    MODES.has(value.sandbox) && ['ask', 'never'].includes(value.approval);
}

/** A private rollback journal is never authority and never enters DSH's log.
 * rc.1 rejects unknown persisted events and forbids append reentrancy, so a
 * custom session event is NOT a compatible persistence mechanism here. */
export function recoverMode(session, { capture, restore, nativeNames = [...MODES] }, journal) {
  const pending = journal.read(session.id);
  if (!pending) return;
  if (pending.sessionCreatedAt !== session.header?.createdAt) {
    journal.remove(session.id, pending.generation);
    return; // A reused ID is not the original session or permission intent.
  }
  // The journal is fsynced; DSH's own event log is buffered. A crash can leave
  // the latter behind, so an ahead-of-log commit cutoff is a partial commit.
  const commitSeq = pending.commitSeq !== null && pending.commitSeq <= session.seq
    ? pending.commitSeq : null;
  let newerChoice = false;
  const runs = new Map();
  const seen = new Set();
  const fullWrite = event => event.type === 'approval/policy' ? event.data.policy === 'never'
    : event.type === 'sandbox/mode' ? event.data.mode === 'danger-full-access'
      : event.data.preset === 'danger-full-access';
  for (let seq = pending.startSeq; seq < session.seq; seq++) {
    const event = session.eventAt(seq);
    if (!event) continue;
    if (event.type === 'command/run' && event.data.name === 'permission' &&
        typeof event.data.args === 'string' && nativeNames.includes(event.data.args.trim()))
      runs.set(event.data.commandId, true);
    if (event.type === 'command/done' && event.data.kind === 'success' && runs.has(event.data.commandId))
      newerChoice = true; // Includes explicit same-value native choices.
    if (!NATIVE_EVENTS.has(event.type)) continue;
    if (commitSeq !== null) {
      if (seq >= commitSeq) newerChoice = true;
    } else {
      // Without a commit marker, only an incomplete, nonrepeated Full-access
      // write prefix belongs to our transaction. Preserve any other native tail.
      if (!fullWrite(event) || seen.has(event.type)) newerChoice = true;
      seen.add(event.type);
    }
  }
  const current = capture();
  const partial = [pending.previous.sandbox, 'danger-full-access'].includes(current.sandbox) &&
    [pending.previous.approval, 'never'].includes(current.approval);
  if (!newerChoice && partial) restore(pending.previous);
  journal.remove(session.id, pending.generation);
}

/** Native adapters preserve the existing preset service and its three defaults. */
export function nativeCallbacks(ctx, agent, journal = ctx.get('adminBridgeJournal')) {
  const session = agent.session;
  const presets = ctx.get('permissionPresets');
  const sandbox = ctx.get('sandboxPolicy');
  const approval = ctx.get('approval');
  if (!presets || !sandbox || !approval || !journal)
    fail('unavailable', 'Native permission modes or restoration storage are unavailable.');
  const capture = () => ({ preset: presets.current(session),
    sandbox: sandbox.resolve({ session }).mode,
    approval: approval.overrideOf(session) ?? approval.config.policy ?? 'ask' });
  const restore = previous => {
    if (!validPrevious(previous)) fail('invalid_session', 'Cannot restore the previous permission mode.');
    if (capture().sandbox !== previous.sandbox) setSandboxMode(session, previous.sandbox);
    if (capture().approval !== previous.approval) approval.setPolicy(agent, previous.approval);
    // Preserve a named preset only if its definition still matches the captured
    // knobs. A changed operator table must never broaden recovery permissions.
    let spec;
    try { spec = presets.resolve(previous.preset); } catch { /* derived custom */ }
    if (spec?.sandbox === previous.sandbox && spec.approval === previous.approval)
      presets.set(session, previous.preset);
  };
  const callbacks = {
    identity: agent, capture, restore,
    commitFull() {
      const full = presets.resolve('danger-full-access');
      if (full.sandbox !== 'danger-full-access' || full.approval !== 'never')
        fail('unavailable', 'Sudo access requires the standard Full access preset.');
      // Called only after fresh password authentication for an explicit human
      // mode intent. No agent tool exposes this transition or begins an intent.
      approval.setPolicy(agent, 'never');
      presets.set(session, 'danger-full-access');
    },
    isUnchanged: previous => {
      const current = capture();
      return sameKnobs(current, previous) && current.preset === previous.preset;
    },
    isFull: () => sameKnobs(capture(), { sandbox: 'danger-full-access', approval: 'never' }),
    isLive: () => ctx.agent === agent && ctx.get('agents')?.get(session.id) === agent,
    isDelegated: () => !session.header || session.header.origin === 'subagent' ||
      (session.header.delegationDepth ?? 0) > 0,
    nativeNames: presets.names,
    audit(type, data) {
      if (type !== MODE_EVENT) fail('invalid_session', 'Invalid restoration journal action.');
      if (data.action === 'enter') {
        journal.write(session.id, { generation: data.generation, previous: data.previous,
          startSeq: session.seq, commitSeq: null, sessionCreatedAt: session.header.createdAt });
      } else if (data.action === 'commit') {
        const entry = journal.read(session.id);
        if (entry?.generation !== data.generation)
          fail('invalid_session', 'Restoration journal changed during mode entry.');
        journal.write(session.id, { ...entry, commitSeq: session.seq });
      } else if (data.action === 'exit') journal.remove(session.id, data.generation);
      else fail('invalid_session', 'Invalid restoration journal action.');
    },
  };
  recoverMode(session, callbacks, journal);
  return callbacks;
}

/** Human-only command intent plus three read/run/revoke tools; no unlock tool. */
export function mountSession(ctx, agent, mode, journal = ctx.get('adminBridgeJournal')) {
  if (!agent || ctx.agent !== agent) fail('invalid_session', 'An exact live agent scope is required.');
  const session = agent.session;
  const sessionId = session.id;
  const tools = ctx.get('tools');
  const commands = ctx.get('commands');
  const original = commands?.find(agent, 'permission');
  if (!tools || !original) fail('unavailable', 'The native permission command is unavailable.');
  const callbacks = nativeCallbacks(ctx, agent, journal);
  const register = (name, description, parameters, required, run) => tools.register(defineTool({
    name, description, parameters, output,
    async execute(args, exec) {
      try {
        if (exec.agent !== agent || exec.agent.session !== session)
          fail('invalid_session', 'This tool belongs to a different live session.');
        exactKeys(args, required);
        if (exec.signal.aborted) fail('cancelled', 'Administrator operation was cancelled.');
        return { ok: true, value: await run(args, exec) };
      } catch (error) { return { ok: false, error: publicError(error) }; }
    },
  }));
  return ctx.effect(function* () {
    yield mode.registerSession(sessionId, callbacks);
    yield ctx.on('session/event', (subject, event) => {
      if (subject === session && NATIVE_EVENTS.has(event.type)) mode.observeNativeChange(sessionId);
    });
    // Supported agent-local shadow: do not replace the global registry or the
    // permission service. Ordinary selections retain their original handler.
    yield commands.register({ ...original, recordInput: true,
      description: 'Switch permission mode: Read Only, Workspace Write, Full access, or password-gated Sudo access',
      handler: async invocation => {
        if (invocation.agent !== agent || invocation.agent.session !== session)
          return { kind: 'error', text: 'This permission selector belongs to another session.' };
        const selected = invocation.rawInput.trim();
        if (selected === 'sudo-access') {
          try {
            if (invocation.signal.aborted) fail('cancelled', 'Mode selection was cancelled.');
            mode.begin(sessionId, { source: 'permission-command', identity: agent });
            return { kind: 'success', text: 'Authenticate in the Sudo access password dialog. The previous mode remains active until authentication succeeds.' };
          } catch (error) { return { kind: 'error', text: publicError(error).message }; }
        }
        if (selected === '') {
          const status = mode.describe(sessionId);
          return { kind: 'success', text: `current mode ${status.modeActive ? 'sudo-access' : callbacks.capture().preset} (available: ${ctx.get('permissionPresets').names.join(', ')}, sudo-access)` };
        }
        if (ctx.get('permissionPresets').names.includes(selected)) {
          try { mode.lock(sessionId); }
          catch { /* Root is already revoked; never block a human's native-mode repair. */ }
        }
        return original.handler(invocation);
      },
    });
    yield register('admin_status',
      'Read this session’s Sudo access mode and configured operations. Only the human can enter Sudo access using the permission selector and password dialog; never request a password in chat or tools.',
      {}, [], () => {
        const { requestId: _browserOnly, ...status } = mode.describe(sessionId);
        return status;
      });
    yield register('admin_run',
      'Run one exact configured operation authorized by this session’s active Sudo access mode. The human must first select Sudo access and authenticate in the GUI. Takes an operation ID, not shell syntax or arguments.',
      { operationId: { type: 'string', required: true, description: 'An ID in this session’s authorized operation set.' } },
      ['operationId'], (args, exec) => mode.run(sessionId, args.operationId, exec.signal));
    yield register('admin_lock',
      'Leave Sudo access or cancel pending authentication, revoke root authorization, and restore this session’s previous permission mode. Does not affect other sessions.',
      {}, [], () => mode.lock(sessionId));
  }, 'admin-bridge: password-gated mode, native selector command, and scoped tools');
}

export const inject = ['tools', 'commands', 'permissionPresets', 'sandboxPolicy', 'approval',
  'adminBridge', 'adminBridgeJournal'];
export function apply(ctx) { return mountSession(ctx, ctx.agent, ctx.adminBridge); }
