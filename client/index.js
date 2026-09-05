/* Hand-written DSH client module: no build step and no credential state/store. */
window.__ModuleLoader__.load({
  id: 'dsh-admin-bridge',
  factory: require => {
    const React = require('react');
    const h = React.createElement;
    const { useEffect, useRef, useState } = React;
    const endpoint = '/admin-bridge/v1/';
    const buttonStyle = { padding: '6px 10px', border: '1px solid GrayText', borderRadius: 6, cursor: 'pointer' };
    const ascii = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));

    async function post(method, payload, signal) {
      const response = await fetch(endpoint + method, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json', 'X-DSH-Admin-Bridge': '1' },
        body: JSON.stringify(payload), signal,
      });
      payload = undefined;
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error?.message ?? 'Administrator bridge unavailable.');
      return result.value;
    }

    function AdminAction({ sessionId }) {
      const [status, setStatus] = useState({ state: 'unavailable', operations: [] });
      const [open, setOpen] = useState(false);
      const [busy, setBusy] = useState(false);
      const [error, setError] = useState('');
      const dialog = useRef(null);
      const password = useRef(null);
      const activeRequest = useRef(null);
      const generation = useRef(0);
      const seenRequest = useRef(null);

      useEffect(() => {
        const current = ++generation.current;
        let stopped = false;
        let timer;
        let request;
        setStatus({ state: 'unavailable', operations: [] });
        setOpen(false); setBusy(false); setError('');
        seenRequest.current = null;
        async function refresh() {
          if (!sessionId || stopped) return;
          request = new AbortController();
          const timeout = setTimeout(() => request.abort(), 5000);
          try {
            const value = await post('status', { sessionId }, request.signal);
            if (!stopped && current === generation.current) {
              setStatus(value);
              if (value.state === 'pending' && seenRequest.current !== value.requestId) {
                seenRequest.current = value.requestId;
                setError(''); setOpen(true);
              }
            }
          } catch {
            if (!stopped) setStatus({ state: 'unavailable', operations: [] });
          } finally {
            clearTimeout(timeout);
            if (!stopped) timer = setTimeout(refresh, 1000);
          }
        }
        refresh();
        return () => {
          stopped = true; clearTimeout(timer); request?.abort();
          activeRequest.current?.abort();
          if (password.current) password.current.value = '';
        };
      }, [sessionId]);

      useEffect(() => {
        if (open) {
          if (!dialog.current?.open) dialog.current?.showModal();
          if (status.state === 'pending') password.current?.focus();
        } else {
          if (password.current) password.current.value = '';
          dialog.current?.close();
        }
      }, [open, status.state]);

      async function lock() {
        activeRequest.current?.abort();
        if (password.current) password.current.value = '';
        const current = generation.current;
        try {
          await post('lock', { sessionId }, AbortSignal.timeout(5000));
          if (current === generation.current) { setStatus({ state: 'locked', operations: status.operations }); setBusy(false); }
        } catch {
          if (current === generation.current) setError('Could not confirm revocation. The helper still enforces its deadline.');
        }
      }

      async function authenticate(event) {
        event.preventDefault();
        if (busy || status.state !== 'pending') return;
        const current = generation.current;
        const controller = new AbortController();
        activeRequest.current = controller;
        const timeout = setTimeout(() => controller.abort(), 50_000);
        setBusy(true); setError('');
        // Uncontrolled input: never copy a password into React state, chat, storage, or an event bus.
        let secret = password.current?.value ?? '';
        if (password.current) password.current.value = '';
        try {
          const task = post('authenticate', { sessionId, requestId: status.requestId, password: secret }, controller.signal);
          secret = undefined;
          await task;
          if (current === generation.current) { setStatus({ ...status, state: 'unlocked' }); setOpen(false); }
        } catch (failure) {
          if (current === generation.current) setError(failure.message || 'Authentication failed. Request a new lease from the agent.');
        } finally {
          secret = undefined;
          clearTimeout(timeout);
          if (activeRequest.current === controller) activeRequest.current = null;
          if (current === generation.current) setBusy(false);
        }
      }

      const commands = status.selectedOperations ?? status.operations ?? [];
      const pending = status.state === 'pending';
      const active = ['pending', 'authenticating', 'unlocked'].includes(status.state);
      return h(React.Fragment, null,
        h('button', { type: 'button', style: buttonStyle, onClick: () => setOpen(true), title: 'Scoped administrator access' },
          status.state === 'unlocked' ? 'Admin: unlocked' : pending ? 'Admin: authenticate' : 'Admin: ' + status.state),
        h('dialog', { ref: dialog,
          'aria-labelledby': 'dsh-admin-bridge-title',
          style: { maxWidth: 620, width: 'min(90vw, 620px)', maxHeight: '85vh', padding: 24, borderRadius: 12,
            border: '1px solid GrayText', background: 'Canvas', color: 'CanvasText', overflow: 'auto' },
          onCancel: event => { event.preventDefault(); if (active && status.state !== 'unlocked') lock(); setOpen(false); },
        },
          h('h2', { id: 'dsh-admin-bridge-title' }, 'Administrator access'),
          h('p', null, 'Session: ', h('code', null, sessionId)),
          h('p', { role: 'status', 'aria-live': 'polite' }, 'Status: ' + status.state),
          status.state === 'disabled' ? h('p', null, 'Approval prompts are disabled. This plugin cannot unlock administrator access.') : null,
          status.state === 'unavailable' ? h('p', null, 'Bridge unavailable. Check plugin configuration and trusted browser origins.') : null,
          active ? h('p', null, 'Authorize only the exact commands below for ', status.ttlSeconds, ' seconds. Root access is powerful; changes cannot automatically be undone.') :
            h('p', null, 'Ask the agent to call admin_unlock with selected operation IDs. Approve the lease in DSH; the password dialog will then open here.'),
          commands.length ? h('ul', null, ...commands.map(op => h('li', { key: op.id, style: { marginBottom: 12 } },
            h('strong', null, op.id), ': ', op.label,
            h('pre', { style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 } }, ascii([op.executable, ...op.args])),
            h('small', null, 'Command timeout: ', op.timeoutSeconds, ' seconds'),
          ))) : h('p', null, 'No operations available. The operator must configure an exact command allowlist.'),
          status.expiresAt ? h('p', null, 'Deadline: ', new Date(status.expiresAt).toLocaleTimeString()) : null,
          h('p', null, 'Your password goes only to the local sudo authentication process through the trusted Harness host. It is not saved or sent to the model. Do not enter it in chat.'),
          error ? h('p', { role: 'alert', style: { color: 'crimson' } }, error) : null,
          pending ? h('form', { onSubmit: authenticate, autoComplete: 'off' },
            h('label', null, 'Sudo password', h('input', { ref: password, type: 'password', autoComplete: 'off',
              maxLength: 4096, disabled: busy, spellCheck: false,
              style: { display: 'block', width: '100%', boxSizing: 'border-box', margin: '8px 0', padding: 8 },
              'aria-label': 'Sudo password; never stored' })),
            h('button', { type: 'submit', disabled: busy, style: buttonStyle }, busy ? 'Authenticating…' : 'Authenticate and unlock'),
          ) : null,
          h('div', { style: { display: 'flex', gap: 10, marginTop: 18 } },
            active ? h('button', { type: 'button', style: buttonStyle, onClick: lock }, 'Lock now / cancel') : null,
            h('button', { type: 'button', style: buttonStyle, onClick: () => { if (active && status.state !== 'unlocked') lock(); setOpen(false); } }, 'Close'),
          ),
        ),
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register(
          { name: 'conversation.session.header.actions', id: 'admin-bridge', order: 50 }, AdminAction,
        ));
      },
    };
  },
});
