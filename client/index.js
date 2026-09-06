/* Hand-written rc.1 client module: no build step and no credential state/store. */
window.__ModuleLoader__.load({
  id: 'dsh-admin-bridge',
  factory: require => {
    const React = require('react');
    const { Menu, RiskConfirmation, IconChevronDownOutline14 } = require('@deepseek-ai/dsh-client-ui-primitives');
    const h = React.createElement;
    const { useEffect, useRef, useState } = React;
    const endpoint = '/admin-bridge/v1/';
    const FULL_ACCESS = 'danger-full-access';
    const SUDO = 'sudo-access';
    const emptyStatus = () => ({ state: 'unavailable', modeActive: false, operations: [] });
    const statusCheckError = 'Could not check Sudo access. The host still enforces its deadline.';
    const buttonStyle = { padding: '6px 10px', border: '1px solid GrayText', borderRadius: 6, cursor: 'pointer' };
    const ascii = value => JSON.stringify(value).replace(/[\u007f-\uffff]/g, char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0'));
    // The three native rc.1 glyphs are intentionally byte-for-byte identical path data.
    const shieldOutline = 'M8.20554 0.899994L14.7901 3.36857V7.01026C14.7901 12 11.0466 14.2103 8.20554 15.3C5.36446 14.2103 1.62012 12 1.62012 7.01026V3.36857L8.20554 0.899994Z';
    const shield = () => h('path', { d: shieldOutline, stroke: 'currentColor', strokeWidth: '1.31831', strokeLinejoin: 'round' });
    const path = d => h('path', { d, fill: 'currentColor' });
    const svg = (...children) => h('svg', { width: '16', height: '16', viewBox: '0 0 16 16', fill: 'none', 'aria-hidden': true }, ...children);
    const glyphs = new Map([
      ['read-only', svg(shield(), path('M12.1654 5.7552L8.9447 9.41475C8.73044 9.65816 8.53628 9.8804 8.35774 10.0423C8.1713 10.2114 7.94235 10.3717 7.64016 10.4254C7.48207 10.4535 7.32 10.4552 7.16151 10.4294C6.85843 10.3801 6.62728 10.2223 6.43836 10.0559C6.25752 9.89653 6.06037 9.67732 5.84264 9.43705L4.72925 8.20897L5.63557 7.38707L6.74897 8.61594C6.98603 8.87755 7.12974 9.03533 7.24673 9.13839C7.31033 9.19443 7.34485 9.21476 7.35823 9.22122C7.38068 9.22484 7.40352 9.22515 7.42593 9.22122C7.40522 9.22502 7.42893 9.23294 7.53583 9.136C7.65132 9.03126 7.79316 8.87139 8.02643 8.60638L11.2479 4.94763L12.1654 5.7552Z'))],
      ['workspace-write', svg(
        path('M8.08887 0.251709C8.20479 0.23085 8.32486 0.241168 8.43652 0.282959L15.0215 2.75171C15.2787 2.84819 15.4492 3.09414 15.4492 3.3689V7.0105C15.4492 7.10986 15.4441 7.2081 15.4414 7.30542C15.0285 7.07175 14.5905 6.87695 14.1309 6.73022V3.82495L8.20508 1.60327L2.2793 3.82495V7.0105C2.27936 9.7171 3.4745 11.5379 5.02734 12.7947C5.01025 12.9942 5 13.1962 5 13.4001C5.00001 13.7617 5.02722 14.1169 5.08008 14.4636C2.91555 13.0393 0.961014 10.752 0.960938 7.0105V3.3689C0.960938 3.09417 1.13146 2.84821 1.38867 2.75171L7.97461 0.282959L8.08887 0.251709Z'),
        path('M11.3525 5.64688V6.85688H5V5.64688H11.3525Z'),
        path('M9.5824 8.29376V9.50376H5V8.29376H9.5824Z'),
        path('M14.6647 15.6852H10.0338C10.3878 15.3751 10.7567 15.0517 11.0772 14.7706C11.2531 14.6164 11.4144 14.4746 11.5511 14.3547H14.6647V15.6852Z'),
        path('M8.14852 14.1308L7.33925 15.4976C7.22458 15.6912 7.42245 15.9194 7.63037 15.8333L9.09785 15.2254L15.0399 10.0719L14.0905 8.97733L8.14852 14.1308Z'))],
      [FULL_ACCESS, svg(shield(), path('M9.10094 4.5V8.75939H7.59888V4.5H9.10094Z'), path('M9.10094 9.8114V11.5H7.59888V9.8114H9.10094Z'))],
      [SUDO, svg(shield(), h('circle', { cx: '6.5', cy: '6.2', r: '1.65', stroke: 'currentColor', strokeWidth: '1.3' }),
        h('path', { d: 'M7.7 7.4L10.8 10.5M9.2 8.9L10.4 7.7M10.3 10L11.5 8.8', stroke: 'currentColor', strokeWidth: '1.3', strokeLinecap: 'round', strokeLinejoin: 'round' }))],
    ]);
    const labels = new Map([['read-only', 'Read Only'], ['workspace-write', 'Workspace Write'], [FULL_ACCESS, 'Full access'], [SUDO, 'Sudo access']]);
    function label(value, name = value) {
      if (labels.has(value) && (name === value || name === labels.get(value))) return labels.get(value);
      return /^[a-z0-9]+(-[a-z0-9]+)*$/.test(name) ? name.split('-').map(word => word[0].toUpperCase() + word.slice(1)).join(' ') : name;
    }
    function safeError(code) {
      if (code === 'password_required') return 'Sudo access requires password-based sudo authentication; passwordless sudo is not supported.';
      if (code === 'rate_limited') return 'Wait before requesting authentication again.';
      return 'Authentication did not complete. Select Sudo access again to try a new request.';
    }
    async function post(method, payload, signal) {
      const task = fetch(endpoint + method, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json', 'X-DSH-Admin-Bridge': '1' },
        body: JSON.stringify(payload), signal,
      });
      payload = undefined;
      const response = await task;
      const result = await response.json();
      // Never render backend exception messages, which could contain sensitive data.
      if (!response.ok || result.error) throw new Error(safeError(result.error?.code));
      return result.value;
    }
    async function request(life, method, payload, milliseconds = 5000) {
      const controller = new AbortController();
      life.controllers.add(controller);
      const timer = setTimeout(() => controller.abort(), milliseconds);
      life.timers.add(timer);
      try {
        const task = post(method, payload, controller.signal);
        payload = undefined;
        return await task;
      } finally {
        clearTimeout(timer); life.timers.delete(timer); life.controllers.delete(controller);
      }
    }
    function revokeOnDeparture(sessionId, requestId) {
      // Never revoke an unknown intent or another tab's newer request/lease.
      // An intent whose nonce was never learned expires without starting authentication.
      if (!requestId) return;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      void post('lock', { sessionId, requestId }, controller.signal).catch(() => {}).finally(() => clearTimeout(timer));
    }

    function PermissionControl({ sessionId, value, locked, command }) {
      const [status, setStatus] = useState(emptyStatus);
      const [menuOpen, setMenuOpen] = useState(false);
      const [dialogOpen, setDialogOpen] = useState(false);
      const [busy, setBusy] = useState(false);
      const [error, setError] = useState('');
      const [statusError, setStatusError] = useState('');
      const [pick, setPick] = useState(null);
      const [confirmation, setConfirmation] = useState(null);
      const [acknowledged, setAcknowledged] = useState(false);
      const [now, setNow] = useState(Date.now);
      const scope = useRef(null);
      const dialog = useRef(null);
      const password = useRef(null);
      const clearPassword = () => { if (password.current) password.current.value = ''; };
      const valid = (life, version) => life.alive && scope.current === life && life.version === version;
      function accept(life, next) {
        life.status = next;
        life.pending = !next.modeActive && (next.state === 'pending' || next.state === 'authenticating');
        setStatus(next); setStatusError(''); setNow(Date.now());
        if (next.state === 'pending' && typeof next.requestId === 'string' && !life.dismissed.has(next.requestId)) {
          if (life.requestId !== next.requestId) { clearPassword(); setError(''); }
          life.requestId = next.requestId;
          life.intentId = next.requestId;
          setDialogOpen(true);
        } else {
          life.requestId = null;
          if (!life.pending) life.intentId = null;
          clearPassword(); setDialogOpen(false);
        }
      }
      function begin(life, action) {
        ++life.version;
        for (const controller of life.controllers) controller.abort();
        life.action = action;
        setBusy(true); setError(''); setMenuOpen(false);
        return life.version;
      }
      function finish(life, version) {
        if (valid(life, version)) { life.action = null; setBusy(false); setPick(null); }
      }

      useEffect(() => {
        const life = { sessionId, alive: true, version: 0, pending: false, requestId: null, intentId: null,
          action: null, controllers: new Set(), timers: new Set(), dismissed: new Set(), status: emptyStatus() };
        scope.current = life;
        setStatus(emptyStatus()); setMenuOpen(false); setDialogOpen(false); setBusy(false);
        setError(''); setStatusError(''); setPick(null); setConfirmation(null); setAcknowledged(false); clearPassword();
        let pollTimer;
        async function refresh() {
          if (!life.alive || !sessionId) return;
          const version = life.version;
          if (!life.action) {
            try {
              const next = await request(life, 'status', { sessionId });
              if (valid(life, version)) accept(life, next);
            } catch {
              if (valid(life, version)) {
                if (life.status.modeActive || life.pending || life.status.restorationPending) {
                  setStatus(emptyStatus()); setDialogOpen(false); clearPassword();
                  setStatusError(statusCheckError);
                } else setStatusError('');
              }
            }
          }
          if (life.alive) {
            setNow(Date.now());
            pollTimer = setTimeout(refresh, 1000);
          }
        }
        void refresh();
        return () => {
          life.alive = false; ++life.version;
          clearTimeout(pollTimer);
          for (const timer of life.timers) clearTimeout(timer);
          for (const controller of life.controllers) controller.abort();
          clearPassword();
          if (life.pending || life.action === 'authenticate') revokeOnDeparture(sessionId, life.intentId);
        };
      }, [sessionId]);
      useEffect(() => {
        if (dialogOpen) {
          if (!dialog.current?.open) dialog.current?.showModal();
          if (status.state === 'pending') password.current?.focus();
        } else { clearPassword(); dialog.current?.close(); }
      }, [dialogOpen, status.requestId]);
      useEffect(() => {
        if (locked || value === undefined) {
          setMenuOpen(false); setAcknowledged(false); setConfirmation(null);
        }
      }, [locked, value]);

      async function cancel(requestId) {
        const life = scope.current;
        if (!life?.alive || life.sessionId !== sessionId || !life.pending || !requestId || life.intentId !== requestId) return;
        // The dialog callback captures its rendered nonce, before any local clearing.
        life.dismissed.add(requestId);
        life.requestId = null;
        clearPassword(); setDialogOpen(false);
        const version = begin(life, 'cancel');
        try {
          await request(life, 'lock', { sessionId, requestId });
          if (!valid(life, version)) return;
          life.pending = false;
          const next = await request(life, 'status', { sessionId });
          if (valid(life, version)) accept(life, next);
        } catch {
          if (valid(life, version)) setError('Could not confirm cancellation. The host still enforces its deadline.');
        } finally { finish(life, version); }
      }
      async function submit(id) {
        const life = scope.current;
        if (!life?.alive || life.sessionId !== sessionId || life.action || locked) return;
        if (id === SUDO && life.status.restorationPending) return;
        const version = begin(life, id === SUDO ? 'sudo' : 'native');
        clearPassword(); setDialogOpen(false);
        if (life.requestId) life.dismissed.add(life.requestId);
        life.requestId = null; life.intentId = null;
        if (id === SUDO) {
          life.pending = true;
          setStatus({ ...life.status, modeActive: false });
        } else setPick(id);
        try {
          const ok = await command('/permission ' + id);
          // If departure won the race, no nonce was learned: never blind-cancel the session.
          if (!valid(life, version)) return;
          const next = await request(life, 'status', { sessionId });
          if (!valid(life, version)) return;
          accept(life, next);
          if (!ok) setError(id === SUDO ? 'Could not request Sudo access; wait before retrying.' : 'Could not change the access mode.');
        } catch {
          if (valid(life, version)) {
            // A rejected command/status read supplied no cancellable nonce.
            setError(id === SUDO ? 'Could not request Sudo access; wait before retrying.' : 'Could not change the access mode.');
          }
        } finally { finish(life, version); }
      }
      function choose(id) {
        setMenuOpen(false);
        if (locked || busy || confirmation !== null) return;
        if (id !== SUDO && !value?.options.some(option => option.value === id && id !== 'custom')) return;
        // Even an active Sudo reselection must pass through the native human command.
        if (id === SUDO) return submit(id);
        if (id === value.currentValue && !status.modeActive && !scope.current?.pending && !status.restorationPending) return;
        if (id === FULL_ACCESS && value.currentValue !== FULL_ACCESS) { setAcknowledged(false); setConfirmation(id); return; }
        return submit(id);
      }
      const closeConfirmation = () => { setAcknowledged(false); setConfirmation(null); };
      function confirmFullAccess() {
        if (locked || !acknowledged || confirmation === null) return;
        const id = confirmation;
        closeConfirmation();
        return submit(id);
      }
      async function authenticate(event) {
        event.preventDefault();
        const life = scope.current;
        if (!life?.alive || life.sessionId !== sessionId || life.action || life.status.state !== 'pending' || !life.requestId) return;
        const requestId = life.requestId;
        const version = begin(life, 'authenticate');
        // Uncontrolled DOM value only; clear before the asynchronous authentication POST.
        let secret = password.current?.value ?? '';
        clearPassword();
        try {
          const task = request(life, 'authenticate', { sessionId, requestId, password: secret }, 50_000);
          secret = undefined;
          await task;
          if (!valid(life, version) || life.requestId !== requestId) return;
          const next = await request(life, 'status', { sessionId });
          if (!valid(life, version) || life.requestId !== requestId) return;
          if (next.state === 'pending' && next.requestId !== requestId) {
            // Another human intent superseded this nonce while authentication was in flight.
            accept(life, next); return;
          }
          if (!next.modeActive) throw new Error(safeError());
          accept(life, next);
        } catch (failure) {
          if (valid(life, version) && life.requestId === requestId) {
            life.dismissed.add(requestId); life.requestId = null;
            setDialogOpen(false); setStatus({ ...life.status, state: 'locked', modeActive: false, requestId: undefined });
            // Inspect before cancellation: an old response must not revoke a newer nonce.
            // Never resubmit the password, including when its HTTP response was lost.
            try {
              let next = await request(life, 'status', { sessionId });
              if (!valid(life, version)) return;
              if (next.modeActive || (next.state === 'pending' && next.requestId !== requestId)) {
                accept(life, next); return;
              }
              if (next.state === 'pending' || next.state === 'authenticating') {
                await request(life, 'lock', { sessionId, requestId });
                if (!valid(life, version)) return;
                life.pending = false;
                next = await request(life, 'status', { sessionId });
              }
              if (valid(life, version)) accept(life, next);
            } catch { /* Fixed safe error below; no exception text or credentials. */ }
            if (valid(life, version)) setError(
              [safeError('password_required'), safeError('rate_limited')].includes(failure?.message) ? failure.message : safeError());
          }
        } finally { secret = undefined; finish(life, version); }
      }

      if (value === undefined) return null;
      // A session change may render before its effect runs; never borrow another session's status.
      const ownStatus = scope.current?.sessionId === sessionId ? status : emptyStatus();
      const remaining = Math.max(0, Math.ceil((ownStatus.expiresAt - now) / 1000));
      const active = ownStatus.modeActive === true && remaining > 0;
      const currentValue = active ? SUDO : pick ?? value.currentValue;
      const current = value.options.find(option => option.value === currentValue);
      const currentLabel = active ? 'Sudo access · ' + Math.floor(remaining / 60) + ':' + String(remaining % 60).padStart(2, '0') + ' remaining' : label(currentValue, current?.name ?? currentValue);
      const items = value.options.filter(option => option.value !== 'custom' && option.value !== SUDO).map(option => ({
        id: option.value, label: label(option.value, option.name), ...(glyphs.has(option.value) ? { icon: glyphs.get(option.value) } : {}),
      }));
      items.push({ id: SUDO, label: 'Sudo access', icon: glyphs.get(SUDO), disabled: !!ownStatus.restorationPending });
      const commands = ownStatus.selectedOperations ?? ownStatus.operations ?? [];
      const pending = ownStatus.state === 'pending' && dialogOpen && !!scope.current?.requestId;
      return h(React.Fragment, null,
        h(Menu, { open: menuOpen, items, selectedId: currentValue, onSelect: choose, onClose: () => setMenuOpen(false), side: 'top',
          anchor: h('button', { type: 'button', className: 'Sh0Q9G_trigger',
            'aria-label': 'Access mode: ' + currentLabel, title: current?.description,
            disabled: locked || busy || confirmation !== null, onClick: () => setMenuOpen(!menuOpen) },
          glyphs.has(currentValue) ? h('span', { className: 'Sh0Q9G_triggerIcon', 'aria-hidden': true }, glyphs.get(currentValue)) : null,
          h('span', { className: 'Sh0Q9G_triggerLabel' }, currentLabel),
          h('span', { className: 'Sh0Q9G_chevron' + (menuOpen ? ' Sh0Q9G_chevronOpen' : ''), 'aria-hidden': true }, h(IconChevronDownOutline14))) }),
        h(RiskConfirmation, { open: confirmation !== null, title: 'Enable Full access?',
          description: 'Full access reduces confirmation steps and lets the agent perform more actions directly, including sensitive operations, file changes, or external commands. Only use it when you trust the current task.',
          acknowledgeLabel: 'I understand the risks and want to continue', cancelLabel: 'Cancel', closeLabel: 'Close', confirmLabel: 'Enable Full access',
          acknowledged, disabled: locked, onAcknowledgedChange: setAcknowledged, onCancel: closeConfirmation, onConfirm: confirmFullAccess }),
        ownStatus.restorationPending ? h('p', { role: 'alert' }, 'Sudo access has ended, but the previous filesystem mode could not be restored. Choose a normal access mode before trying Sudo access again.') : null,
        statusError ? h('p', { role: 'alert', style: { color: 'crimson' } }, statusError) : null,
        error ? h('p', { role: 'alert', style: { color: 'crimson' } }, error) : null,
        h('dialog', { ref: dialog, 'aria-label': 'Sudo access',
          style: { maxWidth: 620, width: 'min(90vw, 620px)', maxHeight: '85vh', padding: 24, borderRadius: 12,
            border: '1px solid GrayText', background: 'Canvas', color: 'CanvasText', overflow: 'auto' },
          onCancel: event => { event.preventDefault(); void cancel(ownStatus.requestId); },
          onClose: () => { if (dialogOpen && scope.current?.pending) void cancel(ownStatus.requestId); } },
          h('h2', null, 'Sudo access'),
          h('p', null, 'Session: ', h('code', null, sessionId)),
          h('p', null, 'This grants Full access to the filesystem: the agent can modify or delete files outside the workspace and run sensitive external commands with fewer confirmations. Root command authority is described below. Changes cannot automatically be undone. Continue only if you trust this task.'),
          h('p', null, 'Duration: ', ownStatus.ttlSeconds ?? ownStatus.maxTtlSeconds ?? '—', ' seconds. A new selection always requires a new password authentication.'),
          ownStatus.allowAllCommands ? h('p', { role: 'alert', style: { fontWeight: 'bold' } }, 'All commands allowed: this session’s agent may execute arbitrary bash commands as root, including modifying or deleting any system file, installing software, and starting services. There is no command allowlist. Effects and detached processes may persist after Sudo access ends.') : null,
          h('p', null, 'The agent may request this dialog when root access is needed. Requesting it does not grant privileges; only your authentication does.'),
          commands.length ? h('ul', null, ...commands.map(op => h('li', { key: op.id, style: { marginBottom: 12 } },
            h('strong', null, op.id), ': ', op.label,
            h('pre', { style: { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 } }, ascii([op.executable, ...op.args])),
            h('small', null, 'Command timeout: ', op.timeoutSeconds, ' seconds')))) : !ownStatus.allowAllCommands ? h('p', null, 'No administrator operations are configured.') : null,
          h('p', null, 'Your password goes only to the local sudo authentication process through the trusted Harness host. It is not saved or sent to the model. Do not enter it in chat.'),
          pending ? h('form', { onSubmit: authenticate, autoComplete: 'off' },
            h('label', null, 'Sudo password', h('input', { ref: password, type: 'password', autoComplete: 'off', maxLength: 4096,
              disabled: busy, spellCheck: false, style: { display: 'block', width: '100%', boxSizing: 'border-box', margin: '8px 0', padding: 8 },
              'aria-label': 'Sudo password; never stored' })),
            h('button', { type: 'submit', disabled: busy, style: buttonStyle }, busy ? 'Authenticating…' : 'Authenticate for Sudo access')) : null,
          h('button', { type: 'button', style: { ...buttonStyle, marginTop: 18 }, onClick: () => cancel(ownStatus.requestId) }, 'Cancel')),
      );
    }
    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.input.permission', () => ctx.slots.register(
          { name: 'conversation.input.permission', id: 'admin-bridge', order: 50 }, PermissionControl,
        ));
      },
    };
  },
});
