import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createHash } from 'node:crypto';

const source = await readFile(new URL('../client/index.js', import.meta.url), 'utf8');
const initialTime = 1_700_000_000_000;
const native = { currentValue: 'workspace-write', options: [
  { value: 'read-only', name: 'Read Only' },
  { value: 'workspace-write', name: 'Workspace Write' },
  { value: 'danger-full-access', name: 'Full access' },
] };
const operation = { id: 'demo', label: 'Demo', executable: '/usr/bin/printf',
  args: ['<img src=x>', '\u202eevil'], timeoutSeconds: 5 };
const baseStatus = { state: 'locked', modeActive: false, operations: [operation], maxTtlSeconds: 60 };
const pending = requestId => ({ ...baseStatus, state: 'pending', requestId, selectedOperations: [operation] });
const active = () => ({ ...baseStatus, state: 'unlocked', modeActive: true, expiresAt: initialTime + 60_000 });
const response = value => ({ ok: true, json: async () => ({ value: structuredClone(value) }) });
const failure = (code, message) => ({ ok: false, json: async () => ({ error: { code, message } }) });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
function nodes(tree, type) {
  if (Array.isArray(tree)) return tree.flatMap(child => nodes(child, type));
  if (!tree || typeof tree !== 'object') return [];
  return [...(tree.type === type ? [tree] : []), ...(tree.children ?? []).flatMap(child => nodes(child, type))];
}
function text(tree) {
  if (tree === null || tree === undefined || tree === false) return '';
  if (Array.isArray(tree)) return tree.map(text).join('');
  return typeof tree === 'object' ? text(tree.children) : String(tree);
}

// Tiny hook/commit runner: real effect cleanups, persistent refs and uncontrolled DOM,
// deterministic fake clock, and synthetic fetch only. No browser or live permissions.
function mount(options = {}) {
  let loaded, Component, cursor = 0, dirty = false, mounted = true, clock = initialTime, timerId = 0;
  const hooks = [], timers = new Map(), registrations = [], stateWrites = [], requests = [], commands = [];
  const methods = {};
  const backend = { status: options.status ?? structuredClone(baseStatus), count: 0 };
  let props = { sessionId: 'test-session', value: structuredClone(native), locked: false };
  let tree;
  const setTimeoutFake = (callback, delay) => { const id = ++timerId; timers.set(id, { callback, at: clock + delay, delay }); return id; };
  const React = {
    Fragment: 'Fragment',
    createElement(type, props, ...children) { return { type, props: props ?? {}, children }; },
    useState(initial) {
      const index = cursor++;
      hooks[index] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [hooks[index].value, value => {
        assert.ok(mounted, 'no state callback after unmount');
        const next = typeof value === 'function' ? value(hooks[index].value) : value;
        stateWrites.push(next);
        if (!Object.is(next, hooks[index].value)) { hooks[index].value = next; dirty = true; }
      }];
    },
    useRef(initial) { const index = cursor++; hooks[index] ??= { current: initial }; return hooks[index]; },
    useEffect(effect, deps) {
      const index = cursor++;
      const old = hooks[index];
      if (!old || deps.some((dep, i) => !Object.is(dep, old.deps[i]))) hooks[index] = { deps, effect, cleanup: old?.cleanup, run: true };
    },
  };
  class FakeDate extends Date { static now() { return clock; } }
  const context = vm.createContext({
    window: { __ModuleLoader__: { load(value) { loaded = value; } } },
    fetch(url, fetchOptions) {
      const method = url.slice('/admin-bridge/v1/'.length);
      const record = { url, options: fetchOptions, method, body: JSON.parse(fetchOptions.body),
        passwordAtSend: nodes(tree, 'input')[0]?.props.ref.current?.value };
      requests.push(record);
      if (method === 'lock') assert.ok(typeof record.body.requestId === 'string' && record.body.requestId.length > 0, 'every client cancellation is nonce-scoped');
      if (methods[method]) return methods[method](record);
      if (method === 'authenticate') backend.status = active();
      if (method === 'lock' && record.body.requestId === backend.status.requestId)
        backend.status = { ...baseStatus, restorationPending: backend.status.restorationPending };
      assert.ok(['status', 'authenticate', 'lock'].includes(method), 'only private bridge endpoints');
      return Promise.resolve(response(backend.status));
    },
    AbortController, setTimeout: setTimeoutFake, clearTimeout: id => timers.delete(id), Date: FakeDate,
    console: new Proxy({}, { get() { return () => assert.fail('Client must never log authentication data'); } }),
  });
  vm.runInContext(source, context);
  assert.equal(loaded.id, 'dsh-admin-bridge');
  const plugin = loaded.factory(name => {
    if (name === 'react') return React;
    assert.equal(name, '@deepseek-ai/dsh-client-ui-primitives');
    return { Menu: 'Menu', RiskConfirmation: 'RiskConfirmation', IconChevronDownOutline14: 'IconChevronDownOutline14' };
  });
  plugin.apply({ slots: {
    inject(name, callback) { registrations.push({ kind: 'inject', name }); callback(); },
    register(slot, component) { registrations.push({ kind: 'register', ...slot }); Component = component; },
  } });
  props.command = async line => {
    commands.push(line);
    if (options.command) return options.command(line);
    if (line === '/permission sudo-access') backend.status = pending('request-' + ++backend.count);
    else {
      backend.status = structuredClone(baseStatus);
      props = { ...props, value: { ...props.value, currentValue: line.slice('/permission '.length) } };
      dirty = true;
    }
    return true;
  };
  function render() {
    dirty = false; cursor = 0;
    const oldRefs = [...nodes(tree, 'input'), ...nodes(tree, 'dialog')].map(node => node.props.ref);
    tree = Component(props);
    const domNodes = [...nodes(tree, 'input'), ...nodes(tree, 'dialog')];
    for (const ref of oldRefs) if (!domNodes.some(node => node.props.ref === ref)) ref.current = null;
    for (const node of domNodes) {
      const ref = node.props.ref;
      if (!ref.current) ref.current = node.type === 'input' ? { value: '', focus() {} } : {
        open: false,
        showModal() { this.open = true; },
        close() { if (this.open) { this.open = false; nodes(tree, 'dialog')[0]?.props.onClose(); } },
      };
    }
    for (const hook of hooks) if (hook?.run) {
      hook.run = false; hook.cleanup?.(); hook.cleanup = hook.effect();
    }
  }
  render();
  const app = {
    backend, methods, registrations, stateWrites, requests, commands, timers,
    get tree() { return tree; },
    get input() { return nodes(tree, 'input')[0]; },
    get menu() { return nodes(tree, 'Menu')[0]; },
    get risk() { return nodes(tree, 'RiskConfirmation')[0]; },
    get dialog() { return nodes(tree, 'dialog')[0]; },
    get label() { return text(this.menu.props.anchor); },
    get alerts() { return nodes(tree, 'p').filter(node => node.props.role === 'alert').map(text).join(' '); },
    async flush() {
      for (let i = 0; i < 40; i++) { if (dirty && mounted) render(); await Promise.resolve(); }
    },
    setProps(next) { props = { ...props, ...next }; dirty = true; render(); },
    select(id) { return this.menu.props.onSelect(id); },
    authenticate(secret) {
      this.input.props.ref.current.value = secret;
      return nodes(tree, 'form')[0].props.onSubmit({ preventDefault() {} });
    },
    async advance(milliseconds = 1000) {
      clock += milliseconds;
      for (const [id, timer] of [...timers]) if (timer.at <= clock && timers.delete(id)) timer.callback();
      await this.flush();
    },
    async unmount() {
      for (const hook of hooks) hook?.cleanup?.();
      mounted = false;
      await this.flush();
    },
  };
  return app;
}

// Snapshot hashes refer to the original native rc.1 SVG path data in order.
const digestPaths = icon => createHash('sha256').update(nodes(icon, 'path').map(node => node.props.d).join('\n')).digest('hex');

test('only the composer single slot is registered; exactly four native-compatible choices', async () => {
  const app = mount(); await app.flush();
  assert.deepEqual(app.registrations.map(row => row.name), ['conversation.input.permission', 'conversation.input.permission']);
  assert.equal(app.registrations[1].id, 'admin-bridge');
  assert.deepEqual(Array.from(app.menu.props.items, item => [item.id, item.label]), [
    ['read-only', 'Read Only'], ['workspace-write', 'Workspace Write'], ['danger-full-access', 'Full access'], ['sudo-access', 'Sudo access'],
  ]);
  assert.equal(app.menu.props.side, 'top');
  assert.equal(app.label, 'Workspace Write');
  const icons = app.menu.props.items.map(item => item.icon);
  assert.deepEqual(Array.from(icons, icon => nodes(icon, 'path').length), [2, 5, 3, 2]);
  assert.equal(nodes(icons[3], 'circle').length, 1, 'fourth shield has a distinct key head');
  assert.equal(nodes(icons[3], 'path')[0].props.d, nodes(icons[0], 'path')[0].props.d);
  assert.equal(new Set(icons.map(digestPaths)).size, 4);
  assert.equal(nodes(icons[3], 'path')[1].props.d, 'M7.7 7.4L10.8 10.5M9.2 8.9L10.4 7.7M10.3 10L11.5 8.8');
  assert.doesNotMatch(source, /conversation\.session\.header|commandUi|decorate|localStorage|sessionStorage|console\./);
  await app.unmount();
});

test('agent-initiated pending status opens dialog and discloses unrestricted root scope', async () => {
  const app = mount({ status: { ...pending('agent-request'), allowAllCommands: true, operations: [], selectedOperations: [] } });
  await app.flush();
  assert.deepEqual(app.commands, [], 'no manual selector command required');
  assert.match(text(app.tree), /All commands allowed/);
  assert.match(text(app.tree), /arbitrary bash commands as root/);
  assert.doesNotMatch(text(app.tree), /No administrator operations are configured/);
  assert.equal(app.requests.some(r => r.method === 'authenticate'), false);
  await app.unmount();
});

test('keeps native glyph path fingerprints unchanged', async () => {
  const app = mount(); await app.flush();
  // Exact original path strings are pinned rather than reading a developer's installed runtime.
  assert.deepEqual(Array.from(app.menu.props.items.slice(0, 3), item => digestPaths(item.icon)), [
    '03957c1f642e59b03c3ec29a620dfe9643b0a139c359c0289a6d04e8c4bf688c',
    '2574591fb7529be1708436d99c80cd043e585050ad22caa5c721a3f65a2f6bb4',
    '84f534edb2e34b5950c30a6ace0fd87b772bbf943fbe602fecbe9a644cdddb0e',
  ]);
  await app.unmount();
});

test('native changes use original human command and Full access keeps acknowledgement gate', async () => {
  const app = mount(); await app.flush();
  app.select('danger-full-access'); await app.flush();
  assert.deepEqual(app.commands, []);
  assert.equal(app.risk.props.open, true);
  assert.equal(app.risk.props.title, 'Enable Full access?');
  assert.match(app.risk.props.description, /including sensitive operations, file changes, or external commands/);
  app.risk.props.onConfirm(); await app.flush();
  assert.deepEqual(app.commands, []);
  app.risk.props.onAcknowledgedChange(true); await app.flush();
  await app.risk.props.onConfirm(); await app.flush();
  assert.deepEqual(app.commands, ['/permission danger-full-access']);
  assert.equal(app.risk.props.open, false);
  assert.equal(app.label, 'Full access');
  await app.select('read-only'); await app.flush();
  assert.equal(app.commands.at(-1), '/permission read-only');
  assert.equal(app.label, 'Read Only');
  await app.unmount();
});

test('native confirmation cancellation and locked owner never execute commands', async () => {
  const app = mount(); await app.flush();
  app.select('danger-full-access'); await app.flush();
  app.risk.props.onCancel(); await app.flush();
  assert.equal(app.risk.props.open, false);
  app.setProps({ locked: true }); await app.flush();
  app.select('sudo-access'); app.select('read-only'); await app.flush();
  assert.equal(app.menu.props.anchor.props.disabled, true);
  assert.deepEqual(app.commands, []);
  app.setProps({ value: undefined }); await app.flush();
  assert.equal(app.tree, null);
  await app.unmount();
});

test('Sudo entry invokes command then status, keeps native label, and shows exact scope and TTL', async () => {
  const app = mount(); await app.flush();
  await app.select('sudo-access'); await app.flush();
  assert.deepEqual(app.commands, ['/permission sudo-access']);
  assert.equal(app.requests.at(-1).method, 'status');
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.dialog.props.ref.current.open, true);
  assert.match(text(app.dialog), /Full access to the filesystem/);
  assert.match(text(app.dialog), /outside the workspace/);
  assert.match(text(app.dialog), /Duration: 60 seconds/);
  const pre = nodes(app.tree, 'pre')[0];
  assert.equal(pre.props.dangerouslySetInnerHTML, undefined);
  assert.equal(pre.children[0], '["/usr/bin/printf","<img src=x>","\\u202eevil"]');
  assert.equal(app.input.props.value, undefined);
  assert.equal(app.input.props.onChange, undefined);
  assert.equal(app.input.props.type, 'password');
  assert.equal(app.input.props.autoComplete, 'off');
  await app.unmount();
});

test('synthetic password clears before fetch and travels only in private authenticate body', async () => {
  const app = mount({ status: pending('nonce-only-in-browser') }); await app.flush();
  const secret = 'synthetic-test-password-not-a-credential';
  const network = deferred();
  app.methods.authenticate = () => network.promise;
  const dom = app.input.props.ref.current;
  const task = app.authenticate(secret);
  assert.equal(dom.value, '');
  const request = app.requests.at(-1);
  assert.equal(request.method, 'authenticate');
  assert.equal(request.passwordAtSend, '');
  assert.deepEqual(request.body, { sessionId: 'test-session', requestId: 'nonce-only-in-browser', password: secret });
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.credentials, 'same-origin');
  assert.equal(request.options.cache, 'no-store');
  assert.equal(request.options.redirect, 'error');
  assert.equal(request.options.headers['X-DSH-Admin-Bridge'], '1');
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.equal(JSON.stringify(app.stateWrites).includes(secret), false);
  assert.equal(JSON.stringify(app.commands).includes(secret), false);
  app.backend.status = active();
  network.resolve(response({ state: 'unlocked' }));
  await task; await app.flush();
  assert.equal(app.requests.at(-1).method, 'status', 'authentication response alone never claims a committed mode');
  assert.equal(app.label, 'Sudo access · 1:00 remaining');
  assert.equal(app.dialog.props.ref.current.open, false);
  assert.equal(JSON.stringify(app.stateWrites).includes(secret), false);
  assert.equal(app.requests.filter(row => row.method !== 'authenticate').some(row => JSON.stringify(row.body).includes(secret)), false);
  await app.unmount();
});

test('auth response without committed modeActive never claims Sudo access or retries', async () => {
  const app = mount({ status: pending('nonce-no-commit') }); await app.flush();
  app.methods.authenticate = async () => response({ state: 'unlocked' });
  await app.authenticate('synthetic-no-commit'); await app.flush();
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.input, undefined);
  assert.match(app.alerts, /Select Sudo access again/);
  await app.advance(5000);
  assert.equal(app.requests.filter(row => row.method === 'authenticate').length, 1);
  await app.unmount();
});

test('failed password returns to prior label, never renders raw errors, and re-entry uses fresh nonce', async () => {
  const app = mount(); await app.flush();
  await app.select('sudo-access'); await app.flush();
  const firstNonce = app.backend.status.requestId;
  const secret = 'synthetic-sensitive-error-content';
  app.methods.authenticate = async () => failure('auth_failed', 'raw host exception ' + secret);
  await app.authenticate(secret); await app.flush();
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.dialog.props.ref.current.open, false);
  assert.match(app.alerts, /Select Sudo access again/);
  assert.equal(JSON.stringify(app.stateWrites).includes(secret), false);
  assert.equal(text(app.tree).includes(secret), false);
  await app.advance(10_000);
  assert.equal(app.requests.filter(row => row.method === 'authenticate').length, 1);
  await app.select('sudo-access'); await app.flush();
  assert.notEqual(app.backend.status.requestId, firstNonce);
  assert.equal(app.input.props.ref.current.value, '');
  assert.equal(app.commands.filter(line => line === '/permission sudo-access').length, 2);
  delete app.methods.authenticate;
  await app.authenticate('synthetic-new-attempt'); await app.flush();
  assert.equal(app.label, 'Sudo access · 0:50 remaining');
  assert.notEqual(app.requests.filter(row => row.method === 'authenticate')[1].body.requestId, firstNonce);
  await app.unmount();
});

test('passwordless diagnostic is fixed safe text and command cooldown failure has safe guidance', async () => {
  const app = mount({ status: pending('nonce') }); await app.flush();
  app.methods.authenticate = async () => failure('password_required', 'RAW SECRET');
  await app.authenticate('synthetic'); await app.flush();
  assert.match(app.alerts, /passwordless sudo is not supported/);
  assert.doesNotMatch(app.alerts, /RAW SECRET/);
  await app.unmount();
  const denied = mount({ command: async () => false }); await denied.flush();
  await denied.select('sudo-access'); await denied.flush();
  assert.equal(denied.label, 'Workspace Write');
  assert.equal(denied.input, undefined);
  assert.match(denied.alerts, /wait before retrying/);
  await denied.unmount();
});

for (const action of ['cancel-button', 'escape', 'native-close']) {
  test(`${action} revokes pending intent and clears password`, async () => {
    const app = mount({ status: pending('cancel-nonce') }); await app.flush();
    const dom = app.input.props.ref.current;
    dom.value = 'synthetic-cancel';
    if (action === 'escape') app.dialog.props.onCancel({ preventDefault() {} });
    else if (action === 'native-close') app.dialog.props.onClose();
    else nodes(app.dialog, 'button').find(button => text(button) === 'Cancel').props.onClick();
    assert.equal(dom.value, '');
    await app.flush();
    assert.equal(app.requests.filter(row => row.method === 'lock').length, 1);
    assert.deepEqual(app.requests.find(row => row.method === 'lock').body, { sessionId: 'test-session', requestId: 'cancel-nonce' });
    assert.equal(app.dialog.props.ref.current.open, false);
    assert.equal(app.label, 'Workspace Write');
    assert.equal(app.requests.filter(row => row.method === 'authenticate').length, 0);
    await app.unmount();
  });
}

test('active reselection always creates a fresh intent and returns to native label pending password', async () => {
  const app = mount({ status: active() }); await app.flush();
  assert.match(app.label, /^Sudo access/);
  await app.select('sudo-access'); await app.flush();
  assert.equal(app.commands.at(-1), '/permission sudo-access');
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.input.props.ref.current.value, '');
  assert.equal(app.requests.filter(row => row.method === 'authenticate').length, 0);
  await app.unmount();
});

test('dropping Sudo to underlying Full access executes native exit without redundant risk gate', async () => {
  const app = mount({ status: active() }); await app.flush();
  app.setProps({ value: { ...native, currentValue: 'danger-full-access' } }); await app.flush();
  await app.select('danger-full-access'); await app.flush();
  assert.equal(app.risk.props.open, false);
  assert.equal(app.commands.at(-1), '/permission danger-full-access');
  assert.equal(app.label, 'Full access');
  assert.equal(app.requests.filter(row => row.method === 'lock').length, 0, 'intentional mode exit remains the unconditional native command');
  // A stale active flag must not skip the risk gate after native restoration to Read Only.
  app.backend.status = active(); await app.advance();
  app.setProps({ value: { ...native, currentValue: 'read-only' } }); await app.flush();
  app.select('danger-full-access'); await app.flush();
  assert.equal(app.risk.props.open, true);
  assert.equal(app.commands.length, 1);
  await app.unmount();
});

test('restoration warning prevents Sudo re-entry but permits native mode repair', async () => {
  const app = mount({ status: { ...baseStatus, restorationPending: true } }); await app.flush();
  assert.match(app.alerts, /previous filesystem mode could not be restored/);
  assert.equal(app.menu.props.items[3].disabled, true);
  await app.select('sudo-access'); await app.flush();
  assert.deepEqual(app.commands, []);
  await app.select('workspace-write'); await app.flush();
  assert.equal(app.commands.at(-1), '/permission workspace-write');
  assert.equal(app.menu.props.items[3].disabled, false);
  await app.unmount();
});

test('only modeActive and unexpired deadline control Sudo label, not legacy state names', async () => {
  const app = mount({ status: { ...active(), modeActive: false } }); await app.flush();
  assert.equal(app.label, 'Workspace Write');
  app.backend.status = active(); await app.advance();
  assert.equal(app.label, 'Sudo access · 0:59 remaining');
  await app.advance(60_000);
  assert.equal(app.label, 'Workspace Write');
  assert.doesNotMatch(text(app.dialog), /\b(?:disabled|enabled|locked|unlocked|unavailable)\b/i);
  await app.unmount();
});

test('polling is bounded, abortable, and unmount cancels pending intent without leaked timers', async () => {
  const app = mount({ status: pending('departure-nonce') }); await app.flush();
  const dom = app.input.props.ref.current;
  dom.value = 'synthetic-departure';
  const delayed = deferred();
  app.methods.status = () => delayed.promise;
  await app.advance();
  const poll = app.requests.at(-1);
  assert.equal(poll.method, 'status');
  assert.equal(poll.options.signal.aborted, false);
  await app.unmount();
  assert.equal(dom.value, '');
  assert.equal(poll.options.signal.aborted, true);
  assert.equal(app.requests.at(-1).method, 'lock');
  assert.deepEqual(app.requests.at(-1).body, { sessionId: 'test-session', requestId: 'departure-nonce' });
  assert.equal(app.timers.size, 0);
  delayed.resolve(response(pending('stale-nonce'))); await app.flush();
  assert.equal(app.timers.size, 0);
});

test('session switch aborts authentication and stale completion cannot change new session UI', async () => {
  const app = mount({ status: pending('old-session-nonce') }); await app.flush();
  const delayed = deferred();
  app.methods.authenticate = () => delayed.promise;
  const task = app.authenticate('synthetic-old-session'); await app.flush();
  const auth = app.requests.find(row => row.method === 'authenticate');
  app.backend.status = structuredClone(baseStatus);
  app.setProps({ sessionId: 'second-session' }); await app.flush();
  assert.equal(auth.options.signal.aborted, true);
  assert.ok(app.requests.some(row => row.method === 'lock' && row.body.sessionId === 'test-session'));
  delayed.resolve(response(active())); await task; await app.flush();
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.input, undefined);
  await app.unmount();
});

test('cancel during authentication prevents old nonce result from closing fresh request', async () => {
  const app = mount({ status: pending('old-nonce') }); await app.flush();
  const delayed = deferred();
  app.methods.authenticate = () => delayed.promise;
  const task = app.authenticate('synthetic-old-nonce'); await app.flush();
  app.dialog.props.onCancel({ preventDefault() {} }); await app.flush();
  await app.select('sudo-access'); await app.flush();
  const fresh = app.backend.status.requestId;
  const dom = app.input.props.ref.current;
  dom.value = 'synthetic-fresh-unsubmitted';
  delayed.resolve(response(active())); await task; await app.flush();
  assert.equal(app.input.props.ref.current, dom);
  assert.equal(dom.value, 'synthetic-fresh-unsubmitted');
  assert.equal(app.backend.status.requestId, fresh);
  assert.equal(app.label, 'Workspace Write');
  assert.equal(app.dialog.props.ref.current.open, true);
  await app.unmount();
});

test('stale poll cannot overwrite newer selection and nonce', async () => {
  const app = mount(); await app.flush();
  const delayed = deferred();
  let count = 0;
  app.methods.status = () => ++count === 1 ? delayed.promise : Promise.resolve(response(app.backend.status));
  await app.advance();
  const poll = app.requests.at(-1);
  await app.select('sudo-access'); await app.flush();
  assert.equal(poll.options.signal.aborted, true);
  const dom = app.input.props.ref.current;
  dom.value = 'synthetic-current';
  delayed.resolve(response(pending('outdated-poll'))); await app.flush();
  assert.equal(app.input.props.ref.current.value, 'synthetic-current');
  await app.unmount();
});

test('late human command after unmount never blindly cancels an unknown nonce', async () => {
  const delayed = deferred();
  const app = mount({ command: () => delayed.promise }); await app.flush();
  const task = app.select('sudo-access'); await app.flush();
  await app.unmount();
  delayed.resolve(true); await task; await app.flush();
  assert.equal(app.requests.filter(row => row.method === 'lock').length, 0);
  assert.equal(app.timers.size, 0);
});

for (const outcome of ['success', 'failure']) {
  test(`a newer backend nonce survives stale authentication ${outcome}`, async () => {
    const app = mount({ status: pending('older-intent') }); await app.flush();
    const delayed = deferred();
    app.methods.authenticate = () => delayed.promise;
    const task = app.authenticate('synthetic-superseded'); await app.flush();
    app.backend.status = pending('new-human-intent');
    delayed.resolve(outcome === 'success' ? response(active()) : failure('auth_failed', 'unsafe detail'));
    await task; await app.flush();
    assert.equal(app.requests.filter(row => row.method === 'lock').length, 0);
    assert.equal(app.backend.status.requestId, 'new-human-intent');
    assert.equal(app.dialog.props.ref.current.open, true);
    assert.equal(app.input.props.ref.current.value, '');
    assert.equal(app.alerts, '');
    delete app.methods.authenticate;
    await app.authenticate('synthetic-new-human-intent'); await app.flush();
    assert.equal(app.requests.filter(row => row.method === 'authenticate').at(-1).body.requestId, 'new-human-intent');
    await app.unmount();
  });
}

test('a rejected mode command never blindly cancels an unknown nonce and keeps a safe error', async () => {
  const app = mount({ command: async () => { throw new Error('RAW-UNSAFE-DETAIL'); } }); await app.flush();
  await app.select('sudo-access'); await app.flush();
  assert.equal(app.requests.filter(row => row.method === 'lock').length, 0);
  assert.match(app.alerts, /Could not request Sudo access/);
  assert.doesNotMatch(app.alerts, /RAW-UNSAFE-DETAIL/);
  assert.equal(app.label, 'Workspace Write');
  await app.unmount();
});

test('polling replaces external pending nonce and clears an unsubmitted password', async () => {
  const app = mount({ status: pending('first-external') }); await app.flush();
  const dom = app.input.props.ref.current;
  dom.value = 'synthetic-not-submitted';
  app.backend.status = pending('second-external');
  await app.advance();
  assert.equal(dom.value, '');
  await app.authenticate('synthetic-second'); await app.flush();
  assert.equal(app.requests.find(row => row.method === 'authenticate').body.requestId, 'second-external');
  await app.unmount();
});

test('duplicate submit events cannot reuse a password request; pending poll does not erase input', async () => {
  const app = mount({ status: pending('one-attempt') }); await app.flush();
  const dom = app.input.props.ref.current;
  dom.value = 'synthetic-user-is-typing';
  await app.advance();
  assert.equal(dom.value, 'synthetic-user-is-typing');
  const delayed = deferred(); app.methods.authenticate = () => delayed.promise;
  const first = app.authenticate('synthetic-once');
  nodes(app.tree, 'form')[0].props.onSubmit({ preventDefault() {} });
  assert.equal(app.requests.filter(row => row.method === 'authenticate').length, 1);
  app.backend.status = active(); delayed.resolve(response(active()));
  await first; await app.flush();
  await app.unmount();
});
