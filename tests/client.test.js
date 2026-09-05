import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../client/index.js', import.meta.url), 'utf8');

function mount(status, fetch) {
  let loaded;
  let stateIndex = 0;
  const stateWrites = [];
  const refs = [];
  const React = {
    Fragment: 'Fragment',
    createElement(type, props, ...children) { return { type, props: props ?? {}, children }; },
    useState(initial) {
      const index = stateIndex++;
      return [index === 0 ? status : initial, value => stateWrites.push({ index, value })];
    },
    useRef(value) { const ref = { current: value }; refs.push(ref); return ref; },
    useEffect() {},
  };
  const context = vm.createContext({
    window: { __ModuleLoader__: { load(value) { loaded = value; } } },
    fetch, AbortController, AbortSignal, setTimeout, clearTimeout, Date,
  });
  vm.runInContext(source, context);
  assert.equal(loaded.id, 'dsh-admin-bridge');
  const plugin = loaded.factory(name => { assert.equal(name, 'react'); return React; });
  let Component;
  plugin.apply({ slots: {
    inject(name, callback) { assert.equal(name, 'conversation.session.header.actions'); callback(); },
    register(slot, component) { assert.equal(slot.id, 'admin-bridge'); Component = component; },
  } });
  const tree = Component({ sessionId: 'test-session' });
  return { tree, refs, stateWrites };
}
function nodes(tree, type) {
  if (!tree || typeof tree !== 'object') return [];
  return [...(tree.type === type ? [tree] : []), ...(tree.children ?? []).flatMap(child => nodes(child, type))];
}

test('client mounts a header action and never offers password input for disabled policy', () => {
  const { tree } = mount({ state: 'disabled', operations: [] }, () => { throw new Error('Unexpected network'); });
  assert.equal(nodes(tree, 'input').length, 0);
  assert.equal(nodes(tree, 'dialog').length, 1);
});

test('client sends synthetic password only in private POST body and clears input immediately', async () => {
  const secret = 'synthetic-test-password-not-a-credential';
  let finish;
  let network;
  const response = new Promise(resolve => { finish = resolve; });
  const { tree, refs, stateWrites } = mount({ state: 'pending', requestId: 'browser-only-request',
    operations: [], selectedOperations: [], ttlSeconds: 60 }, (url, options) => {
    network = { url, options };
    return response;
  });
  const inputs = nodes(tree, 'input');
  assert.equal(inputs.length, 1);
  assert.equal(inputs[0].props.type, 'password');
  assert.equal(inputs[0].props.autoComplete, 'off');
  refs[1].current = { value: secret };
  const task = nodes(tree, 'form')[0].props.onSubmit({ preventDefault() {} });
  assert.equal(refs[1].current.value, '');
  assert.equal(network.url, '/admin-bridge/v1/authenticate');
  assert.equal(network.options.method, 'POST');
  assert.equal(network.options.credentials, 'same-origin');
  assert.equal(network.options.cache, 'no-store');
  assert.deepEqual(JSON.parse(network.options.body), {
    sessionId: 'test-session', requestId: 'browser-only-request', password: secret,
  });
  assert.equal(JSON.stringify(stateWrites).includes(secret), false);
  finish({ ok: true, json: async () => ({ value: { state: 'unlocked' } }) });
  await task;
  assert.equal(JSON.stringify(stateWrites).includes(secret), false);
});

test('client displays exact argv as text with non-ASCII escaped, not executable markup', () => {
  const { tree } = mount({ state: 'locked', operations: [{ id: 'demo', label: 'Demo',
    executable: '/usr/bin/printf', args: ['<img src=x>', '\u202eevil'], timeoutSeconds: 5 }] }, () => {});
  const pre = nodes(tree, 'pre')[0];
  assert.equal(pre.props.dangerouslySetInnerHTML, undefined);
  assert.equal(pre.children[0], '["/usr/bin/printf","<img src=x>","\\u202eevil"]');
});
