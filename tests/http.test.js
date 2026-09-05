import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createServer } from 'node:http';
import { attachHttp, createHandler, HTTP_PREFIX, originAllowed, validateOrigins } from '../src/http.js';

const SECRET = 'synthetic-http-test-secret';
const localOrigin = 'http://127.0.0.1:3080';
const trustedOrigin = 'https://admin.example.test';
const validHeaders = () => ({
  host: '127.0.0.1:3080', origin: localOrigin,
  'content-type': 'application/json', 'x-dsh-admin-bridge': '1',
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function bridgeDouble(overrides = {}) {
  const calls = [];
  return {
    calls,
    describe(sessionId) { calls.push(['status', sessionId]); return { state: 'locked' }; },
    lock(sessionId) { calls.push(['lock', sessionId]); return { state: 'locked' }; },
    authenticate(...args) { calls.push(['authenticate', ...args]); return Promise.resolve({ state: 'unlocked' }); },
    cancelRequest(...args) { calls.push(['cancel', ...args]); },
    ...overrides,
  };
}
// EventEmitter request doubles expose body boundaries and TLS/peer facts without a server.
function startRequest(options = {}) {
  const req = new EventEmitter();
  req.method = options.method ?? 'POST';
  req.url = options.url ?? `${HTTP_PREFIX}status`;
  req.headers = options.headers ?? validHeaders();
  req.socket = options.socket ?? { remoteAddress: '127.0.0.1', encrypted: false };
  const res = new EventEmitter();
  Object.assign(res, { destroyed: false, writableEnded: false, statusCode: undefined, headers: {}, text: '' });
  res.writeHead = (statusCode, headers) => { res.statusCode = statusCode; res.headers = headers; };
  res.end = text => { res.text = text; res.writableEnded = true; };
  const bridge = options.bridge ?? bridgeDouble();
  const handler = createHandler({ bridge, allowedOrigins: options.allowedOrigins ?? [],
    requestRejection: options.requestRejection ?? (() => undefined) });
  const completion = handler(req, res);
  return { req, res, bridge, completion };
}
async function request(options = {}) {
  const context = startRequest(options);
  const chunks = options.chunks ?? [Buffer.from(options.rawBody ?? JSON.stringify(Object.hasOwn(options, 'payload') ? options.payload : { sessionId: 'session-a' }))];
  for (const chunk of chunks) context.req.emit('data', chunk);
  context.req.emit('end');
  await context.completion;
  return { ...context, json: JSON.parse(context.res.text) };
}
function errorResponse(response, status, code) {
  assert.equal(response.res.statusCode, status);
  assert.equal(response.json.error.code, code);
  assert.equal(response.bridge.calls.length, 0, 'rejected input must never reach the bridge');
}
function assertBodyListenersRemoved(req) {
  for (const event of ['data', 'end', 'aborted', 'error']) assert.equal(req.listenerCount(event), 0, event);
}

test('origin configuration only permits exact HTTPS or loopback HTTP origins', () => {
  for (const origin of [trustedOrigin, localOrigin, 'http://localhost:3000', 'http://[::1]:3000']) {
    const origins = validateOrigins([origin]);
    assert.deepEqual(origins, [origin]);
    assert.ok(Object.isFrozen(origins));
  }
  for (const origins of [null, {}, 'https://admin.example.test', Array(17).fill(trustedOrigin),
    ['http://admin.example.test'], ['http://192.168.1.1'], ['https://admin.example.test/'],
    ['https://admin.example.test/path'], ['https://admin.example.test?q=x'],
    ['https://admin.example.test#hash'], ['https://user:pass@admin.example.test'],
    ['HTTPS://ADMIN.EXAMPLE.TEST'], ['https://admin.example.test:443'], ['null'],
    ['file:///tmp/test'], ['javascript:alert(1)'], ['http://127.0.0.1.evil.test:3080']]) {
    assert.throws(() => validateOrigins(origins), error => error.code === 'invalid_config');
  }
});

test('loopback HTTP requires an exact Origin/Host pair and a real loopback immediate peer', () => {
  for (const [origin, host, peer] of [
    [localOrigin, '127.0.0.1:3080', '127.0.0.1'],
    ['http://localhost:3080', 'localhost:3080', '::1'],
    ['http://[::1]:3080', '[::1]:3080', '::ffff:127.0.0.1'],
  ]) {
    assert.equal(originAllowed({ headers: { origin, host }, socket: { remoteAddress: peer } }, []), true);
  }
  for (const headers of [
    { host: '127.0.0.1:3080' }, { origin: 'null', host: '127.0.0.1:3080' },
    { origin: `${localOrigin}/`, host: '127.0.0.1:3080' },
    { origin: [localOrigin], host: '127.0.0.1:3080' },
    { origin: localOrigin, host: '127.0.0.1:3081' },
    { origin: localOrigin, host: 'localhost:3080' },
    { origin: 'http://evil.example.test', host: 'evil.example.test' },
    { origin: 'http://127.0.0.1.evil.test:3080', host: '127.0.0.1.evil.test:3080' },
  ]) {
    assert.equal(originAllowed({ headers, socket: { remoteAddress: '127.0.0.1' } }, []), false);
  }
  for (const peer of ['203.0.113.4', '192.168.1.10', undefined]) {
    const req = { headers: { ...validHeaders(), 'x-forwarded-for': '127.0.0.1', 'x-forwarded-proto': 'https',
      forwarded: 'for=127.0.0.1;proto=https;host=127.0.0.1:3080' }, socket: { remoteAddress: peer } };
    assert.equal(originAllowed(req, []), false);
  }
  assert.equal(originAllowed({ headers: validHeaders(), socket: { remoteAddress: '127.0.0.1' } }, [trustedOrigin]), false);
});

test('HTTPS origin requires explicit allowlisting and TLS or a local TLS-proxy hop, never spoofed forwarding headers', () => {
  const headers = { origin: trustedOrigin, host: 'admin.example.test', 'x-forwarded-proto': 'https', 'x-forwarded-for': '127.0.0.1' };
  assert.equal(originAllowed({ headers, socket: { remoteAddress: '203.0.113.4', encrypted: true } }, [trustedOrigin]), true);
  assert.equal(originAllowed({ headers, socket: { remoteAddress: '127.0.0.1' } }, [trustedOrigin]), true);
  assert.equal(originAllowed({ headers, socket: { remoteAddress: '203.0.113.4', encrypted: false } }, [trustedOrigin]), false);
  assert.equal(originAllowed({ headers, socket: { remoteAddress: '203.0.113.4' } }, [trustedOrigin]), false);
  assert.equal(originAllowed({ headers }, [trustedOrigin]), false);
  assert.equal(originAllowed({ headers, socket: { remoteAddress: '127.0.0.1', encrypted: true } }, []), false);
  assert.equal(originAllowed({ headers: { ...headers, origin: 'https://evil.example.test' }, socket: { encrypted: true } }, [trustedOrigin]), false);
});

test('DSH transport authentication is checked first on every endpoint, with no status leak', async () => {
  for (const status of [401, 403]) {
    for (const endpoint of ['status', 'lock', 'authenticate', 'unknown']) {
      let checked = 0;
      const response = await request({ url: `${HTTP_PREFIX}${endpoint}`, requestRejection: req => {
        checked++;
        assert.equal(req.url, `${HTTP_PREFIX}${endpoint}`);
        return status;
      } });
      errorResponse(response, status, 'unauthorized');
      assert.equal(checked, 1);
      assertBodyListenersRemoved(response.req);
    }
  }
});

test('noOrigin transport mode does not bypass the plugin browser-origin fence', async () => {
  const headers = validHeaders();
  delete headers.origin;
  const response = await request({ headers, requestRejection: () => undefined });
  errorResponse(response, 403, 'forbidden');
});

test('method, custom header, origin, and remote plaintext are independently enforced', async () => {
  for (const method of ['GET', 'HEAD', 'PUT', 'OPTIONS', 'DELETE']) {
    errorResponse(await request({ method }), 403, 'forbidden');
  }
  for (const value of [undefined, '', 'true', '0', ['1'], '1, 1']) {
    const headers = { ...validHeaders(), 'x-dsh-admin-bridge': value };
    if (value === undefined) delete headers['x-dsh-admin-bridge'];
    errorResponse(await request({ headers }), 403, 'forbidden');
  }
  errorResponse(await request({ headers: { ...validHeaders(), origin: 'http://evil.example.test' } }), 403, 'forbidden');
  errorResponse(await request({ socket: { remoteAddress: '203.0.113.4' } }), 403, 'forbidden');
  errorResponse(await request({ headers: { ...validHeaders(), origin: trustedOrigin }, allowedOrigins: [trustedOrigin],
    socket: { remoteAddress: '203.0.113.4', encrypted: false } }), 403, 'forbidden');
});

test('valid status, lock, and authentication dispatch only the exact expected arguments', async () => {
  for (const endpoint of ['status', 'lock', 'authenticate']) {
    const payload = endpoint === 'authenticate'
      ? { sessionId: 'session-a', requestId: 'synthetic-nonce', password: SECRET }
      : { sessionId: 'session-a' };
    const response = await request({ url: `${HTTP_PREFIX}${endpoint}`, payload });
    assert.equal(response.res.statusCode, 200);
    assert.deepEqual(response.bridge.calls, [endpoint === 'authenticate'
      ? [endpoint, 'session-a', 'synthetic-nonce', SECRET] : [endpoint, 'session-a']]);
    assert.equal(response.res.text.includes(SECRET), false);
    assert.equal(response.res.headers['Cache-Control'], 'no-store');
    assert.equal(response.res.headers.Pragma, 'no-cache');
    assert.equal(response.res.headers['X-Content-Type-Options'], 'nosniff');
    assert.equal(response.res.headers['Referrer-Policy'], 'no-referrer');
    assert.equal(response.res.headers['Content-Type'], 'application/json; charset=utf-8');
    assert.equal(response.res.headers['Access-Control-Allow-Origin'], undefined);
    assertBodyListenersRemoved(response.req);
    assert.equal(response.res.listenerCount('close'), 0);
  }
});

test('only known exact routes exist: no unrestricted command or unlock endpoint', async () => {
  for (const url of ['/status', '/admin-bridge/v1', `${HTTP_PREFIX}run`, `${HTTP_PREFIX}unlock`,
    `${HTTP_PREFIX}exec`, `${HTTP_PREFIX}status/`, `${HTTP_PREFIX}status?sessionId=session-a`,
    `${HTTP_PREFIX}%73tatus`, `${HTTP_PREFIX}../status`, `${HTTP_PREFIX}authenticate/extra`]) {
    errorResponse(await request({ url }), 404, 'not_found');
  }
});

test('body shape rejects unexpected fields, prototype keys, missing fields, and invalid session identifiers', async () => {
  for (const payload of [null, [], 'text', 1, true, {}, { sessionId: null }, { sessionId: 1 },
    { sessionId: '../session' }, { sessionId: 'a'.repeat(65) }, { sessionId: '' },
    { sessionId: 'session-a', command: 'id' }, { sessionId: 'session-a', operationId: 'inspect' },
    { sessionId: 'session-a', password: SECRET }, { sessionId: 'session-a', ttlSeconds: 900 },
    JSON.parse('{"sessionId":"session-a","__proto__":{"admin":true}}')]) {
    errorResponse(await request({ payload }), 400, 'invalid_request');
  }
  for (const endpoint of ['lock', 'authenticate']) {
    const base = endpoint === 'authenticate' ? { sessionId: 'session-a', requestId: 'nonce', password: SECRET } : { sessionId: 'session-a' };
    errorResponse(await request({ url: `${HTTP_PREFIX}${endpoint}`, payload: { ...base, command: '/bin/sh' } }), 400, 'invalid_request');
    for (const field of Object.keys(base)) {
      const payload = { ...base };
      delete payload[field];
      errorResponse(await request({ url: `${HTTP_PREFIX}${endpoint}`, payload }), 400, 'invalid_request');
    }
  }
});

test('content type, encoding, malformed length, malformed JSON, and declared body cap reject before dispatch', async () => {
  for (const value of [undefined, '', 'text/plain', 'application/x-www-form-urlencoded', 'application/json; charset=latin1',
    'application/json; boundary=x', 'application/json; charset=utf-8; extra=x']) {
    const headers = { ...validHeaders(), 'content-type': value };
    if (value === undefined) delete headers['content-type'];
    errorResponse(await request({ headers }), 400, 'invalid_request');
  }
  for (const encoding of ['', 'identity', 'gzip', 'br']) {
    errorResponse(await request({ headers: { ...validHeaders(), 'content-encoding': encoding } }), 400, 'invalid_request');
  }
  for (const length of ['8193', '999999999999999999999999', '-1', '1.5', '+10', '12x', '']) {
    errorResponse(await request({ headers: { ...validHeaders(), 'content-length': length } }), 400, 'invalid_request');
  }
  for (const rawBody of ['', '{', '{"sessionId":', '{"sessionId":"session-a"} garbage', SECRET]) {
    const response = await request({ rawBody });
    errorResponse(response, 400, 'invalid_request');
    assert.equal(response.res.text.includes(SECRET), false);
    assertBodyListenersRemoved(response.req);
  }
  for (const type of ['application/json', 'application/json; charset=utf-8', 'Application/JSON;Charset=UTF-8']) {
    assert.equal((await request({ headers: { ...validHeaders(), 'content-type': type } })).res.statusCode, 200);
  }
});

test('body cap counts actual bytes across chunks, including multibyte UTF-8 and dishonest lengths', async () => {
  const minimal = JSON.stringify({ sessionId: 'session-a' });
  const atLimit = Buffer.from(minimal + ' '.repeat(8192 - Buffer.byteLength(minimal)));
  assert.equal(atLimit.length, 8192);
  assert.equal((await request({ chunks: [atLimit.subarray(0, 4000), atLimit.subarray(4000)] })).res.statusCode, 200);
  for (const headers of [validHeaders(), { ...validHeaders(), 'content-length': '10' }]) {
    const response = await request({ headers, chunks: [atLimit, Buffer.from(' ')] });
    errorResponse(response, 400, 'invalid_request');
    assertBodyListenersRemoved(response.req);
  }
  const unicode = Buffer.from(JSON.stringify({ sessionId: 'session-a', requestId: 'nonce', password: 'é'.repeat(4096) }));
  assert.ok(unicode.length > 8192);
  errorResponse(await request({ url: `${HTTP_PREFIX}authenticate`, chunks: [unicode] }), 400, 'invalid_request');
});

test('aborted, errored, and timed-out bodies remove listeners and settle without dispatch', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const event of ['aborted', 'error', 'timeout']) {
    const context = startRequest();
    context.req.emit('data', Buffer.from('{'));
    if (event === 'timeout') t.mock.timers.tick(5000);
    else context.req.emit(event, new Error(`raw transport error ${SECRET}`));
    await context.completion;
    errorResponse({ ...context, json: JSON.parse(context.res.text) }, 400, 'invalid_request');
    assert.equal(context.res.text.includes(SECRET), false);
    assertBodyListenersRemoved(context.req);
  }
});

test('internal exceptions and parser/PAM details are sanitized rather than logged or echoed', async () => {
  for (const endpoint of ['status', 'lock', 'authenticate']) {
    const rawError = new Error(`PAM password=${SECRET}; /private/path; stack trace`);
    const bridge = bridgeDouble({
      describe() { throw rawError; }, lock() { throw rawError; }, authenticate() { return Promise.reject(rawError); },
    });
    const response = await request({ bridge, url: `${HTTP_PREFIX}${endpoint}`,
      payload: endpoint === 'authenticate' ? { sessionId: 'session-a', requestId: 'nonce', password: SECRET } : { sessionId: 'session-a' } });
    errorResponse(response, 400, 'internal');
    assert.deepEqual(response.json, { error: { code: 'internal', message: 'Administrator bridge failed; access was not granted.' } });
    assert.equal(response.res.text.includes(SECRET), false);
    assert.equal(response.res.listenerCount('close'), 0);
  }
  const response = await request({ requestRejection: () => { throw new Error(SECRET); } });
  errorResponse(response, 400, 'internal');
});

test('browser disconnect while authenticating cancels only its exact session/nonce and removes cleanup listener', async () => {
  const pending = deferred();
  const bridge = bridgeDouble({ authenticate(...args) {
    this.calls.push(['authenticate', ...args]);
    return pending.promise;
  } });
  const context = startRequest({ bridge, url: `${HTTP_PREFIX}authenticate` });
  context.req.emit('data', Buffer.from(JSON.stringify({ sessionId: 'session-a', requestId: 'nonce-a', password: SECRET })));
  context.req.emit('end');
  await Promise.resolve(); // Continue after the body read, up to the worker's authentication await.
  assert.equal(context.res.listenerCount('close'), 1);
  context.res.destroyed = true;
  context.res.emit('close');
  assert.deepEqual(bridge.calls, [['authenticate', 'session-a', 'nonce-a', SECRET], ['cancel', 'session-a', 'nonce-a']]);
  pending.reject(new Error(`cancelled PAM details ${SECRET}`));
  await context.completion;
  assert.equal(context.res.text, '');
  assert.equal(context.res.listenerCount('close'), 0);
  assertBodyListenersRemoved(context.req);
});

test('normal authentication response does not cancel a completed request when the connection closes', async () => {
  const response = await request({ url: `${HTTP_PREFIX}authenticate`,
    payload: { sessionId: 'session-a', requestId: 'nonce', password: SECRET } });
  response.res.emit('close');
  assert.deepEqual(response.bridge.calls, [['authenticate', 'session-a', 'nonce', SECRET]]);
});

test('HTTP attachment delegates the live DSH connection fence and returns its unregister handle', async () => {
  const bridge = bridgeDouble();
  const cleanup = () => {};
  let registration, checked = 0;
  const ctx = {
    connection: { requestRejection() { checked++; return 401; } },
    webServer: { register(value) { registration = value; return cleanup; } },
  };
  assert.equal(attachHttp(ctx, bridge), cleanup);
  assert.equal(registration.path, HTTP_PREFIX.slice(0, -1));
  assert.equal(registration.kind, 'prefix');
  const req = new EventEmitter();
  const res = { writeHead(status) { this.status = status; }, end(text) { this.text = text; } };
  await registration.handler(req, res);
  assert.equal(checked, 1);
  assert.equal(res.status, 401);
  assert.equal(bridge.calls.length, 0);
});

test('ephemeral loopback node:http fixture enforces browser and transport gates with real fetch', async t => {
  const bridge = bridgeDouble();
  const handler = createHandler({ bridge, requestRejection: req => req.headers.authorization === 'Bearer synthetic-fixture-token' ? undefined : 401 });
  const server = createServer((req, res) => { void handler(req, res); });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = { origin, authorization: 'Bearer synthetic-fixture-token', 'content-type': 'application/json', 'x-dsh-admin-bridge': '1' };
  const send = async overrides => {
    const response = await fetch(`${origin}${HTTP_PREFIX}status`, { method: 'POST', headers: { ...headers, ...overrides }, body: '{"sessionId":"session-a"}' });
    return { status: response.status, json: await response.json(), headers: response.headers };
  };
  const accepted = await send({});
  assert.equal(accepted.status, 200);
  assert.deepEqual(accepted.json, { value: { state: 'locked' } });
  assert.equal(accepted.headers.get('cache-control'), 'no-store');
  assert.equal((await send({ authorization: 'Bearer wrong-token' })).status, 401);
  assert.equal((await send({ origin: 'http://evil.example.test' })).status, 403);
  assert.equal((await send({ 'x-dsh-admin-bridge': '0' })).status, 403);
  assert.deepEqual(bridge.calls, [['status', 'session-a']]);
});
