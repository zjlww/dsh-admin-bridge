import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { Context } from '@deepseek-ai/cordis';
import * as connectionPlugin from '@deepseek-ai/dsh-client-connection';
import { createHandler } from '../src/http.js';

// Exercise native DSH cookie verification using an ephemeral in-memory credential
// provider. Never reads the real Harness home, launch token, cookies or secrets.
test('bridge route enforces real DSH browser authentication plus its stricter Origin fence', async t => {
  const ctx = new Context();
  const fixture = await ctx.plugin({ apply(c) {
    c.provide('webServer', { register() { return () => {}; } });
    c.provide('credentials', { async modifyRecord(_key, update) { return update(undefined); } });
  } });
  const connection = await ctx.plugin(connectionPlugin, {});
  t.after(async () => { await connection.dispose(); await fixture.dispose(); await ctx.fiber.dispose(); });
  const host = '127.0.0.1:3080';
  const origin = 'http://' + host;
  const login = new URL(ctx.connection.authenticatedUrl(origin));
  let headers;
  ctx.connection.authorizeIndex({ method: 'GET', url: login.pathname + login.search, headers: { host } }, {
    writeHead(status, value) { assert.equal(status, 303); headers = value; }, end() {},
  });
  const cookie = headers['set-cookie'].split(';', 1)[0];
  const handler = createHandler({ bridge: { describe: () => ({ state: 'locked' }) },
    requestRejection: request => ctx.connection.requestRejection(request) });
  async function request(overrides = {}) {
    const req = new PassThrough();
    req.method = 'POST'; req.url = '/admin-bridge/v1/status';
    req.socket = { remoteAddress: '127.0.0.1' };
    req.headers = { host, origin, cookie, 'content-type': 'application/json', 'x-dsh-admin-bridge': '1', ...overrides };
    let status;
    let response;
    const res = { destroyed: false, writableEnded: false,
      writeHead(code) { status = code; },
      end(text) { this.writableEnded = true; response = JSON.parse(text); },
    };
    const pending = handler(req, res);
    req.end(JSON.stringify({ sessionId: 'fixture-session' }));
    await pending;
    req.destroy();
    return { status, response };
  }
  assert.equal((await request({ cookie: undefined })).status, 401);
  assert.equal((await request({ cookie: cookie.slice(0, -3) + 'bad' })).status, 401);
  assert.equal((await request({ origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await request({ origin: undefined })).status, 403);
  assert.deepEqual(await request(), { status: 200, response: { value: { state: 'locked' } } });
});
