import { BridgeError, exactKeys, fail, identifier, publicError } from './policy.js';

export const HTTP_PREFIX = '/admin-bridge/v1/';
const LIMIT = 8192;
const loopbackNames = new Set(['localhost', '127.0.0.1', '[::1]']);
const loopbackPeers = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

export function validateOrigins(origins = []) {
  if (!Array.isArray(origins) || origins.length > 16) fail('invalid_config', 'Configure at most 16 browser origins.');
  for (const value of origins) {
    let url;
    try { url = new URL(value); } catch { fail('invalid_config', 'Invalid browser origin.'); }
    if (url.origin !== value || url.username || url.password ||
        !(url.protocol === 'https:' || (url.protocol === 'http:' && loopbackNames.has(url.hostname))))
      fail('invalid_config', 'Browser origins must be exact HTTPS or loopback HTTP origins.');
  }
  return Object.freeze([...origins]);
}

export function originAllowed(req, allowedOrigins) {
  const origin = req.headers.origin;
  if (typeof origin !== 'string') return false;
  let url;
  try { url = new URL(origin); } catch { return false; }
  if (url.origin !== origin) return false;
  if (url.protocol === 'https:') return allowedOrigins.includes(origin) &&
    (req.socket?.encrypted === true || loopbackPeers.has(req.socket?.remoteAddress));
  // Never accept remote plaintext HTTP, including a forwarded loopback authority.
  return url.protocol === 'http:' && loopbackNames.has(url.hostname) &&
    loopbackPeers.has(req.socket?.remoteAddress) &&
    url.host === req.headers.host &&
    (allowedOrigins.length === 0 || allowedOrigins.includes(origin));
}

function body(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let bytes = 0;
    const finish = (error, value) => {
      clearTimeout(timer);
      req.off('data', data); req.off('end', end); req.off('aborted', abort); req.off('error', abort);
      chunks = [];
      error ? reject(error) : resolve(value);
    };
    const invalid = () => new BridgeError('invalid_request', 'Invalid or oversized request body.');
    const abort = () => finish(invalid());
    const data = chunk => {
      bytes += chunk.length;
      if (bytes > LIMIT) { finish(invalid()); return; }
      chunks.push(chunk);
    };
    const end = () => {
      let value;
      try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { finish(invalid()); return; }
      finish(null, value);
    };
    const timer = setTimeout(abort, 5000);
    req.on('data', data); req.on('end', end); req.on('aborted', abort); req.on('error', abort);
  });
}

function respond(res, status, value) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store', 'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    'Connection': 'close',
  });
  res.end(JSON.stringify(value));
}

export function createHandler({ bridge, requestRejection, allowedOrigins = [] }) {
  const origins = validateOrigins(allowedOrigins);
  return async (req, res) => {
    try {
      const rejection = requestRejection(req);
      if (rejection !== undefined) { respond(res, rejection, { error: { code: 'unauthorized', message: 'DSH browser authentication is required.' } }); return; }
      if (req.method !== 'POST' || req.headers['x-dsh-admin-bridge'] !== '1' || !originAllowed(req, origins)) {
        respond(res, 403, { error: { code: 'forbidden', message: 'A trusted same-origin browser request is required.' } }); return;
      }
      if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '') ||
          req.headers['content-encoding'] !== undefined ||
          (req.headers['content-length'] !== undefined &&
            (!/^\d+$/.test(req.headers['content-length']) || Number(req.headers['content-length']) > LIMIT)))
        fail('invalid_request', 'Invalid or oversized request body.');
      const endpoint = req.url?.slice(HTTP_PREFIX.length);
      if (!req.url?.startsWith(HTTP_PREFIX) || !['status', 'authenticate', 'lock'].includes(endpoint)) {
        respond(res, 404, { error: { code: 'not_found', message: 'Unknown administrator endpoint.' } }); return;
      }
      let payload = await body(req);
      exactKeys(payload, endpoint === 'authenticate' ? ['sessionId', 'requestId', 'password'] : ['sessionId']);
      if (!identifier(payload.sessionId)) fail('invalid_request', 'Invalid session identifier.');
      let value;
      if (endpoint === 'status') value = bridge.describe(payload.sessionId);
      else if (endpoint === 'lock') value = bridge.lock(payload.sessionId);
      else {
        const { sessionId, requestId } = payload;
        const disconnect = () => { if (!res.writableEnded) bridge.cancelRequest(sessionId, requestId); };
        res.on('close', disconnect);
        try {
          const pending = bridge.authenticate(sessionId, requestId, payload.password);
          payload.password = undefined;
          payload = undefined;
          value = await pending;
        } finally { res.off('close', disconnect); }
      }
      respond(res, 200, { value });
    } catch (error) {
      // Never rethrow into the Web server logger or stringify a raw PAM/parser exception.
      respond(res, 400, { error: publicError(error) });
    }
  };
}

export function attachHttp(ctx, bridge, { allowedOrigins = [] } = {}) {
  const handle = createHandler({ bridge, allowedOrigins,
    requestRejection: req => ctx.connection.requestRejection(req) });
  return ctx.webServer.register({ path: HTTP_PREFIX.slice(0, -1), kind: 'prefix', handler: handle });
}
