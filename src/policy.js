// Policy data is operator-controlled, never model-supplied shell syntax.
export class BridgeError extends Error {
  constructor(code, message) { super(message); this.name = 'BridgeError'; this.code = code; }
}
export const fail = (code, message) => { throw new BridgeError(code, message); };
export const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function exactKeys(value, required, optional = []) {
  if (!isObject(value) || required.some(key => !Object.hasOwn(value, key)) ||
      Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) {
    fail('invalid_request', 'Invalid request shape.');
  }
}
export function integer(value, min, max) { return Number.isSafeInteger(value) && value >= min && value <= max; }
export function identifier(value) { return typeof value === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(value); }
export function validateOperations(value) {
  if (!Array.isArray(value) || value.length > 16) fail('invalid_config', 'Configure at most 16 operations.');
  const seen = new Set();
  return Object.freeze(value.map(op => {
    exactKeys(op, ['id', 'label', 'executable', 'args', 'timeoutSeconds']);
    if (!identifier(op.id) || seen.has(op.id) || typeof op.label !== 'string' ||
        op.label.length < 1 || op.label.length > 120 || /[\x00-\x1f\x7f]/.test(op.label) ||
        typeof op.executable !== 'string' || !op.executable.startsWith('/') ||
        op.executable.length > 1024 || /[\x00-\x20\x7f]/.test(op.executable) ||
        !Array.isArray(op.args) || op.args.length > 32 ||
        op.args.some(arg => typeof arg !== 'string' || arg.length > 1024 || /[\x00-\x1f\x7f]/.test(arg)) ||
        !integer(op.timeoutSeconds, 1, 120)) fail('invalid_config', 'Invalid operation definition.');
    seen.add(op.id);
    return Object.freeze({ ...op, args: Object.freeze([...op.args]) });
  }));
}
export function selectManifest(operations, operationIds, ttlSeconds, maxTtlSeconds = 300) {
  if (!integer(maxTtlSeconds, 30, 900) || !integer(ttlSeconds, 30, maxTtlSeconds))
    fail('invalid_request', 'Requested lifetime is outside the configured bounds.');
  if (!Array.isArray(operationIds) || operationIds.length < 1 || operationIds.length > 16 ||
      operationIds.some(id => !identifier(id)) || new Set(operationIds).size !== operationIds.length)
    fail('invalid_request', 'Choose one or more distinct configured operation IDs.');
  const selected = operationIds.map(id => operations.find(op => op.id === id));
  if (selected.some(op => !op)) fail('invalid_request', 'Unknown configured operation.');
  return Object.freeze({ version: 1, ttlSeconds, operations: Object.freeze(selected) });
}
export function publicError(error) {
  return error instanceof BridgeError
    ? { code: error.code, message: error.message }
    : { code: 'internal', message: 'Administrator bridge failed; access was not granted.' };
}
