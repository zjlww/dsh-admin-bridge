# Architecture

## Components

```text
agent admin_unlock(ids, duration)
    -> DSH approval.request(create this exact lease)
    -> pending session-bound request (90s)
                         |
DSH conversation header -> status polling (authenticated POST)
    -> native HTML dialog with uncontrolled password input
    -> authenticated POST /admin-bridge/v1/authenticate
    -> private stdin pipe -> sudo -S -k -> isolated Python helper
                         |
agent admin_run(id) -> policy check -> private pipe {operationId}
    -> helper's frozen argv table -> supervised root subprocess
    -> bounded output -> ordinary agent tool result
```

`src/index.js` contributes one host plugin and attaches tools to each live/new agent. `src/session.js` owns tool definitions and translates the native one-time approval into an explicit lease-creation action. `src/bridge.js` owns session registration and lease state. `src/http.js` owns a dedicated authenticated secret transport; it does not use the generic agent RPC or durable credential store. `src/sudo-worker.js` supervises sudo and the pipe protocol. `helper/runner.py` independently validates and enforces the fixed command manifest. `client/index.js` is a hand-written DSH module-loader contribution to the conversation header; no bundler or shell modification is necessary.

## States

- **unavailable**: session is not attached (or plugin/transport is unavailable).
- **disabled**: the session's approval policy is not positively `ask`.
- **locked**: no pending request or administrator lease.
- **pending**: native approval granted; one browser request ID awaits authentication.
- **authenticating**: the browser request ID is consumed; one sudo authentication attempt is in flight.
- **unlocked**: the exact selected operations can run until the independent helper deadline.

Any cancellation, deadline, policy revocation, session detach, plugin disposal or worker failure clears authority before cleaning up. An expired or failed authentication requires a new agent request and a new native approval. An unlocked lease cannot be extended or widened; lock it and request another.

## Helper protocol

Startup argument: canonical unpadded base64url encoding of a UTF-8 JSON manifest, maximum 32 KiB decoded:

```json
{
  "version": 1,
  "ttlSeconds": 60,
  "operations": [{
    "id": "whoami-root",
    "label": "Show effective user ID",
    "executable": "/usr/bin/id",
    "args": ["-u"],
    "timeoutSeconds": 5
  }]
}
```

The helper reports `{"type":"ready","uid":0}`. The broker accepts only UID 0. Python protocol tests intentionally run as the ordinary test user and assert their real UID, never elevate.

The parent sends only exact JSON lines:

```json
{"type":"run","id":"unique-request-id","operationId":"whoami-root"}
{"type":"lock"}
```

The helper returns one bounded result per completed operation:

```json
{"type":"result","id":"unique-request-id","exitCode":0,"stdout":"0\n","stderr":"","truncated":false,"timedOut":false}
```

Unknown fields, malformed input, unknown operation IDs, replayed request IDs or concurrent execution revoke authority instead of being interpreted permissively. EOF also revokes. The command stdin is `/dev/null`, so a command cannot read the parent's protocol or a password. The helper never receives a password; sudo consumes it before the helper starts. Startup diagnostics are deliberately generic and are not relayed to the model.

## Lifetime and supervision

The root deadline uses monotonic time and never renews. There is no `sudo -v` keepalive. Each command runs in a new process group, with a timeout no larger than 120 seconds and a combined stdout/stderr retention limit of 64 KiB. The helper actively drains excess output without retaining it. The parent allows up to 1 MiB per protocol frame to account for JSON escaping of bounded output.

Closing a pipe or pressing Lock now asks the helper to terminate its supervised group. Root-side cleanup is necessary because the unprivileged Node process cannot reliably kill root descendants. Already committed effects, separately started services, and deliberately escaped process groups cannot be undone or reliably stopped; see [SECURITY.md](../SECURITY.md).

## Compatibility decisions

- DSH **0.1.2-rc.1** is the initial pinned API target.
- Use the native public approval policy accessor and only the `allowed-once` outcome.
- A dedicated named HTTP route applies `connection.requestRejection` and additional exact-origin/body restrictions. DSH's generic `/api` interceptor is not replaced.
- No DSH credential-storage service: its persistence contract is inappropriate for sudo passwords.
- No patch to bash, sandbox, core Web shell, sudoers, PAM, or permission presets.
- No new public listener or server. The plugin contributes a route and client module to the existing DSH host when installed.
- No build or generated client artifact: Git installs work directly from checked-in source.
