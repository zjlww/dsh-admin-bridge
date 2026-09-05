# Architecture

## Components

```text
human selects Sudo access in the existing four-mode composer selector
    -> scoped /permission sudo-access prepares intent (90s), no authority
    -> dedicated dialog: fixed allowlist + TTL + uncontrolled password
    -> authenticated POST /admin-bridge/v1/authenticate
    -> private pipe -> sudo -S -k (fresh password challenge required)
    -> isolated Python helper ready as root
    -> recheck exact session/generation and unchanged native mode
    -> journal previous knobs, commit Full access, publish active mode LAST
                         |
agent admin_run(id) -> active-mode/lease check -> private pipe {operationId}
    -> helper's frozen argv table -> supervised root subprocess
    -> bounded output -> ordinary agent tool result
                         |
exit / expiry / failure -> clear root first -> restore previous native mode
```

`src/index.js` owns one host service and synchronous per-agent scopes. `src/session.js` adds a supported agent-local shadow of the human `/permission` command, keeps the original handler for the native modes, adapts native permission setters, and registers only status/run/revoke tools. There is no agent unlock tool. `src/mode.js` owns the ephemeral capability, live identity, generation and native-mode transaction over a private `AdminBridge`. `src/bridge.js` retains the lower-level manifest, nonce, deadlines and worker lifecycle.

`src/http.js` is the dedicated browser-authenticated secret transport; there is no HTTP begin or run endpoint and no password through generic agent RPC. `src/sudo-worker.js` supervises fresh password-based sudo authentication and private pipes. `helper/runner.py` independently validates and enforces the fixed manifest. `client/index.js` replaces only the new `conversation.input.permission` single slot. `compat/permission-slot.mjs` explicitly rebuilds the rc.1 composer artifact to declare that slot with its untouched native selector as fallback. No new server or bash interception is used.

## Mode state and native permissions

Users see four choices, one authentication dialog and an active countdown. Internal pending/authenticating/unlocked fields remain protocol details, not user-facing toggles. A pending intent leaves native permissions unchanged; the raw worker being ready is still insufficient for `admin_run`. Only successful synchronous Full-access commit publishes `modeActive: true`.

The native preset table and Settings defaults stay unchanged. Sudo access is a capability overlay over `danger-full-access` plus ordinary approval policy `never`. This does not permit ordinary approval requests under `never`; the separate human mode authentication preauthorizes the fixed root operations. The existing Full access mode alone grants none of them.

Exit invalidates the generation and clears root authority before restoring captured native knobs. Scoped normal-mode commands exit first, then invoke the original handler, including same-value selections. External native changes revoke without overwriting the newer human choice. Re-entry ends the old lease and creates a fresh nonce/password attempt. Expiry, worker close, disposal and lost connections fail closed.

`src/journal.js` stores non-secret per-session rollback files: creation identity, previous preset/sandbox/approval, generation and pre/post-commit native event cutoffs. It fsyncs the intent before knob writes and the commit marker before publishing the mode, then removes the matching generation after restoration. Startup recovery restores only the same session and distinguishes later native choices from partial writes, including a journal ahead of DSH's buffered event log. Files are private `0600` in a `0700` directory; no password, authentication nonce or root grant is persisted. Forks never inherit root; their ordinary non-root presets retain DSH's normal inheritance semantics.

This deliberately avoids custom DSH session events: rc.1's persistence rejects unknown non-ignorable event types, its live append API cannot mark such events ignorable, and observers cannot reenter Session.append. The private file adapter therefore also allows immediate external-change revocation without recursively writing the native session log. Restoration failures keep the file and a safe warning, never root authority; ordinary native selections remain available for repair.

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
- Use native public permission/sandbox/approval APIs; the human mode flow does not call agent approval requests or change native preset/default tables.
- A dedicated named HTTP route applies `connection.requestRejection` and additional exact-origin/body restrictions. DSH's generic `/api` interceptor is not replaced.
- No DSH credential-storage service: its persistence contract is inappropriate for sudo passwords.
- No patch to bash, sandbox enforcement, core Web shell, sudoers, PAM, or native permission presets. A minimal, explicit rc.1 composer client artifact/type extension declares the permission slot; the renderer and native fallback stay intact.
- No new public listener or server. The plugin contributes a route and client module to the existing DSH host when installed.
- The plugin ships handwritten executable source with no install/build lifecycle. The rc.1 compatibility script explicitly rebuilds two upstream artifacts with guarded anchors, original backups and rollback; an existing-host restart/refresh or verified live rehash is still necessary.
