# Security policy and threat model

This is an **experimental privileged-execution plugin**, not a reviewed security boundary. Review its source and configuration before using it. Do not deploy on a shared or untrusted Harness host.

## Supported scope

Initial target: Linux, Python 3.10+, `/usr/bin/sudo`, `/usr/bin/python3`, Node.js 22+, DeepSeek Harness **0.1.2-rc.1**. A conventional sudo/PAM password prompt is supported; MFA, `requiretty`, hardware-token interaction and nonstandard authentication conversations are not supported. Authentication gets one password submission and a 45-second timeout.

The account must already be authorized by sudo to run the Python helper as root. This is suitable for a **trusted application operated by an account with full sudo authority**, not an account restricted to particular sudo commands. Do not add a sudoers rule that grants passwordless root Python or a user-writable helper to make this work. The plugin does not edit sudoers, install a privileged daemon, or elevate the Harness process itself.

## Trust boundary

The Harness host, this package and its configuration, other loaded plugins, the browser and extensions, authenticated DSH users, local same-user processes, the OS, PAM, sudo and Python must be trusted. The root helper is shipped in a user-owned package. A same-user process can modify it or the bridge, inspect process memory, or replace the UI. This design **does not confine an agent that already has arbitrary same-user shell/file access**. In `0.3.0-alpha.1`, `allowAllCommands` defaults to **true**: authenticating grants arbitrary root Bash execution, including the ability to change the host, helper or policy. This is **not a sandbox**. Setting `allowAllCommands: false` restricts this API to configured operation IDs and reduces accidental and model-supplied command scope; it does not defeat a compromised host.

For a stronger boundary, use a separately installed root-owned helper with root-owned policy, authenticated IPC, an OS-controlled authentication surface, and a security review. That is not implemented in this release.

## Authorization

- No active mode or lease exists by default. Sudo access is never a saved session default. However, `allowAllCommands` defaults to **true**, even with an empty operation list: after authentication arbitrary root commands are authorized. Set it explicitly to **false** for legacy configured-operation-only scope.
- The human selects **Sudo access**, uses `/permission sudo-access`, or the agent calls `admin_request({})` to prepare the GUI password dialog. Preparing a request does not grant root or change native permission knobs. Agents should actively request this dialog when root work is needed, never request a password in chat or tools.
- The dedicated dialog displays whether arbitrary root commands are allowed, the whole configured operation list, duration and Full-access filesystem implications. Only fresh human password authentication through the protected browser route can commit Full access plus the ephemeral root capability. Cancellation or failure leaves the previous mode unchanged.
- `admin_request({})` is idempotent while active or pending: it neither renews the lease nor replaces the pending authentication. There is no `admin_unlock` tool. A tool call, preset value, logged intent or ordinary approval outcome alone never grants the capability.
- A fresh browser-only request ID binds the password to one pending generation. It is absent from model-facing tool status and is not a command-execution bearer token.
- The lease is bound to one exact live agent, an immutable manifest including `allowAllCommands` and configured operations, and an absolute deadline (30–900 seconds; default maximum 300). Arbitrary commands are accepted only when that authenticated manifest permits them; a request cannot widen its scope. Operation-ID execution still uses exact configured argv with no replacements.
- Delegated subagents cannot request or enter the mode. Other sessions, forks and resumed sessions never inherit its authorization.
- The wrapper checks live identity, current native knobs and generation before password delivery, after authentication and before every execution. The host also sweeps every 250 ms; the helper independently enforces its monotonic deadline. Root authority is published only after the synchronous native permission commit succeeds.
- Native Full access keeps its ordinary `never` approval policy. The human's explicit Sudo-mode authentication authorizes the displayed manifest scope (arbitrary root commands by default, or configured operations only); it does not make ordinary approval requests succeed under `never`. Merely being in Full access never creates a mode intent or grants root.
- Exit, expiry, worker failure and disposal clear root before restoring native permissions. A newer external human mode selection is preserved rather than overwritten. Re-entry closes the previous helper and requires fresh authentication; failed/cancelled attempts remain rate-limited.
- A private non-secret rollback file records the exact session creation identity, previous native knobs and event cutoffs before changing native permissions; it is durably committed before publishing the mode. Restart recovery uses it only to undo that session's interrupted transition, never as authority. Later native choices are preserved. If restoration fails, root stays revoked and the rollback file remains for recovery.
- Journal files are user-owned `0600` inside a dedicated `0700` directory, normally `$DSH_HOME/state/admin-bridge` (or `~/.dsh/state/admin-bridge`). `stateDirectory` can explicitly select another absolute non-symlink private directory. They never contain passwords, authentication nonces, operation results or a restorable lease. Forks have distinct identities: root is never inherited, while native non-root permissions follow DSH's ordinary fork rules.

## Credential handling

Passwords are accepted only through an uncontrolled password field in the client module. They are sent in the body of an authenticated same-origin POST to the Harness host, passed once through a private pipe to `sudo -S -k`, and discarded. They are never intentionally saved to files, settings, logs, chat, tool arguments, model messages, command-line arguments or environment variables. The helper does not receive or understand the password.

JavaScript strings, browser networking, Node internals and PAM may retain transient copies in memory. Clearing the input and zeroing the explicit Buffer **is not a guarantee of cryptographic memory erasure**. Core dumps, swap, browser extensions, debugging, compromised plugins or request-body logging can expose secrets. Do not enable request-body logging at the reverse proxy, application instrumentation, or TLS termination. The plugin cannot protect against those trusted components.

The plugin runs sudo with `-k` for every helper invocation rather than refreshing a global timestamp. It does not call `sudo -v`, retain the password, or enable passwordless sudo. **Sudo mode rejects a ready helper unless sudo actually requested the password.** A `NOPASSWD` rule cannot make an arbitrary input look authenticated; such configurations are unsupported for this mode and the helper is closed without running configured operations.

## HTTP authentication

Every route calls DSH's `connection.requestRejection` for its cookie authentication and Host/Origin fence. It also requires POST, an explicit exact Origin, a custom header, JSON content type, bounded request bodies and no content encoding. HTTPS origins must be explicitly configured and arrive over a TLS socket or a loopback connection from a trusted local HTTPS reverse proxy. Forwarded headers do not grant trust. HTTP is accepted only for exact loopback authorities on a loopback socket; arbitrary remote plaintext origins are never accepted.

No password is sent via the generic DSH tool or approval transport. Errors are caught and reduced to fixed safe messages before reaching the Harness server logger. Responses are `no-store`; there is no CORS allowance, query-string credential transport, or browser storage. Origin checks do not establish separate user identities: DSH is treated as a single trusted-user host. In the targeted DSH prerelease, the native browser cookie is HttpOnly and SameSite=Strict but is not marked Secure; the plugin does not repair that upstream behavior. Restrict network exposure to the intended HTTPS entry point and do not make the authenticated hostname available over untrusted plaintext HTTP.

## Commands and revocation

`admin_run` accepts exactly one of these forms:

- `command`: a Bash string up to **16 KiB**, optional absolute `workdir` (default `/`), and optional integer `timeoutSeconds` from **1 to 120** (default **120**). This runs in **root Bash**, without a `sudo` prefix, and requires `allowAllCommands: true` in the authenticated manifest. It is not limited to the configured operation list.
- `operationId`: one exact configured argv, with no shell and no `command`, `workdir`, or `timeoutSeconds` overrides. This legacy form uses its configured timeout and `/` as working directory.

Both use a fixed environment and closed command stdin, not an interactive terminal. A command's working directory is not a filesystem boundary. Arbitrary root Bash can read or overwrite host files, install persistence, start detached processes, and alter its own supervision; manifest scope and lease limits are **not confinement**.

For configured operations, the helper rejects symlink executable paths and paths whose components are not root-owned and non-group/world-writable. These checks do not make a dangerous program safe: interpreters, package managers, editors, pagers, service managers, file-writing utilities and programs that load user-writable configuration may confer broad root authority. If using `allowAllCommands: false` to reduce scope, audit each entire argv and all indirect inputs; do not configure shells, Python, `env`, command launchers, or user-controlled scripts as operations. A fixed `systemctl restart` can run a service's configured code as root; that code must be trusted too.

One operation runs at a time, with a bounded timeout and combined output cap. Malformed protocol, unexpected fields, unknown/replayed request IDs, concurrent commands, EOF and expiration terminate the helper's authority. Root-side process-group cleanup sends termination then kill signals. A lost/unresponsive host remains bounded by the root helper's independent deadline.

**Lock is not rollback.** Filesystem effects remain. Commands that launch services, submit jobs, daemonize, or deliberately leave their process group may continue outside the supervised group. A reported interruption can have a partial or unknown outcome; inspect system state before retrying. Commands must not be designed to escape supervision.

Command text and output go through model-visible tools and may persist in ordinary transcripts. Never put passwords, private keys, tokens or other sensitive material in commands, and do not run commands that print them. Configured argv and labels are also public to the authenticated UI and agent status. A password belongs only in the dedicated GUI field, never in `admin_request`, `admin_run`, chat, or a shell command.

## Reporting

Do not file passwords, tokens, sensitive command output or exploit details in a public issue. [Report a vulnerability privately through GitHub](https://github.com/zjlww/dsh-admin-bridge/security/advisories/new); private vulnerability reporting is enabled for this repository. No independent security audit or production-hardening claim is made.
