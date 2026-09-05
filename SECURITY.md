# Security policy and threat model

This is an **experimental privileged-execution plugin**, not a reviewed security boundary. Review its source and configuration before using it. Do not deploy on a shared or untrusted Harness host.

## Supported scope

Initial target: Linux, Python 3.10+, `/usr/bin/sudo`, `/usr/bin/python3`, Node.js 22+, DeepSeek Harness **0.1.2-rc.1**. A conventional sudo/PAM password prompt is supported; MFA, `requiretty`, hardware-token interaction and nonstandard authentication conversations are not supported. Authentication gets one password submission and a 45-second timeout.

The account must already be authorized by sudo to run the Python helper as root. This is suitable for a **trusted application operated by an account with full sudo authority**, not an account restricted to particular sudo commands. Do not add a sudoers rule that grants passwordless root Python or a user-writable helper to make this work. The plugin does not edit sudoers, install a privileged daemon, or elevate the Harness process itself.

## Trust boundary

The Harness host, this package and its configuration, other loaded plugins, the browser and extensions, authenticated DSH users, local same-user processes, the OS, PAM, sudo and Python must be trusted. The root helper is shipped in a user-owned package. A same-user process can modify it or the bridge, inspect process memory, or replace the UI. This design **does not confine an agent that already has arbitrary same-user shell/file access**. Restricted operation IDs reduce accidental and model-supplied command scope inside this API; they do not defeat a compromised host.

For a stronger boundary, use a separately installed root-owned helper with root-owned policy, authenticated IPC, an OS-controlled authentication surface, and a security review. That is not implemented in this release.

## Authorization

- No configured commands and no lease by default.
- The agent first asks DSH to approve the exact one-time action **create this bounded administrator lease**, including session, selected command argv and lifetime. An ordinary command approval is not reinterpreted as a persistent grant.
- Only `allowed-once` for that request permits opening the dedicated password dialog. Missing approval service, rejection, unavailable UI, cancellation or policy `never` fail closed.
- A fresh browser-only request ID binds the password submission to one pending lease. It is not a model tool argument or bearer token for executing commands.
- The lease is bound to one live DSH agent session, a frozen subset of configured operation IDs, and an absolute deadline (30–900 seconds; default maximum 300).
- Subagents and other sessions do not inherit the lease. The root helper accepts operation IDs, not arbitrary paths, arguments, working directories or shell strings.
- Policy is checked before requests, after authentication and before every execution. A 250 ms host sweep also revokes on policy change/expiry. The helper independently enforces its own monotonic deadline. No policy system can retroactively undo an operation that already started.
- No per-command password or extra approval within the explicit lease. This is the authorization the human granted, not a bypass of `never` policy.

## Credential handling

Passwords are accepted only through an uncontrolled password field in the client module. They are sent in the body of an authenticated same-origin POST to the Harness host, passed once through a private pipe to `sudo -S -k`, and discarded. They are never intentionally saved to files, settings, logs, chat, tool arguments, model messages, command-line arguments or environment variables. The helper does not receive or understand the password.

JavaScript strings, browser networking, Node internals and PAM may retain transient copies in memory. Clearing the input and zeroing the explicit Buffer **is not a guarantee of cryptographic memory erasure**. Core dumps, swap, browser extensions, debugging, compromised plugins or request-body logging can expose secrets. Do not enable request-body logging at the reverse proxy, application instrumentation, or TLS termination. The plugin cannot protect against those trusted components.

The plugin runs sudo with `-k` for the helper invocation rather than refreshing a global sudo timestamp. It does not periodically call `sudo -v`, retain the password, or enable passwordless sudo. An already configured `NOPASSWD` rule may allow the helper to start without a password; the unused input is discarded.

## HTTP authentication

Every route calls DSH's `connection.requestRejection` for its cookie authentication and Host/Origin fence. It also requires POST, an explicit exact Origin, a custom header, JSON content type, bounded request bodies and no content encoding. HTTPS origins must be explicitly configured and arrive over a TLS socket or a loopback connection from a trusted local HTTPS reverse proxy. Forwarded headers do not grant trust. HTTP is accepted only for exact loopback authorities on a loopback socket; arbitrary remote plaintext origins are never accepted.

No password is sent via the generic DSH tool or approval transport. Errors are caught and reduced to fixed safe messages before reaching the Harness server logger. Responses are `no-store`; there is no CORS allowance, query-string credential transport, or browser storage. Origin checks do not establish separate user identities: DSH is treated as a single trusted-user host.

## Commands and revocation

The helper uses exact argv with no shell, a fixed environment, `/` as the working directory, and closed command stdin. It rejects symlink executable paths and paths whose components are not root-owned and non-group/world-writable. These checks do not make a dangerous program safe: interpreters, package managers, editors, pagers, service managers, file-writing utilities and programs that load user-writable configuration may confer broad root authority. Audit each entire argv and all indirect inputs. Do not configure shells, Python, `env`, command launchers, or user-controlled scripts as operations. A fixed `systemctl restart` can run a service's configured code as root; that code must be trusted too.

One operation runs at a time, with a bounded timeout and combined output cap. Malformed protocol, unexpected fields, unknown/replayed request IDs, concurrent commands, EOF and expiration terminate the helper's authority. Root-side process-group cleanup sends termination then kill signals. A lost/unresponsive host remains bounded by the root helper's independent deadline.

**Lock is not rollback.** Filesystem effects remain. Commands that launch services, submit jobs, daemonize, or deliberately leave their process group may continue outside the supervised group. A reported interruption can have a partial or unknown outcome; inspect system state before retrying. Commands must not be designed to escape supervision.

Command output goes back to the agent and may be persisted in ordinary tool transcripts. Do not configure commands that print passwords, private keys, tokens or other sensitive material. Command argv and labels are public to the authenticated UI and approval log: never put secrets there.

## Reporting

Do not file passwords, tokens, sensitive command output or exploit details in a public issue. Use GitHub's private vulnerability reporting when available, or contact the repository owner privately to coordinate disclosure. No independent security audit or production-hardening claim is made.
