# DSH Admin Bridge

**Authenticate once. Run a selected set of administrator commands for a short time. Never save the sudo password.**

A public, Linux-only plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness), initially targeting **DSH 0.1.2-rc.1**.

> **Experimental.** This is a trusted-application convenience feature, not a sandbox or an independently audited privilege boundary. Read [SECURITY.md](SECURITY.md) before installing. An account already permitted to run the helper through sudo is required. Do not grant passwordless root Python to enable it.

## What it does

1. The agent requests a session-bound lease for specific configured operation IDs and a duration.
2. DSH asks you to approve creation of that exact lease.
3. **Admin** in the conversation header opens a password dialog.
4. You enter your sudo password there—not in chat. The plugin sends it once to sudo over a private pipe and discards it.
5. The agent can repeat the selected operations without another password during the lease.
6. **Lock now**, expiration, session disposal, or disabled approvals revoke access.

The root helper retains authorization, not your password. There is no sudo timestamp keepalive, sudoers modification, persistent root daemon, unrestricted `sudo` tool, or change to the built-in bash tool. No operations are configured by default.

## Requirements

- Linux; Node.js 22+; Python 3.10+ at `/usr/bin/python3`; sudo at `/usr/bin/sudo`.
- DSH **0.1.2-rc.1**, Web profile, and a session with approval prompts enabled.
- A trusted single-user Harness host and trusted browser/plugins. Ordinary password-based sudo/PAM authentication; interactive MFA and `requiretty` are unsupported.
- Local loopback HTTP, or an explicitly allowlisted HTTPS origin with a local HTTPS reverse proxy. Remote plaintext HTTP is rejected.

**This does not bypass disabled approval prompts.** If your session policy is `never`, it cannot unlock or use an administrator lease.

## Install from GitHub

This package is not published to npm. Install a reviewed Git commit through DSH's plugin manager, not a similarly named registry package:

```sh
# Replace <reviewed-commit> with the full commit SHA you reviewed.
dsh plugin --profile web add 'github:zjlww/dsh-admin-bridge#<reviewed-commit>'
```

There is no build step or install script: server code, Python helper and the hand-written browser module are checked-in source. DSH reconciles `dsh.bundle.patch` into its profile.

Then configure the allowlist in the Web profile's `cordis.patch.yml` (normally `~/.dsh/profiles/web/cordis.patch.yml`). **Merge** this row into the existing YAML list; do not overwrite your other configuration:

```yaml
- id: admin-bridge
  config:
    maxTtlSeconds: 300
    operations:
      - id: whoami-root
        label: Show effective user ID
        executable: /usr/bin/id
        args: ['-u']
        timeoutSeconds: 5
```

The example only prints the effective UID; it does not change system state. Audit the entire command and all indirect inputs before configuring more powerful operations. Executables and all path components must be root-owned, non-group/world-writable and non-symlinks; use canonical paths such as `/usr/bin/id`, not `/bin/id` on merged-usr systems. Arguments are fixed; the model cannot supply replacements.

For an HTTPS reverse proxy running on the same machine, also set the exact browser origin (no trailing slash):

```yaml
    allowedOrigins:
      - https://harness.example.com
```

Keep DSH's own trusted-host/browser authentication configured too. Do not enable request-body logging at your proxy or application instrumentation.

Restart **your existing DSH Web process** through your normal service manager, then refresh the existing browser page. Installing this repository alone does not update a running GUI. See [installation and rollback](docs/INSTALL.md) for checks and limitations.

## Use

Ask the agent:

> Request a 60-second administrator lease for `whoami-root`, then run it twice.

Approve the native DSH lease request, then authenticate in the Admin dialog. The successful demonstration returns `0` twice. Never paste the password into a user message or a tool argument.

| Agent tool | Purpose |
|---|---|
| `admin_status` | List configured operations and this session's public lease status. |
| `admin_unlock` | Request native approval, then wait for GUI authentication. |
| `admin_run` | Execute one operation ID already included in the active lease. |
| `admin_lock` | Cancel a pending request or revoke the lease. |

The browser-only request identifier is not returned through the model-facing tools. Other sessions and subagents need their own approval and authentication. A new request is required after authentication failure; the same password is never automatically retried.

**Lock is not rollback:** completed changes remain. Services, daemonized jobs and descendants that escape the supervised process group may outlive the lease. Command output is ordinary model-visible tool output—never configure commands that print secrets.

## Development

```sh
npm ci --ignore-scripts
npm test
npm run check
npm pack --dry-run --ignore-scripts
```

Tests use fake sudo processes and unprivileged helper subprocesses. They must never request a real password or run sudo. Real PAM/sudo authentication requires an explicit operator smoke test in a trusted installation; automated tests are not evidence of successful privileged execution.

## Architecture and status

- [Architecture and protocol](docs/ARCHITECTURE.md)
- [Installation, smoke test and rollback](docs/INSTALL.md)
- [Security assumptions and reporting](SECURITY.md)
- [Verification and development side effects](docs/VERIFICATION.md)

Implemented: scoped lease state machine, private authentication transport, DSH tool/approval integration, conversation-header dialog, bounded Python helper, and automated tests. Not implemented: arbitrary root shells, password vault/keyring storage, remote untrusted users, Windows/macOS, polkit, a root-owned system service, transparent bash interception, MFA, or an independently audited security boundary.

Next steps: operator-run real sudo/PAM smoke tests, independent security review, and a separately installed root-owned broker if stronger isolation is needed.

## License

MIT — [LICENSE](LICENSE).
