# DSH Admin Bridge

**Sudo access: a fourth permission mode. Select it, authenticate once, and repeat configured administrator operations until the timer ends.**

A public, Linux-only plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness), targeting **DSH 0.1.2-rc.1**. Version `0.2.0-alpha.1` replaces the original separate Admin button and agent-requested unlock flow.

> **Experimental.** This is a trusted-application convenience feature, not an audited privilege boundary. Read [SECURITY.md](SECURITY.md). The user-owned helper requires an account already permitted to run it through sudo; never grant passwordless root Python to enable it.

## Four modes, one selector

The existing composer permission selector retains its three choices and icons:

1. **Read Only**
2. **Workspace Write**
3. **Full access**
4. **Sudo access** — a distinct shield-with-key icon

Selecting Sudo access opens one password dialog showing the fixed operation list and duration. Until authentication succeeds, the previous mode remains in effect. Successful entry adds a temporary, session-scoped root capability over Full access. The selector shows **Sudo access · time remaining**, not disabled/enabled/locked/unlocked toggles.

Leaving the mode, expiry, disposal, or worker failure revokes the capability and restores the previous native mode. Selecting another native mode preserves that new choice. Selecting Sudo access again requires a **fresh authentication**, not lease renewal. Failed attempts are rate-limited and never retry a password automatically.

There is **no separate enable-approvals step** and no agent `admin_unlock` tool. A human mode selection plus fresh password authentication authorizes the displayed operations. The normal modes and DSH's ordinary approval policy are unchanged. Native Full access alone, a saved preference, restart, or fork never grants root access. Delegated subagents cannot enter or inherit this mode.

## Scope and requirements

- Linux, Node.js 22+, Python 3.10+ at `/usr/bin/python3`, sudo at `/usr/bin/sudo`.
- DSH **0.1.2-rc.1**, Web profile, its native permission/command services, and the explicit compatibility extension below.
- A trusted single-user host/browser and ordinary **password-based** sudo/PAM. MFA, `requiretty`, and passwordless `NOPASSWD` authentication are unsupported for this mode.
- Exact operator-configured argv only. No arbitrary root shell, transparent bash interception, saved password, sudo timestamp keepalive, sudoers change, or persistent root daemon.
- No operations are configured by default. The example below only reports the effective UID.

The root helper retains authorization, **not your password**. Passwords go only from the dedicated uncontrolled input through authenticated same-origin HTTP and a private sudo pipe—not chat, model tools, argv, environment, or durable storage. Transient memory copies cannot be guaranteed erased.

## Install from GitHub

This package is not published to npm. Install a reviewed commit through DSH's manager:

```sh
dsh plugin --profile web add 'github:zjlww/dsh-admin-bridge#<reviewed-commit>' --ignore-scripts
```

Merge this row into the selected Web profile's `cordis.patch.yml`; do not overwrite other entries:

```yaml
- id: admin-bridge
  config:
    maxTtlSeconds: 60
    operations:
      - id: whoami-root
        label: Show effective user ID
        executable: /usr/bin/id
        args: ['-u']
        timeoutSeconds: 5
```

For a trusted HTTPS reverse proxy on the same host, add the exact browser origin under that same config:

```yaml
    allowedOrigins:
      - https://harness.example.com
```

Audit the entire argv and its indirect inputs before adding any meaningful operation. Executable paths must be canonical, root-owned, non-symlink and non-group/world-writable.

### Required rc.1 selector extension

This DSH prerelease hardcodes the composer selector. The plugin supplies a small, explicit, version-guarded compatibility rebuild that adds a **single replaceable permission-control slot with the untouched native selector as fallback**. It does not replace the renderer, native permission service, or their three presets.

From the installed plugin or reviewed checkout, replacing `/path/to/dsh/runtime` with the actual npm runtime directory:

```sh
node compat/permission-slot.mjs --check --runtime /path/to/dsh/runtime
node compat/permission-slot.mjs --apply --runtime /path/to/dsh/runtime
```

There are no install lifecycle scripts; this step is deliberate and backs up the original affected artifacts. See [compatibility details](compat/README.md). Restart the **existing** DSH Web process at a safe turn boundary, then refresh its existing URL. Never start a replacement server to update the current GUI. See [installation, migration and rollback](docs/INSTALL.md).

## Use

Select **Sudo access** in the composer, review the displayed scope, and enter the password only in its dialog. Then ask the agent to run `whoami-root` twice: both results should be `0`, with one authentication.

| Tool | Purpose |
|---|---|
| `admin_status` | Read mode status and the configured operation catalog; no authentication nonce. |
| `admin_run` | Run one fixed operation ID already authorized by this session's active mode. |
| `admin_lock` | Leave Sudo access or cancel its pending dialog and restore the previous mode. |

The native `/permission sudo-access` command can also prepare the password dialog. The rc.1 slash-command popup still lists the native presets; the **composer selector** is the four-mode control. Sudo access is intentionally not a default for future sessions.

**Revocation is not rollback:** completed command effects remain. Commands that launch services or escape supervision can outlive a lease. Never configure commands that print secrets; output is model-visible.

## Development and status

```sh
npm ci --ignore-scripts
npm test
npm run check
npm pack --dry-run --ignore-scripts
```

Automated tests use synthetic credentials, fake sudo processes and unprivileged Python helpers. They never request a real password or execute sudo. A real smoke test requires the human-operated flow documented in [INSTALL.md](docs/INSTALL.md).

- [Architecture and protocol](docs/ARCHITECTURE.md)
- [Security assumptions and reporting](SECURITY.md)
- [Verification and development side effects](docs/VERIFICATION.md)

Unsupported: arbitrary root shells, password vault/keyring storage, untrusted multi-user hosts, Windows/macOS, polkit, MFA, or an independently secured root-owned broker. An independent security audit and broader distribution/browser testing remain necessary.

## License

MIT — [LICENSE](LICENSE).
