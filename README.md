# DSH Admin Bridge

**Sudo access: a fourth permission mode. Agents can request it; only fresh human password authentication grants temporary root access.**

A public, Linux-only plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness), targeting **DSH 0.1.2-rc.1**. Version `0.3.0-alpha.1` adds arbitrary root commands and agent-requested GUI authentication to the fourth-mode flow.

> **Experimental and dangerous.** By default, authentication authorizes **all root Bash commands**, not just configured operations. This is not a sandbox or an audited privilege boundary. Read [SECURITY.md](SECURITY.md). The user-owned helper requires an account already permitted to run it through sudo; never grant passwordless root Python to enable it.

## Four modes, one selector

The existing composer permission selector retains its three choices and icons:

1. **Read Only**
2. **Workspace Write**
3. **Full access**
4. **Sudo access** — a distinct shield-with-key icon

Selecting Sudo access opens a password dialog showing the command scope and duration. The agent can also call `admin_request({})` to open that dialog. **A request is not permission:** the previous mode remains in effect until the human completes fresh password authentication. Successful entry adds a temporary, session-scoped root capability over Full access. The selector shows **Sudo access · time remaining**.

Leaving the mode, expiry, disposal, or worker failure revokes the capability and restores the previous native mode. Selecting another native mode preserves that new choice. Human reselection of Sudo access requires **fresh authentication**, not lease renewal. `admin_request({})` is idempotent while active or pending: it does not replace a pending request, renew a lease, or reauthenticate an active one. Failed attempts are rate-limited and never retry a password automatically.

There is **no separate enable-approvals step** and no `admin_unlock` tool. The normal modes and DSH's ordinary approval policy are unchanged. Native Full access alone, a saved preference, restart, or fork never grants root access. Delegated subagents cannot request, enter, or inherit Sudo access.

## Scope and requirements

- Linux, Node.js 22+, Python 3.10+ at `/usr/bin/python3`, sudo at `/usr/bin/sudo`.
- DSH **0.1.2-rc.1**, Web profile, its native permission/command services, and the explicit compatibility extension below.
- A trusted single-user host/browser and ordinary **password-based** sudo/PAM. MFA, `requiretty`, and passwordless `NOPASSWD` authentication are unsupported for this mode.
- `allowAllCommands` defaults to **true**: arbitrary Bash commands run as root within the authenticated, immutable manifest scope. Set it to **false** for legacy configured-operation-only execution.
- No transparent bash interception, saved password, sudo timestamp keepalive, sudoers change, or persistent root daemon. Ordinary `bash` tools do not acquire this capability.
- Configured operations default to an empty list. This does **not** disable arbitrary root execution when `allowAllCommands: true`.

The root helper retains authorization, **not your password**. Passwords go only from the dedicated uncontrolled input through authenticated same-origin HTTP and a private sudo pipe—not chat, model tools, argv, environment, or durable storage. Agents must request the GUI dialog, never ask for a password in chat. Transient memory copies cannot be guaranteed erased.

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
    # DANGER: authentication allows arbitrary root Bash commands.
    # Set false to permit only the configured operations below.
    allowAllCommands: true
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

Audit the entire argv and its indirect inputs before adding any configured operation. Executable paths must be canonical, root-owned, non-symlink and non-group/world-writable. These checks are not confinement for arbitrary root Bash commands.

### Required rc.1 selector extension

This DSH prerelease hardcodes the composer selector. The plugin supplies a small, explicit, version-guarded compatibility rebuild that adds a **single replaceable permission-control slot with the untouched native selector as fallback**. It does not replace the renderer, native permission service, or their three presets.

From the installed plugin or reviewed checkout, replacing `/path/to/dsh/runtime` with the actual npm runtime directory:

```sh
node compat/permission-slot.mjs --check --runtime /path/to/dsh/runtime
node compat/permission-slot.mjs --apply --runtime /path/to/dsh/runtime
```

There are no install lifecycle scripts; this step is deliberate and backs up the original affected artifacts. See [compatibility details](compat/README.md). Restart the **existing** DSH Web process at a safe turn boundary, then refresh its existing URL. Never start a replacement server to update the current GUI. See [installation, migration and rollback](docs/INSTALL.md).

## Use

When root work is needed, the agent should call `admin_request({})`. Alternatively, select **Sudo access** in the composer. Review the displayed scope and enter the password **only in the GUI dialog**. After authentication, for example:

```js
admin_run({command: 'id -u', workdir: '/', timeoutSeconds: 5})
// Or the backwards-compatible configured operation:
admin_run({operationId: 'whoami-root'})
```

Both examples should report `0`. Commands already run in **root Bash**; no `sudo` prefix is needed.

| Tool | Purpose |
|---|---|
| `admin_status` | Read mode status, command scope and configured operations; no authentication nonce. |
| `admin_request` | With `{}`, request the GUI password dialog; no permission is granted by the call itself. Idempotent while pending or active. |
| `admin_run` | Run an arbitrary `command` if the active manifest allows it, or one configured `operationId`. |
| `admin_lock` | Leave Sudo access or cancel its pending dialog and restore the previous mode. |

`admin_run` accepts **exactly one** execution form:

- `command`: Bash string up to **16 KiB**, optional absolute `workdir` (default `/`), optional integer `timeoutSeconds` **1–120** (default **120**).
- `operationId`: the old configured-operation form, with no `command`, `workdir`, or `timeoutSeconds` overrides.

The native `/permission sudo-access` command can also prepare the password dialog. The rc.1 slash-command popup still lists the native presets; the **composer selector** is the four-mode control. Sudo access is intentionally not a default for future sessions.

**Revocation is not rollback:** filesystem and other command effects remain. Services, jobs and detached processes can outlive the lease. Arbitrary root commands can compromise the entire host, including this plugin; neither a timeout nor the manifest is a sandbox. Command text and output are model-visible and may persist in transcripts: never include or print secrets.

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

Unsupported: interactive password conversations inside commands, password vault/keyring storage, untrusted multi-user hosts, Windows/macOS, polkit, MFA, or an independently secured root-owned broker. An independent security audit and broader distribution/browser testing remain necessary.

## License

MIT — [LICENSE](LICENSE).
