# Installation, migration, smoke test and rollback

## Before installing

1. Read [SECURITY.md](../SECURITY.md). Use a trusted single-user host and an account already allowed to run the user-owned Python helper through sudo. This is not a separately secured root service.
2. Verify **DSH 0.1.2-rc.1**, its native permission/command services and browser-cookie authentication. Other versions require separate review.
3. Verify Node.js 22+, Python 3.10+ at `/usr/bin/python3`, and `/usr/bin/sudo`. Ordinary password-based sudo/PAM is required. `NOPASSWD`, MFA and `requiretty` are unsupported for Sudo mode.
4. Privately back up the selected profile's manifest, lockfile and `cordis.patch.yml`. Do not copy credentials, browser cookies or the whole DSH home into a public repository.
5. Select a full reviewed Git commit. There is no npm registry release.

## Install and configure

```sh
dsh plugin --profile web add 'github:zjlww/dsh-admin-bridge#<reviewed-commit>' --ignore-scripts
```

The official manager changes the selected profile, not the core runtime. Merge the following into its existing patch list:

```yaml
- id: admin-bridge
  config:
    maxTtlSeconds: 60
    allowedOrigins: []
    operations:
      - id: whoami-root
        label: Show effective user ID
        executable: /usr/bin/id
        args: ['-u']
        timeoutSeconds: 5
```

A DSH patch replaces the row's **whole config**, so include all intended keys together. A private, non-secret rollback directory defaults to `$DSH_HOME/state/admin-bridge` (or `~/.dsh/state/admin-bridge`); `stateDirectory` can specify another absolute canonical path. It must be owned by the Harness user with mode `0700`, without symlink ancestors; its files are `0600`. No password, authentication nonce or root authorization is stored there. Empty operations leave the fourth mode unavailable for authentication. The maximum lease is 30–900 seconds (default 300), at most 16 fixed operations, with unique 1–64-character ASCII IDs and per-operation timeouts of 1–120 seconds. Mode entry authorizes the displayed **whole configured allowlist**, not model-selected replacements.

`allowedOrigins: []` accepts only exact same-origin loopback HTTP over a loopback connection. For a trusted HTTPS reverse proxy on the same host, explicitly configure the full browser origin:

```yaml
    allowedOrigins:
      - https://harness.example.com
      - http://127.0.0.1:3080
```

Ports matter. No trailing slash, wildcard, path, userinfo or remote HTTP origin is accepted. An allowlisted HTTPS Origin over a remote plaintext backend is rejected. DSH's independent Host/Origin and browser-cookie checks still apply. Do not expose the backend publicly or log request bodies.

Audit each full argv and indirect input. Do not configure arbitrary shells, interpreters, package managers, editors, pagers or user-controlled scripts. Executable paths and all components must be root-owned, non-group/world-writable and non-symlink; on merged-usr hosts use `/usr/bin/id`, not `/bin/id`.

## Extend the existing rc.1 selector

This prerelease has a hardcoded composer selector. From the reviewed checkout or installed plugin directory, explicitly apply the guarded compatibility rebuild:

```sh
node compat/permission-slot.mjs --check --runtime /path/to/dsh/runtime
node compat/permission-slot.mjs --apply --runtime /path/to/dsh/runtime
```

The runtime path is the npm installation containing `node_modules/@deepseek-ai/dsh-client-ui-conversation`, **not** the Web profile. The script version-checks and preflights its exact anchors, backs up originals, and updates the composer client artifact plus its slot type contract. It adds `conversation.input.permission` with the native selector as fallback. It does not change the native three presets, global command registry, default settings, renderer, or bash implementation. See [compatibility details](../compat/README.md).

Restart the **existing Web process** at a safe turn boundary and refresh its existing URL. No replacement server should be started. Handwritten plugin source has no install/build lifecycle, but the core compatibility rebuild and browser refresh are still required. Live patch watchers do not make Node's already-imported server modules fresh after an in-place package upgrade; a normal restart is the safe generic procedure. Newly rebuilt client bytes also need to reach DSH's client-module revision graph before refresh can serve them.

The existing composer selector must show:

1. Read Only — unchanged native icon
2. Workspace Write — unchanged native icon
3. Full access — unchanged native icon and confirmation
4. Sudo access — shield-with-key icon

The old standalone Admin header action is removed. The native `/permission` popup and Settings defaults still list only ordinary presets in rc.1; Sudo access cannot be saved as an automatically activated default. A direct human `/permission sudo-access` command can prepare the same dedicated authentication dialog.

## Migrate from 0.1.x

- End every existing lease before updating. Upgrading/unloading also revokes its workers.
- Retain reviewed operation/origin/TTL configuration; do not add root commands merely for migration.
- Upgrade the pinned source, apply the explicit selector compatibility rebuild, then restart/refresh as above.
- The model tool `admin_unlock` is removed. Do not ask an agent to enable approval prompts. The human selects Sudo access and authenticates; ordinary Full access still has approval policy `never`.
- For an earlier live installation with a disabled original bundle row plus a distinct live row, retain exactly one active host instance and one client module. Rollback must account for both rows. Do not append a duplicate bundle ID.

## Human-operated smoke test

These steps are **not** performed by automated tests:

1. Verify the fourth option and icon in the existing composer. Record the current ordinary mode.
2. Select Sudo access and cancel its password dialog. The original mode must remain, and `admin_run` must reject execution.
3. Select it again. Review the exact `/usr/bin/id -u` operation and duration. Enter the sudo password **only in this dialog**; never paste it into chat/tools or capture the request body.
4. After success the selector must show Sudo access with a countdown. Ask the agent to run `admin_run({operationId:'whoami-root'})` twice: both results should be UID `0`, with one authentication.
5. Select the previous ordinary mode, or ask for `admin_lock`. Root execution must then fail. Selecting Full access while it already underlies Sudo must still revoke the lease.
6. Every subsequent Sudo selection must require a fresh password. A wrong password must not change native mode or be retried automatically; wait for the short failure cooldown before another attempt.
7. With a short lease, verify expiry restores the prior mode and rejects execution. Other sessions and delegated agents must not inherit the lease.
8. Confirm no password appears in agent output. No password-input screenshot, browser storage, network export or secret-bearing log is needed for verification.

Errors use fixed safe messages. Failure may mean wrong password, sudo policy denial, unsupported PAM, cancellation or deadline. An explicit password-required error means sudo did not challenge for a password; the mode refuses to pretend the input was verified. If restoration fails, root stays revoked, a safe warning is shown, and the journal remains for recovery; select a safe native mode and investigate rather than retrying privileged work.

## Rollback

1. Leave Sudo access or call `admin_lock`. Inspect any partial effects or separately started services yourself.
2. Remove the plugin's profile override(s), preserving unrelated rows. A live disable-and-insert deployment must remove both rows.
3. Remove the plugin through the official manager:

   ```sh
   dsh plugin --profile web remove dsh-admin-bridge --ignore-scripts
   ```

4. Optionally revert the compatibility extension from a retained reviewed checkout:

   ```sh
   node compat/permission-slot.mjs --revert --runtime /path/to/dsh/runtime
   ```

   The extension is harmless without the plugin: it falls back to the untouched native selector. Never revert over unrelated later core edits; the script refuses mismatched targets.
5. Restart the same Web process at a safe boundary and refresh. Verify three native modes, no plugin tools, and no active `/admin-bridge/v1/` API. A removed route may return the Web shell rather than a literal 404.
6. Restore private profile backups only if needed and without undoing unrelated newer changes.

No passwords, sudoers rules, root service or durable lease authority are created. Only private non-secret native-permission rollback files can persist; inspect and restore any outstanding record before removing its directory. No custom mode events are appended to DSH's session log. Uninstalling cannot undo commands previously executed under an authorized lease.
