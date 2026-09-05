# Installation, operator smoke test and rollback

## Before installing

1. Read [SECURITY.md](../SECURITY.md). Use a trusted, single-user Harness installation. The helper is user-owned code launched with full sudo authority, not a separately secured system service.
2. Verify DSH is **0.1.2-rc.1**, with working browser-cookie authentication. The plugin intentionally requires this API version; do not assume older or later prereleases are compatible.
3. Verify the host has Node.js 22+, Python 3.10+ at `/usr/bin/python3`, and sudo at `/usr/bin/sudo`. This plugin has no interactive installer and does not change PAM or sudoers.
4. Back up your own profile's `package.json`, lockfile and `cordis.patch.yml` using your normal private configuration-backup procedure. Do not copy credentials, browser cookies or the entire DSH home into this public repository.
5. Select and review a full commit SHA from this repository. No npm registry release currently exists.

## Install and configure

```sh
dsh plugin --profile web add 'github:zjlww/dsh-admin-bridge#<reviewed-commit>'
```

This modifies the selected profile, not the DSH runtime installation. The package metadata declares a bundle patch inserting `id: admin-bridge`. Its host route and browser module are part of the existing Web server; no second server should be started to update the current GUI.

Merge the following into the profile's existing patch list:

```yaml
- id: admin-bridge
  config:
    maxTtlSeconds: 300
    allowedOrigins: []
    operations:
      - id: whoami-root
        label: Show effective user ID
        executable: /usr/bin/id
        args: ['-u']
        timeoutSeconds: 5
```

A DSH patch replaces the row's **whole config**, so include all intended keys in the same row. An empty operation list is valid and leaves the plugin inert. `maxTtlSeconds` must be 30–900. There are at most 16 operations; IDs are unique 1–64-character ASCII letters, digits, `_` or `-`. Each exact command has a 1–120-second timeout.

`allowedOrigins: []` accepts an exact same-origin loopback HTTP browser, such as `http://127.0.0.1:3080`, on a loopback connection. To use HTTPS through a trusted reverse proxy on the **same host**, set the canonical full origin:

```yaml
    allowedOrigins:
      - https://harness.example.com
      - http://127.0.0.1:3080
```

The HTTPS port is significant; include it when non-default. No trailing slash, wildcard, URL path, userinfo or remote HTTP origin is accepted. Requests to a non-loopback plaintext backend are rejected even with an allowlisted HTTPS Origin. This prevents treating untrusted forwarding headers as proof of TLS. DSH's independent Host/Origin and browser-cookie checks still apply. Do not expose the backend publicly or log request bodies at any proxy.

Do not configure an arbitrary shell, interpreter, package manager, editor, pager or user-controlled script as an operation. A fixed executable path is not sufficient to constrain a program with broad capabilities. All executable path components must be root-owned, non-group/world-writable and not symlinks. For example, `/bin/id` is rejected on a merged-usr distribution; use the canonical `/usr/bin/id` path after verifying its ownership.

Restart the **existing DSH Web process** through your normal service manager and refresh the existing GUI. This repository has no build step. If the profile is configured for live patch reload, do not assume the browser roster has updated without verifying after a refresh.

## Safe operator smoke test

These steps require a human and are intentionally **not** performed by CI or development tests:

1. Start a fresh DSH conversation with approval prompts enabled. The conversation header should show **Admin: locked**. Open it and verify the exact `/usr/bin/id`, `['-u']` configuration.
2. Ask the agent to call `admin_unlock` for `whoami-root` for 60 seconds.
3. Check the native DSH approval describes the session, duration and exact argv. Reject it first: no password request or root helper should start.
4. Ask again and approve **creation of the lease**. The Admin password dialog should open. Enter the sudo password **only there**, never into chat.
5. Ask the agent to call `admin_run` with `whoami-root` twice. Each result should be `0`, with only one password entry.
6. Press **Lock now**. Another `admin_run` must fail. This does not undo already completed operations.
7. Repeat with a short lease and wait for expiry; then verify execution fails. In another session, the first session's authorization must not work.
8. Disable session approvals and verify new and existing leases fail closed. A policy change is also swept by the host every 250 ms; it cannot undo an operation already started.
9. Confirm no password appears in chat/tool output. Do not export or log secret request bodies to verify this.

Authentication failures intentionally return generic messages. This can mean a wrong password, sudo policy denial, unsupported PAM conversation, deadline, cancellation or worker failure. There is no automatic password retry; request a new lease. A worker interruption may leave partial effects for nontrivial commands—inspect system state before retrying.

## Rollback

1. Press **Lock now** in each session with a lease, or call `admin_lock`. Wait for any supervised command to finish or terminate. Inspect any separately started services/jobs yourself.
2. Remove the `id: admin-bridge` configuration override from your profile patch. Keep other rows intact.
3. Remove the package using your profile manager:

   ```sh
   dsh plugin --profile web remove dsh-admin-bridge
   ```

4. Restart the same Web process and refresh the same browser page. Verify the Admin action, tools and `/admin-bridge/v1/` route are no longer contributed. Depending on the host's fallback, a removed route may serve the Web shell rather than a literal 404; it must no longer implement bridge APIs.
5. Restore the private profile backup if necessary, taking care not to revert unrelated newer changes.

The plugin creates no credential files, sudoers rules, root service, or persistent lease state. Uninstalling is not a rollback of commands previously executed with a lease. Check their side effects separately.
