# Verification and development side effects

## Initial alpha scope

Target: `dsh-admin-bridge@0.1.0-alpha.1`, Linux, DSH `0.1.2-rc.1`.

The implementation was developed against the installed DSH package interfaces and the same exact public peer versions in a separate project-local dependency tree. Local tools: Node.js `v26.7.0`, Python `3.14.7`. Node 22/24 are intended compatibility targets but were not exercised in this local run.

## Automated evidence

Local combined validation passed:

| Check | Result |
|---|---|
| `npm test` — JavaScript | 121 passed; no failures or skips |
| `npm test` — Python helper | 22 passed; no failures or skips |
| `npm run check` | All JavaScript/Python syntax checks passed |
| `npm pack --dry-run --ignore-scripts` | Source-only package; no dependencies, secrets or generated artifacts included |
| `git diff --check` | Passed |

- Real Cordis `4.0.2` and DSH Tools `0.1.2-rc.1` registration, execution/output validation and scoped disposal are exercised with fake agents/approval outcomes. Both already-live and newly created agent sessions receive tools without adding global tools.
- The actual DSH Connection plugin's cookie verification is exercised using a newly generated, memory-only test credential provider. Missing/tampered cookies and cross-origin requests fail; valid test cookies work. No real DSH credentials or browser sessions are used.
- Bridge tests exercise session isolation, frozen operation manifests, deadlines, policy denial and revocation across asynchronous authentication, nonce replay, concurrent authentication, cancellation, cooldown and fail-closed error handling.
- HTTP tests cover native-auth rejection, exact Origin/transport checks, malformed/oversized input, unexpected fields, no-store responses, error sanitization and disconnect cancellation.
- Sudo protocol tests use **fake child processes**. They assert no password in argv/env, no write before the unique prompt, one submission only, discarded unused secrets, live policy checks before spawn/password delivery, bounded frames, validated root-ready/result messages, and EOF/error cleanup.
- Client tests execute the hand-written module in a VM with React/Fetch doubles: slot registration, disabled-policy UI, exact inert argv presentation, and clearing the uncontrolled password field before the simulated request resolves. This is **not** a real-browser end-to-end test.
- Python tests run the actual helper **unprivileged**, including strict manifests/protocol, immutable argv, environment/cwd/stdin, output caps, deadlines, signals, process-group termination/reaping and emergency cleanup after injected supervisor failures. Root ownership checks are mocked; root integration tests are intentionally not performed.

GitHub Actions CI is **not enabled**. The current GitHub OAuth login lacks the `workflow` scope, and GitHub rejected a push containing an Actions workflow. The optional workflow was removed from the unpublished commit rather than requesting broader credentials or bypassing that restriction. Local tests and the checked-in lockfile remain reproducible; CI can be added later by an appropriately authorized human.

## Not verified / operator gate

**No real sudo/PAM authentication or privileged command was executed during development. No password was requested.** Successful unit/protocol tests are not proof that a particular host's sudo/PAM configuration works. MFA, custom PAM dialogs, `requiretty` and sudo I/O-policy variations need separate consideration. Run the explicit human-operated `/usr/bin/id -u` smoke test in [INSTALL.md](INSTALL.md) before using meaningful privileged operations.

The initial development run did not install the plugin. A subsequent human-authorized installation successfully loaded it into an existing DSH Web host; see the live-installation evidence below. A visible browser/password flow and privileged end-to-end result are still not claimed. Browser UI compatibility has been checked against the targeted DSH module/slot contracts and component tests, not a screenshot of an installed plugin.

## Side effects, backups and rollback

Development created this public GitHub repository, enabled private vulnerability reporting, and pushed source/documentation/tests. It created a separate local project checkout and project-local `node_modules`/lockfile; dependencies and generated artifacts are excluded from Git. `npm install --ignore-scripts` reported zero dependency vulnerabilities when the initial lockfile was created.

During initial development, no changes were made to sudoers, PAM, system packages, services, permissions, DSH runtime files, live profiles, credentials or permission presets. No replacement Web server was started. Automated HTTP fixtures bind ephemeral loopback ports and shut down after their tests; fake browser-auth signing material exists only in test memory. Helper subprocesses run at the invoking test user's privileges and are cleaned up.

There was no pre-existing project to back up, and no system rollback is needed for development. A future operator installation changes the selected DSH profile and requires a private profile backup, a restart/refresh of the existing GUI, and the documented removal procedure. Removing the plugin cannot undo effects of commands a user later authorizes.

## First live installation — 2026-09-05

The human subsequently requested installation and testing. Source commit `9193a501666fbd05fec20a4ba41054bd2755a1f4` was installed into the existing Web profile using the official plugin manager with lifecycle scripts disabled. Profile-only backups were taken privately; no credentials were copied. The dependency/lockfile delta added only this package, and the installed executable sources matched the reviewed checkout byte-for-byte. Peer imports resolved to the existing exact-version runtime packages without adding duplicate core packages.

The DSH prerelease caches bundle layers and command-line overlays at startup. Its profile-patch watcher supports live additions, so the deployment used a **permanent** profile override disabling the default `admin-bridge` bundle row and inserting a distinct `admin-bridge-live` row with the full configuration. This avoids restarting the process hosting the active agent. The actual patch composer and client graph reconciliation methods were tested with detached before/after-restart entry lists: both have exactly one enabled host instance and one browser module. An ordinary same-ID insert is **not** safe because it duplicates the bundle row after restart. The simpler canonical restart-based installation remains documented in [INSTALL.md](INSTALL.md).

Live results:

- The existing service stayed active with the same PID; no replacement server or core runtime patch was used.
- Only `whoami-root` = `/usr/bin/id -u` was configured, with a five-second command timeout and a 60-second maximum lease.
- The actual route changed from the unloaded fallback's HTTP 405 to the plugin's HTTP 401 JSON browser-authentication rejection, with `no-store` and other defensive headers.
- The existing agent successfully called `admin_status`: disabled approval policy, exact one-operation catalog, TTL limit 60. `admin_run(whoami-root)` returned `policy_denied`; `admin_lock` returned locked. These are real live-host tool calls, not mocks.
- All 121 JavaScript and 22 unprivileged Python tests passed again before activation.

The browser automation extension was disconnected, so a human refresh and explicit approval-enabled test session are still needed to verify the visible dialog and real sudo/PAM authentication. No approval policy was changed and no sudo command was executed. Rollback of this live composition must remove **both** the original-row disable and the distinct live insert, remove the package through DSH, then restart the existing service at a safe turn boundary and refresh the page.

## Remaining work

- Enable GitHub Actions with appropriate repository authorization and exercise Node 22/24 on supported distributions.
- Human-run real sudo/PAM and installed-browser smoke tests on supported distributions.
- Independent security audit before recommending production use.
- A separately installed root-owned broker/policy for deployments needing isolation from same-user processes or restricted-sudo accounts.
