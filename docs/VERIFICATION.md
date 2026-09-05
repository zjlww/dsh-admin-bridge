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

## Validation limits

The initial automated development run did not request passwords or execute sudo. A subsequent human-operated live test successfully exercised the Admin UI flow, two real root commands under one lease, and revocation; see below. This validates one host configuration, not every distribution or PAM policy. MFA, custom PAM dialogs, `requiretty` and sudo I/O-policy variations remain unsupported or unverified. Run the explicit operator smoke test in [INSTALL.md](INSTALL.md) before using meaningful privileged operations on another host.

No independent screenshot or browser automation capture was taken during password entry. The human confirmed the Admin button was visible and completed the dedicated authentication flow; the agent observed only lease status and command results, never the password.

## Side effects, backups and rollback

Development created this public GitHub repository, enabled private vulnerability reporting, and pushed source/documentation/tests. It created a separate local project checkout and project-local `node_modules`/lockfile; dependencies and generated artifacts are excluded from Git. `npm install --ignore-scripts` reported zero dependency vulnerabilities when the initial lockfile was created.

During initial development, no changes were made to sudoers, PAM, system packages, services, permissions, DSH runtime files, live profiles, credentials or permission presets. No replacement Web server was started. Automated HTTP fixtures bind ephemeral loopback ports and shut down after their tests; fake browser-auth signing material exists only in test memory. Helper subprocesses run at the invoking test user's privileges and are cleaned up.

Installation later changed the selected DSH profile, with a private profile backup and documented rollback. The human explicitly changed the current session to Workspace Write, enabling native approval prompts, then later restored Full access after the test (approval policy returned to `never`). The agent did not change either permission setting. The real privileged operations were only two executions of `/usr/bin/id -u`; they reported the effective UID and made no system changes. The test ended with administrator access locked. Removing the plugin cannot undo effects of any future commands a user authorizes.

## First live installation and sudo test — 2026-09-05

The human requested installation and testing. Source commit `9193a501666fbd05fec20a4ba41054bd2755a1f4` was installed into the existing Web profile using the official plugin manager with lifecycle scripts disabled. Profile-only backups were taken privately; no credentials were copied. The dependency/lockfile delta added only this package, and the installed executable sources matched the reviewed checkout byte-for-byte. Peer imports resolved to the existing exact-version runtime packages without adding duplicate core packages.

The DSH prerelease caches bundle layers and command-line overlays at startup. Its profile-patch watcher supports live additions, so the deployment used a **permanent** profile override disabling the default `admin-bridge` bundle row and inserting a distinct `admin-bridge-live` row with the full configuration. This avoids restarting the process hosting the active agent. The actual patch composer and client graph reconciliation methods were tested with detached before/after-restart entry lists: both have exactly one enabled host instance and one browser module. An ordinary same-ID insert is **not** safe because it duplicates the bundle row after restart. The simpler canonical restart-based installation remains documented in [INSTALL.md](INSTALL.md).

Live results:

- The existing service stayed active with the same PID; no replacement server or core runtime patch was used.
- Only `whoami-root` = `/usr/bin/id -u` was configured, with a five-second command timeout and a 60-second maximum lease.
- The actual route changed from the unloaded fallback's HTTP 405 to the plugin's HTTP 401 JSON browser-authentication rejection, with `no-store` and other defensive headers.
- With native approval policy disabled, actual `admin_status` reported disabled and the exact catalog; `admin_run(whoami-root)` returned `policy_denied`.
- The human refreshed the existing GUI, confirmed the Admin button, and used this conversation's `/permission` picker to switch to **Workspace Write**. The runtime confirmed policy `never` changed to `ask`; `admin_status` then reported locked. Changing only the Settings default would not change an existing session.
- `admin_unlock` requested one 60-second lease for `whoami-root`. The human approved the native request and completed the Admin authentication dialog. The tool returned `unlocked` for exactly that operation ID.
- Two successive actual `admin_run` calls each returned `exitCode: 0`, `stdout: "0\n"`, empty stderr, `truncated: false` and `timedOut: false`. No second unlock/authentication was requested.
- `admin_lock` returned locked. A subsequent `admin_run` was rejected with code `locked` and message `Authenticate an approved administrator request first.`
- All 121 JavaScript and 22 unprivileged Python tests passed again before activation.

The browser automation extension was disconnected, so GUI interaction was performed by the human rather than captured by automation. No password appeared in agent arguments, results or documentation. Natural expiry and multi-session isolation are covered by automated tests but were not separately repeated with additional real authentications in this smoke test.

Rollback of this live composition must remove **both** the original-row disable and the distinct live insert, remove the package through DSH, then restart the existing service at a safe turn boundary and refresh the page.

## Fourth-mode implementation — 0.2.0-alpha.1

A separate development pass replaces the standalone Admin header/approval workflow with **Sudo access**, the fourth option in the existing composer selector. The original three labels, glyphs and normal Full-access acknowledgement are retained; Sudo has a shield-with-key glyph. Each selection requires fresh password-based sudo authentication, including reselection while active. There is no model `admin_unlock` tool and no prerequisite to enable ordinary approval prompts.

Current automated evidence, on the same Node/Python versions above:

| Check | Result |
|---|---|
| `npm test` — JavaScript | **216 passed**, no failures/skips |
| `npm test` — unprivileged Python | **22 passed**, no failures/skips |
| `npm run check`, `git diff --check` | Passed |
| `npm pack --dry-run --ignore-scripts` | 21 source/documentation files; no dependencies or secrets |
| `npm install --ignore-scripts` | 44 packages audited, zero vulnerabilities |

New coverage includes 26 synthetic component tests, native SVG fingerprints, 27 mode-controller tests, 23 private rollback-journal tests, guarded compatibility apply/revert tests, real Cordis command ownership and disposal, actual DSH Session snapshot replay, delegation headers, explicit same-value exits, native-choice preservation, journal-ahead-of-log crash recovery, and fresh-password challenge enforcement. HTTP/client cancellation is bound to its original nonce; stale dialogs cannot revoke a newer entry. These tests do **not** enter a real password or execute privileged commands.

Integration review found and fixed two rc.1 compatibility issues before deployment: its session persistence does not accept arbitrary unmarked event types, and Session.append cannot be reentered from native event observers. Mode rollback therefore uses a private, strictly validated, fsynced metadata file rather than unsupported custom session events. This contains no password, authentication nonce or restorable root authority. The original session creation identity and native event cutoffs distinguish rollback from newer human choices.

The only core change is the explicit two-artifact composer compatibility rebuild documented in `compat/README.md`, with an unchanged native fallback. There is no new sandbox enum, global default, generic renderer patch, unrestricted root shell, or replacement Web server. The plugin explicitly refreshes already-built client artifacts in DSH's revision graph during live activation; this is not a source watcher or a promise of refresh-free browser updates.

### New mode: human-operated live test passed — 2026-09-05

The new flow was separately installed and tested from commit `8f09d73e5e6c007771039c9b9ef6a544017155eb`. The official manager updated the pinned profile package with lifecycle scripts disabled; a complete fresh versioned physical package prevented reuse of old ESM imports. Source bytes and all twelve shared runtime peer resolutions were verified. The guarded composer rebuild reported both artifacts patched, and the existing process stayed active with the same PID; the original bundle row remains disabled beside the single live row.

Before authentication, `admin_status` reported `modeActive:false` under ordinary Full access (`never` approval policy); execution was rejected. The human was asked to refresh the existing page and use the fourth-mode password dialog, then reported **Done**. Status confirmed `modeActive:true`, the exact one-operation allowlist, TTL 60 and previous preset Full access. Two real `admin_run(whoami-root)` calls each returned exit code 0 and stdout `0\n`, with empty stderr and no timeout/truncation, under that one authentication. `admin_lock` returned `modeActive:false`; a subsequent operation was rejected. The previous Full access mode was restored, and the private rollback directory was empty afterward.

The existing GUI and unauthenticated bridge API retained HTTP 401 authentication fences. No password was supplied to the agent or captured in browser automation, screenshots or request exports. This was a human-operated GUI test, not independent visual automation. Natural expiry, repeat-entry password requirements and isolation retain automated coverage but were not additionally exercised with real password submissions in this run. No sudoers, PAM, system package, root service or routing changes were made; the two privileged commands only reported their UID.

## Remaining work

- Enable GitHub Actions with appropriate repository authorization and exercise Node 22/24 on supported distributions.
- Broader distribution/PAM/browser testing, including additional operator-run expiry and cross-session checks.
- Independent security audit before recommending production use.
- A separately installed root-owned broker/policy for deployments needing isolation from same-user processes or restricted-sudo accounts.
