# DSH rc.1 composer permission slot

DSH `0.1.2-rc.1` hardcodes its three-mode composer selector. The explicit `permission-slot.mjs` compatibility patch adds one supported, session-scoped **single** slot, `conversation.input.permission`, at that exact location. Its owner props are `{ value: permissions, locked, command }`; session slot context supplies `sessionId` and `useProjection`. `command(line)` returns `Promise<boolean>`.

The untouched native `PermissionSelect` is the fallback when no plugin occupies the slot. Admin Bridge registers only this slot, preserving the three native labels, SVG glyphs, and Full access risk confirmation, and adding Sudo access with a shield-and-key glyph. It does not register an Admin header action or decorate commands. Native permission presets, saved defaults, and the slash-command popup still contain only the native modes.

## Deliberate application

Run from the reviewed plugin checkout, using the actual existing runtime directory:

```sh
node compat/permission-slot.mjs --check --runtime /absolute/runtime
node compat/permission-slot.mjs --apply --runtime /absolute/runtime
```

The script checks the exact package version and expected anchors in `lib/client.js` and `lib/types/client/contract/slots.d.ts`, rejects partial/foreign patches, and backs up both originals with suffix `.admin-bridge-permission-slot.rc1.bak` before writing. It does not edit core permission behavior or automatically run at installation.

Follow the deployment's existing client-artifact rebuild procedure if it bundles these installed modules. Restart the **existing** DSH Web process at a safe turn boundary and refresh its existing URL. Do not start a replacement server or assume plugin HMR rebuilds the shell or installed artifacts.

## Rollback

Remove the plugin contribution to immediately restore the native fallback on the next client load. To also remove the compatibility slot, keep the matching backups and run:

```sh
node compat/permission-slot.mjs --revert --runtime /absolute/runtime
```

Rebuild affected deployment artifacts if applicable, restart the existing Web process safely, and refresh. The script validates backups before restoring and leaves them available for audit. It neither changes live session permissions nor performs sudo authentication. Revoking a Sudo session does not undo completed command effects.

## Verification scope

`node --test tests/client.test.js` exercises the client in a synthetic VM/component harness, including its four choices, native glyphs, Full access confirmation, private password transport, cancellation, fresh re-entry, status polling, and lifecycle cleanup. These tests do not launch a browser, run sudo, request real passwords, or modify live configuration. Runtime patch/deployment and real human-authentication verification are separate integration steps; no live GUI result is implied by the component tests.
