# DSH Admin Bridge

Scoped, short-lived administrator access for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

## Status

Under development. This repository does not install itself, change sudoers, or grant administrator access. The first target is Linux and DSH `0.1.2-rc.1`.

## Purpose

Let a human authenticate from a dedicated UI and authorize a bounded set of administrator operations for a short period, without placing a sudo password in the model context or retaining it for later commands.

## Design commitments

- Never request passwords in chat or tool arguments.
- Never persist passwords or enable blanket passwordless sudo.
- Do not run the Harness as root.
- Fail closed when session approvals are disabled or unavailable.
- Scope authorization to a session, explicit operations, and a deadline.
- Provide immediate revocation; document its limits for already-started operations.
- Treat the Harness host, plugins, and same-user processes as trusted: this is not a sandbox against a compromised application.

## Development and next steps

Inspect the installed plugin interfaces, implement the privilege bridge and browser authentication surface, add adversarial tests, and document installation and rollback before declaring a usable release.

## License

MIT. See [LICENSE](LICENSE).
