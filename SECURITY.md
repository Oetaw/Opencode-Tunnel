# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
private vulnerability reporting ("Security" → "Report a vulnerability") for this
repository. Include:

- affected version/commit;
- deployment topology (relay/host/client);
- reproduction steps or a proof of concept;
- impact assessment;
- whether secrets or user data may be exposed.

We will acknowledge reports as quickly as possible and coordinate disclosure.

## Supported versions

Only the latest release and `main` receive security fixes. Pre-release and
unreleased development builds are not supported for production.

## Security model

Read [docs/security.md](docs/security.md) before deploying. OCT is not
independently audited. Do not expose a relay publicly until the release gates in
that document are complete.

## Operational expectations

- Run the relay behind TLS/WSS.
- Keep OpenCode on loopback.
- Use E2EE (the default).
- Protect state directories and environment files.
- Rotate leaked invites, tokens or identities immediately.
