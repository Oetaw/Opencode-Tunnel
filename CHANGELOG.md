# Changelog

All notable changes are recorded here. The project follows Semantic Versioning.

## [Unreleased]

### Added

- End-to-end Noise XX transport with pinned host identities.
- One-time invite pairing and host device allowlist/revocation.
- HTTP/SSE/WebSocket/PTY forwarding, including ticket-aware PTY upgrades.
- Byte-credit flow control, carrier idle detection and automatic rekeying.
- CLI commands: `relay`, `host`, `invite`, `pair`, `tui`, `devices`, `revoke`,
  `status`, `doctor`.
- Docker/Caddy public relay and Kubernetes deployment manifests.
- Property-based parser tests and cargo-fuzz targets.
- Optional OS keyring identity storage.

### Security

- Relay control protocol 2 separates the host admission credential from a
  room-scoped client credential. Only an admitted host can create a room or
  occupy the host role; a client token cannot be used for host-slot squatting
  or unauthenticated room exhaustion.
- A host evicts a client slot after a failed Noise/device authorization so a
  revoked client cannot hold the client role indefinitely.
- Relay admission tokens are required and redacted from debug output.

### Changed

- E2EE is the default for host and TUI; `--no-e2ee` is loopback-only.
- The relay requires `OCT_RELAY_ADMISSION_TOKEN` (or `--admission-token`);
  hosts use the same value as `OCT_TOKEN`. Clients receive a derived client
  credential in the invite and do not need the host admission token.
- Host HTTP client uses HTTP/1.1 with no idle connection reuse for OpenCode
  compatibility.
- Relay rooms and queued peer bytes are bounded; slow writers are disconnected
  and the limits are configurable with `--max-rooms` and
  `--max-queued-bytes`.
- Invite output is written atomically with mode 0600 and does not follow a
  pre-existing symlink.
- A wrong-token relay room squat is retried instead of terminating the host
  process.
- `host` and `tui` only auto-generate a room token on an interactive terminal;
  non-interactive runs must supply `OCT_TOKEN` or `--token`.

## [0.1.0] - 2026-10-23

- First functional release candidate.
