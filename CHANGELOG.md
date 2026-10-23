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

### Changed

- E2EE is the default for host and TUI; `--no-e2ee` is loopback-only.
- Host HTTP client uses HTTP/1.1 with no idle connection reuse for OpenCode
  compatibility.

## [0.1.0] - 2026-10-23

- First functional release candidate.
