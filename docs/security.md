# Security model

OCT gives a paired client control of a remote OpenCode service. OpenCode can
execute tools, read repositories and use provider credentials, so a paired
client has **remote-code-execution-equivalent power** inside the service
account. Treat the client identity and invite as highly sensitive.

## Trust model

- Host and client endpoints are trusted. If either is compromised, endpoint
  encryption cannot protect the other.
- The relay is untrusted for confidentiality and integrity. It sees IPs, room
  IDs, timing and ciphertext sizes and can drop, delay or close connections. It
  cannot forge an authenticated frame or change identities.
- TLS protects each relay hop. Noise protects endpoint-to-endpoint traffic.
- The host OS, key storage and OpenCode's own credentials remain in scope.

## Endpoint encryption

With E2EE (default), each connection performs a fresh Noise XX handshake using
persistent X25519 identities.

- The client pins the host public key from the invite or paired state and checks
  it before completing the handshake.
- The host accepts a client only if its public key is in the device allowlist or
  a valid one-time invite is presented inside the encrypted prelude.
- Every binary OCT frame is Noise ciphertext. The relay cannot decrypt it.
- A one-byte authenticated envelope distinguishes DATA from REKEY. Transport
  keys rotate automatically after a byte threshold (default 1 GiB).
- Reconnects always use a fresh handshake, epoch and transport keys.
- `--no-e2ee` is a legacy plaintext loopback mode. It must never be used over a
  public network; host/client validation rejects non-loopback plaintext URLs.

## Pairing and revocation

- Invites contain a 256-bit secret, pinned host key, relay URL, room and token,
  and expire after five minutes by default.
- Invite consumption is atomic and one-time.
- The host stores only device public keys and metadata; the client stores its
  private identity and the pinned host key.
- `oct revoke` marks a device revoked and closes an active session within a few
  seconds. The host reloads the allowlist while running.
- The host enforces a single active writer lease. Observer/multi-writer
  permissions are not implemented.

## Local gateway

The gateway started by `oct tui`:

- binds only `127.0.0.1`;
- requires a random per-run Basic password on every HTTP route and WebSocket
  upgrade;
- enforces Host and Origin policy to prevent DNS rebinding and browser CSRF;
- never forwards the local gateway password to OpenCode;
- passes the backend Basic password only on the host's fixed loopback upstream.

## Relay

- The relay is an opaque router: it does not parse OCT application frames.
- Public bind requires explicit `--allow-public`.
- TLS termination is required in front of a public relay.
- The relay enforces room limits, connection-rate limits, frame bounds and
  idle-room expiry.
- It does not persist application payloads.

## Secrets and logging

Never log or commit:

- `OPENCODE_PASSWORD`, relay room tokens or invite secrets;
- OCT private identity keys;
- Authorization/Cookie headers, PTY tickets or decrypted traffic;
- OpenCode `auth.json` or `opencode.db`.

Use `--use-keyring` where available. Otherwise secrets are stored in 0600 files
inside 0700 directories. Systemd units should use a 0600 `EnvironmentFile`, not
command-line arguments.

## Release gates

This project is not yet independently audited. Before an internet-facing
deployment, complete:

- independent cryptographic design review and penetration test;
- continuous fuzzing/corpus promotion for wire, WS and Noise parsers;
- TLS/WSS terminator review, per-IP edge rate limits and monitoring;
- key-rotation and host-identity replacement drills;
- validation of the OS keyring backend on each target OS.

Do not describe OCT as secure merely because it uses TLS, X25519 or Noise.
