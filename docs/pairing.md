# Pairing, E2EE and device authorization

**Status:** implemented, pending independent review. This document describes the
actual CLI/state behavior in this tree. See `security.md` for residual gates.

## Identity and state

The host and client each have a persistent X25519 static identity. By default
state lives under:

- host: `~/.config/oct/host` (or `$XDG_CONFIG_HOME/oct/host`)
- client: `~/.config/oct/client` (or `$XDG_CONFIG_HOME/oct/client`)

Override with `--state-dir` or `OCT_STATE_DIR` (the role name is appended).

```text
<state-dir>/identity.json   # public key (+ private key only in file mode)
<state-dir>/devices.json    # host allowlist
<state-dir>/invites/        # one-time invite records keyed by secret hash
<state-dir>/client.json     # paired client: relay/room/token/host pin
```

Private keys, invite secrets, relay tokens, and decrypted traffic must never be
logged or copied between machines. Use `--use-keyring` on `host`, `invite`,
`pair`, and `tui` to store the private identity in macOS Keychain, Linux Secret
Service, or Windows DPAPI. In that mode `identity.json` contains only the public
key and the OS store holds the secret. The default is a restrictive 0600 file
fallback.

## First enrollment

1. Start the relay with an admission token and the host with the same value in
   `OCT_TOKEN`; E2EE is the default. Clients never receive this token.

```sh
OCT_RELAY_ADMISSION_TOKEN=<host-admission-token> \
  cargo run -p oct-cli -- relay --listen 127.0.0.1:8080

OCT_TOKEN=<host-admission-token> cargo run -p oct-cli -- host \
  --state-dir ~/.config/oct/host \
  --relay wss://relay.example/oct/v1 \
  --room <room> --upstream http://127.0.0.1:4096
```

2. Create a one-time invitation. The host derives a room-scoped client token
   from its admission token and puts only that derived token in the invite. The
   URI also contains the invite secret, relay URL, room, host public key, and
   expiry.

```sh
OCT_TOKEN=<host-admission-token> cargo run -p oct-cli -- invite \
  --state-dir ~/.config/oct/host \
  --relay wss://relay.example/oct/v1 \
  --room <room> --ttl-secs 300
```

3. On the local client, import the URI. This connects to the relay, performs
   Noise XX, verifies the pinned host key, proves possession of the invite
   inside the encrypted session, and stores the paired client state.

```sh
# Preferred: keep the invite out of process argv/shell history. The file
# contains only the URI (not the host_fingerprint line).
cargo run -p oct-cli -- pair --invite-stdin \
  --state-dir ~/.config/oct/client --name laptop < invite.txt
# Compatibility: positional URI (visible in `ps` and shell history).
cargo run -p oct-cli -- pair 'octpair1:...' \
  --state-dir ~/.config/oct/client --name laptop
```

The host consumes the invite atomically and adds the client static key to its
allowlist. Reusing the invite fails even if the client retries. The paired
client state stores the room-scoped client token; the client does not need
`OCT_TOKEN` or `OCT_ROOM` after pairing.

4. Run the TUI with E2EE. The client loads its pinned host key and identity; no
   invite is sent after successful enrollment.

```sh
cargo run -p oct-cli -- tui --e2ee \
  --state-dir ~/.config/oct/client
```

## Reconnect

Every reconnect performs a fresh Noise XX handshake and new transport keys.
Existing authorized device keys are accepted without an invite. A revoked key
is rejected immediately for future connections. The host watcher reloads
`devices.json` every two seconds and cancels an active session whose device is
revoked.

A failed PTY/WebSocket upgrade consumes its one-use ticket; reconnect logic must
mint a fresh ticket rather than replaying the old query.

## Revocation

```sh
cargo run -p oct-cli -- revoke <device-id> \
  --state-dir ~/.config/oct/host --terminate-active
```

Revocation is persistent in `devices.json`. `--terminate-active` documents the
intent; the running host closes the matching active tunnel within a few
seconds. Removing the host identity is a new host identity and requires
re-pairing all clients.

## Threat model summary

- The relay is untrusted for confidentiality/integrity; it can drop/delay but
  cannot forge a Noise-authenticated frame or change the pinned host identity.
- Invite possession plus the pinned host key authorizes first enrollment.
- A compromised endpoint defeats E2EE; OS/account compromise is in scope.
- TLS/WSS protects each relay hop; Noise protects endpoint-to-endpoint traffic.
- The local gateway still requires its per-run Basic password on every HTTP and
  WS route, including PTY paths.
