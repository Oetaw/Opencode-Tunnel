# CLI reference

## Global conventions

- `oct --help`, `oct <command> --help`
- E2EE is the default for `host` and `tui`.
- `--no-e2ee` selects the legacy plaintext loopback transport. Never use it on
  a public network.
- `--state-dir` defaults to `$XDG_CONFIG_HOME/oct/<role>` or
  `~/.config/oct/<role>`, where role is `host` or `client`.
- `--use-keyring` stores private identities in the OS credential store. The
  default is a 0600 file in a 0700 directory.
- Secrets are never printed by status/diagnostic commands.

## Host setup

```sh
export OCT_ROOM="$(openssl rand -hex 16)"
export OCT_TOKEN="$(openssl rand -hex 32)"
export OPENCODE_PASSWORD="$(openssl rand -base64 32)"

oct host \
  --relay wss://relay.example.com/oct/v1 \
  --upstream http://127.0.0.1:4096 \
  --state-dir ~/.config/oct/host
```

Useful flags: `--ping-secs`, `--reconnect-max-secs`,
`--backend-password-env`, `--use-keyring`.

`oct host` does not start OpenCode. Run `opencode serve --hostname 127.0.0.1
--port 4096` under its own service or TUI.

## Invite

```sh
oct invite \
  --relay wss://relay.example.com/oct/v1 \
  --room "$OCT_ROOM" --token "$OCT_TOKEN" \
  --state-dir ~/.config/oct/host \
  --output ~/oct-invite.txt
```

- `--ttl-secs` defaults to 300.
- `--output` writes only the URI to a 0600 file.
- Without `--output`, the URI is printed as `pairing_uri=...`.
- The invite is one-time and includes the relay URL, room, token, host public
  key and secret.

## Pair

```sh
oct pair --invite-file ~/oct-invite.txt \
  --state-dir ~/.config/oct/client \
  --name laptop
```

Alternatives: `--invite-stdin` (preferred when piping) or a positional URI.
The host must be online. Pairing fails closed on an expired, reused or
substituted invite.

## Run the TUI

```sh
oct tui --state-dir ~/.config/oct/client
oct tui --state-dir ~/.config/oct/client --auto
```

`--auto` passes `--auto` to OpenCode (auto-approve). Additional OpenCode
arguments go after `--`:

```sh
oct tui --state-dir ~/.config/oct/client -- --model provider/model
```

The TUI launches with the paired host's location. Use OpenCode's directory
controls inside the TUI to switch projects.

## Devices and revocation

```sh
oct devices --state-dir ~/.config/oct/host
oct devices --state-dir ~/.config/oct/host --json
oct revoke <device-id> --state-dir ~/.config/oct/host --terminate-active
```

Revocation is immediate for future handshakes; a running host closes an active
session within a few seconds.

## Relay

```sh
oct relay --listen 127.0.0.1:8080
oct relay --listen 0.0.0.0:8080 --allow-public \
  --public-url wss://relay.example.com/oct/v1
```

`--max-rooms` (default 512) and `--max-queued-bytes` (default 33554432, or
32 MiB) bound in-memory rooms and slow-peer buffering. If either limit is
reached, the relay rejects new rooms or applies backpressure instead of growing
without bound. Keep per-IP connection limiting at the TLS/ingress layer.

Do not expose the relay port directly. Put TLS/WSS in front of it and publish
only the terminator.

## Diagnostics

```sh
oct status --relay wss://relay.example.com/oct/v1
oct doctor --relay wss://relay.example.com/oct/v1
```

`status` prints relay health metrics as JSON. `doctor` fails non-zero when the
relay cannot be reached.
