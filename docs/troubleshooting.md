# Troubleshooting

## `oct status` fails

- Check DNS and TLS: `curl https://<relay-domain>/healthz`.
- Ensure the TLS terminator proxies exact `/oct/v1` and `/healthz` paths.
- Check Caddy/nginx logs and the relay service.

## Client shows `HOST_OFFLINE` / 503

- Host service is not connected to the relay.
- Relay and host admission tokens differ (`OCT_RELAY_ADMISSION_TOKEN` vs
  `OCT_TOKEN`), or the room changed.
- The client is using an old invite/session token after the host rotated the
  room or admission secret; re-pair it.
- Host is in E2EE mode but the client has no paired state, or vice versa.
- Relay control protocol mismatch: upgrade relay and host together; protocol 1
  clients cannot join a protocol 2 relay.
- Check `systemctl --user status oct-host` and relay metrics.

## Pairing fails

- Host must be online and in the same room.
- Invite expires after five minutes and is single-use.
- Do not mix `--e2ee`/`--no-e2ee` between a host and a client.
- Host identity mismatch means a different host or a replaced identity; re-pair.

## TUI starts but cannot reach the gateway

- `oct tui` should print `local gateway ready` and wait for the tunnel.
- Check host/relay first. Run `oct tui` with `RUST_LOG=oct=debug` for local
  gateway request logs.
- Ensure the local OpenCode version matches the remote version; mixed versions
  can fail to negotiate.

## MCP/plugin warnings inside the TUI

These come from OpenCode's own configuration, not OCT. Fix or remove the MCP
server/plugin in the local or remote OpenCode config. They do not affect the
tunnel transport.

## Keyring errors

- macOS Keychain may prompt on first use.
- Linux needs an unlocked Secret Service (GNOME Keyring/KWallet) in the user's
  session.
- Headless hosts should use the default 0600 file keystore instead.

## Recovering access

- If a client is lost, `oct revoke <id> --state-dir <host-state>`.
- If the host identity is lost, restore its backed-up identity or create a new
  one and re-pair all clients. A new identity cannot be silently substituted.
