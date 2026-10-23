# Operations

## Topology

```text
OpenCode TUI -> 127.0.0.1:<gateway> -> oct client
                                      outbound WSS + Noise
                                      -> TLS terminator -> oct relay
                                      <- outbound WSS + Noise
                                      <- oct host -> 127.0.0.1:4096 OpenCode
```

No inbound port is opened on the OpenCode host. Only the TLS terminator is
public; the relay stays on a private interface/network.

## Health checks

- Relay liveness/readiness: `GET /healthz` (JSON).
- Client/relay probe: `oct status --relay wss://relay.example.com/oct/v1`.
- Host: `systemctl --user status oct-host`.
- OpenCode: `curl -u "opencode:$OPENCODE_PASSWORD" http://127.0.0.1:4096/api/info`.

## Deploy

- Docker/Caddy: [deployment.md](deployment.md#docker-compose-caddy-tls)
- Kubernetes: [deployment.md](deployment.md#kubernetes)
- systemd host: [deployment.md](deployment.md#systemd-host)

## Logs

OCT never logs bodies, authorization headers, cookies, invite secrets, PTY
tickets, decrypted frames or query strings. Logs include service health,
connection lifecycle and redacted errors.

Use structured logs in production:

```sh
RUST_LOG=oct=info oct host ...
```

For debugging a local gateway only:

```sh
RUST_LOG=oct=debug oct tui ...
```

Do not enable trace logging in production; it can include timing and stream
metadata even though payloads remain redacted.

## Secrets

- Store `OCT_ROOM`, `OCT_TOKEN` and `OPENCODE_PASSWORD` in 0600 environment
  files or an external secret manager.
- Prefer `--use-keyring` for host/client identities on workstations.
- Back up host identity securely; losing it requires re-pairing all clients.
- Never copy `opencode.db`, `auth.json` or provider credentials between hosts.

## Upgrades

1. Build/pull the candidate binary or image.
2. Run the release gate: fmt, clippy, workspace tests and the real E2E suite.
3. Upgrade relay, then host, then client.
4. Keep the previous artifact for rollback.
5. A host identity change is a new identity and requires re-pairing.

## Incident response

- Lost client: `oct revoke <id> --state-dir <host-state> --terminate-active`.
- Leaked invite: let it expire; invites are single-use and short-lived.
- Leaked host key: stop the host, replace its identity, re-pair all clients.
- Leaked relay token: change the room/token, restart host and clients.
- Suspicious relay: treat it as untrusted; rotate room/token and use a trusted
  relay. Endpoint E2EE remains the confidentiality boundary.
