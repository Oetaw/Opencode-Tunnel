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
- Relay Prometheus metrics: `GET /metrics` (internal only; not proxied publicly).
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

- Store `OCT_ROOM`, `OCT_TOKEN`/`OCT_RELAY_ADMISSION_TOKEN` and
  `OPENCODE_PASSWORD` in 0600 environment files or an external secret manager.
- `OCT_TOKEN` is the host admission secret and must match the relay's
  `OCT_RELAY_ADMISSION_TOKEN`. Never send it to a client.
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
- Revoked client: revocation removes device authorization, but the client still
  knows its room-scoped token. It cannot decrypt traffic or claim the host
  role; the host evicts it after a rejected handshake. For a clean cut, rotate
  `OCT_ROOM` and `OCT_TOKEN`/`OCT_RELAY_ADMISSION_TOKEN`, restart the relay and
  host, and re-pair remaining clients.
- Leaked invite: let it expire; invites are single-use and short-lived. If it
  was used to enroll an unknown device, revoke that device.
- Leaked host key: stop the host, replace its identity, re-pair all clients.
- Leaked admission token: rotate `OCT_TOKEN` and
  `OCT_RELAY_ADMISSION_TOKEN` together, change `OCT_ROOM`, restart relay and
  host, and re-pair clients.
- Suspicious relay: treat it as untrusted; rotate credentials and use a trusted
  relay. Endpoint E2EE remains the confidentiality boundary.
