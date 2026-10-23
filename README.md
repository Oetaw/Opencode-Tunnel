# OCT — OpenCode Tunnel

OCT connects your local [OpenCode](https://opencode.ai) TUI to an OpenCode
service running on another machine. Both ends dial **outbound** to a relay; no
inbound port is opened on the OpenCode host. Application traffic is protected
end-to-end with Noise XX, so the relay routes ciphertext without holding
endpoint keys.

```text
 local machine                         relay VPS                     OpenCode host
┌──────────────────┐   WSS + Noise   ┌──────────────┐   WSS + Noise  ┌────────────────────┐
│ opencode TUI     │ ──────────────> │ Caddy + OCT  │ <───────────── │ oct host           │
│ oct local gateway│                 │ relay        │                │ opencode serve     │
└──────────────────┘                 └──────────────┘                └────────────────────┘
```

## Why OCT

- **No inbound ports** on the OpenCode machine.
- **End-to-end encryption** with a pinned host identity and one-time invites.
- **Device allowlist and revocation** on the host.
- **Unmodified OpenCode TUI** over HTTP, SSE, WebSocket and PTY traffic.
- **Single binary** for relay, host, client and diagnostics.
- **Public deployment assets** for Docker/Caddy and Kubernetes.

## Install

Requirements:

- Rust 1.93.1 when building from source.
- OpenCode V2 installed locally and on the remote host.
- Linux or macOS for the host/client. The relay runs anywhere Docker or a
  static binary runs.

```sh
git clone https://github.com/anomalyco/oct.git
cd oct
cargo build --release -p oct-cli --bin oct
install -m 755 target/release/oct /usr/local/bin/oct

# or install directly into Cargo's bin directory
cargo install --path crates/oct-cli --locked
```

Container images and release binaries are produced by the GitHub workflows.

## Quick start

### 1. Relay

The simplest public relay is Docker Compose with Caddy:

```sh
cd deploy/relay
cp .env.example .env
# set OCT_DOMAIN, OCT_ACME_EMAIL and a random OCT_RELAY_ADMISSION_TOKEN
docker compose -f compose.public.yaml up -d --build
```

The relay is reachable at `wss://<OCT_DOMAIN>/oct/v1`. Caddy terminates TLS;
only ports 80 and 443 are public. Kubernetes manifests are in
[`deploy/kubernetes`](deploy/kubernetes).

`OCT_RELAY_ADMISSION_TOKEN` is the host admission secret. It is never given to
clients; clients receive only a room-scoped credential inside an invite.

### 2. Host

On the machine running OpenCode:

```sh
mkdir -p ~/.config/oct/host
chmod 700 ~/.config/oct/host

# Copy OCT_RELAY_ADMISSION_TOKEN from deploy/relay/.env.
# Never send OCT_TOKEN to clients; invites contain a derived client credential.
export OCT_ROOM="$(openssl rand -hex 16)"
export OCT_TOKEN="<paste-relay-admission-token>"
export OPENCODE_PASSWORD="$(openssl rand -base64 32)"

oct host \
  --relay wss://relay.example.com/oct/v1 \
  --upstream http://127.0.0.1:4096 \
  --state-dir ~/.config/oct/host
```

E2EE is enabled by default. OpenCode must already be listening on loopback.
Create an invite:

```sh
oct invite \
  --relay wss://relay.example.com/oct/v1 \
  --room "$OCT_ROOM" --token "$OCT_TOKEN" \
  --state-dir ~/.config/oct/host \
  --output ~/oct-invite.txt
```

`oct invite` prints the host fingerprint and writes a 0600 invite file. The
invite expires after five minutes and can be used once. It contains a
room-scoped client credential derived from `OCT_TOKEN`; the host admission
token itself is never placed in the invite.

### 3. Client

On the local machine:

```sh
oct pair --invite-file ~/oct-invite.txt \
  --state-dir ~/.config/oct/client \
  --name laptop

oct tui --state-dir ~/.config/oct/client --auto
```

`oct tui` starts the authenticated loopback gateway and launches the unmodified
OpenCode TUI against it. `--auto` enables OpenCode's auto-approval mode. Remove
it if you want normal permission prompts. The paired client state already
contains the room and client credential; clients do not need `OCT_TOKEN`.

Use `--use-keyring` on `host`, `invite`, `pair`, and `tui` to keep private
identities in macOS Keychain, Linux Secret Service, or Windows DPAPI.

## CLI

| Command | Purpose |
|---|---|
| `oct relay` | Opaque relay; loopback by default, public bind requires `--allow-public`. |
| `oct host` | Outbound host agent. E2EE by default. |
| `oct invite` | Create a one-time host invitation. |
| `oct pair` | Enroll a client from an invitation. |
| `oct tui` | Start the local gateway and launch OpenCode. E2EE by default. |
| `oct devices` | List authorized devices on the host. |
| `oct revoke` | Revoke a device and optionally close its active session. |
| `oct status` | Query relay health. |
| `oct doctor` | Validate relay reachability and local configuration. |

See [docs/cli.md](docs/cli.md) for every flag and workflow.

## Documentation

- [Architecture](docs/architecture.md) — components, data flow and trust boundaries.
- [CLI reference](docs/cli.md) — commands, state directories and examples.
- [Pairing and E2EE](docs/pairing.md) — invitation, key storage and revocation.
- [Security model](docs/security.md) — threat model, controls and residual gates.
- [Deployment](docs/deployment.md) — Docker/Caddy, Kubernetes and systemd.
- [Operations](docs/operations.md) — upgrades, logs, backup and incident handling.
- [Troubleshooting](docs/troubleshooting.md) — common failures and diagnostics.
- [Protocol](docs/protocol.md) — OCT/1 wire format.
- [Compatibility](docs/compatibility.md) — tested OpenCode versions and version matching.
- [Fuzzing](fuzz/README.md) — fuzz targets and commands.

## Security

A paired OCT client can control an OpenCode service that executes tools and
reads repositories. Treat it as remote-code-execution-equivalent access.

- E2EE is required for non-loopback relays. The legacy plaintext transport is
  available only with `--no-e2ee` for loopback testing.
- The relay sees room metadata and ciphertext, never endpoint keys.
- The local gateway binds `127.0.0.1` only and authenticates every HTTP and
  WebSocket route.
- The host never accepts arbitrary upstream URLs; it dials one configured
  loopback origin.
- Invite secrets, admission/client credentials, provider credentials, PTY tickets and decrypted
  traffic are never logged.

This project has not completed an independent cryptographic audit. See
[docs/security.md](docs/security.md) before exposing a relay to the internet.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Real OpenCode tests are opt-in:

```sh
./scripts/e2e-real-opencode.sh
./scripts/e2e-tui.py
./scripts/e2e-tui.py --e2ee
```

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
