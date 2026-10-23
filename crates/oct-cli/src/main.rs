use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::{
    generate_room_credentials, validate_token, RelayControl, RelayRole, RELAY_PROTOCOL,
};
use oct_relay::{Relay, RelayConfig};
use oct_security::{
    parse_public_key, public_key_hex, ClientPrelude, ClientSecurity, DeviceStore, HostPrelude,
    HostSecurity, Invite, Keystore, DEFAULT_INVITE_TTL,
};
use oct_transport::{WsConnection, WsOptions};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "oct", version, about = "OpenCode Tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the opaque relay (loopback by default; public requires E2EE).
    Relay(RelayArgs),
    /// Run the outbound host agent.
    Host(HostArgs),
    /// Start the local gateway and launch the unmodified OpenCode TUI.
    Tui(TuiArgs),
    /// Query the relay health endpoint.
    Status(RelayOnlyArgs),
    /// Validate configuration and relay reachability.
    Doctor(RelayOnlyArgs),
    /// Create a one-time host invitation.
    Invite(InviteArgs),
    /// Import an invitation and enroll this device.
    Pair(PairArgs),
    /// Revoke a paired device on the host.
    Revoke(RevokeArgs),
    /// List devices authorized by a host.
    Devices(DevicesArgs),
}

#[derive(Args)]
struct RelayArgs {
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long)]
    public_url: Option<String>,
    /// Explicitly allow a non-loopback bind. Requires Phase 2 E2EE on both endpoints.
    #[arg(long)]
    allow_public: bool,
}

#[derive(Args)]
struct RelayOnlyArgs {
    #[arg(long, default_value = "ws://127.0.0.1:8080/oct/v1")]
    relay: String,
}

#[derive(Args)]
struct HostArgs {
    #[arg(long, default_value = "ws://127.0.0.1:8080/oct/v1")]
    relay: String,
    #[arg(long, env = "OCT_ROOM")]
    room: String,
    #[arg(long, env = "OCT_TOKEN")]
    token: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:4096")]
    upstream: String,
    #[arg(long, default_value = "OPENCODE_PASSWORD")]
    backend_password_env: String,
    #[arg(long, default_value_t = 20)]
    ping_secs: u64,
    #[arg(long, default_value_t = 30)]
    reconnect_max_secs: u64,
    /// Compatibility flag; E2EE is enabled by default.
    #[arg(long, hide = true)]
    e2ee: bool,
    /// Use the legacy plaintext loopback transport (never for public networks).
    #[arg(long = "no-e2ee", alias = "legacy-plaintext")]
    no_e2ee: bool,
    /// Host security state directory (identity, devices, invites).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Store the private identity in the OS credential store (Keychain/Secret Service/DPAPI).
    #[arg(long)]
    use_keyring: bool,
}

#[derive(Args)]
struct TuiArgs {
    #[arg(long, default_value = "ws://127.0.0.1:8080/oct/v1")]
    relay: String,
    #[arg(long, env = "OCT_ROOM")]
    room: Option<String>,
    #[arg(long, env = "OCT_TOKEN")]
    token: Option<String>,
    #[arg(long, default_value = "opencode")]
    opencode: PathBuf,
    #[arg(long, default_value_t = 10)]
    connect_timeout_secs: u64,
    /// Start the TUI in auto-approve mode (`opencode --auto`).
    #[arg(long)]
    auto: bool,
    /// Arguments passed through to opencode after `--`.
    #[arg(last = true)]
    opencode_args: Vec<String>,
    /// Compatibility flag; E2EE is enabled by default.
    #[arg(long, hide = true)]
    e2ee: bool,
    /// Use the legacy plaintext loopback transport (never for public networks).
    #[arg(long = "no-e2ee", alias = "legacy-plaintext")]
    no_e2ee: bool,
    /// Client security state directory (identity and paired session).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Store the private identity in the OS credential store.
    #[arg(long)]
    use_keyring: bool,
}

#[derive(Args)]
struct InviteArgs {
    #[arg(long, default_value = "ws://127.0.0.1:8080/oct/v1")]
    relay: String,
    #[arg(long, env = "OCT_ROOM")]
    room: String,
    #[arg(long, env = "OCT_TOKEN")]
    token: Option<String>,
    #[arg(long, default_value_t = DEFAULT_INVITE_TTL)]
    ttl_secs: u64,
    #[arg(long)]
    label: Option<String>,
    /// Host security state directory (identity and invite store).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Store the private identity in the OS credential store.
    #[arg(long)]
    use_keyring: bool,
    /// Write only the pairing URI to this 0600 file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
struct PairArgs {
    invite: Option<String>,
    /// Read the one-time invite URI from stdin instead of argv.
    #[arg(long)]
    invite_stdin: bool,
    /// Read the invite URI from a file.
    #[arg(long)]
    invite_file: Option<PathBuf>,
    #[arg(long)]
    name: Option<String>,
    /// Client security state directory (identity and paired session).
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Store the private identity in the OS credential store.
    #[arg(long)]
    use_keyring: bool,
}

#[derive(Args)]
struct DevicesArgs {
    /// Host security state directory.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Emit JSON for scripts.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RevokeArgs {
    device: String,
    #[arg(long)]
    terminate_active: bool,
    /// Host security state directory (device allowlist).
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("oct=info,warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Relay(args) => run_relay(args).await,
        Command::Host(args) => run_host(args).await,
        Command::Tui(args) => run_tui(args).await,
        Command::Status(args) => run_status(args).await,
        Command::Doctor(args) => run_doctor(args).await,
        Command::Invite(args) => run_invite(args).await,
        Command::Pair(args) => run_pair(args).await,
        Command::Revoke(args) => run_revoke(args).await,
        Command::Devices(args) => run_devices(args).await,
    }
}

async fn run_relay(args: RelayArgs) -> Result<()> {
    if let Some(url) = &args.public_url {
        tracing::info!(public_url = %url, "relay public URL configured for diagnostics only");
    }
    let relay = Relay::bind(RelayConfig {
        listen: args.listen,
        public_url: args.public_url,
        allow_public: args.allow_public,
        ..RelayConfig::default()
    })
    .await
    .context("bind relay")?;
    let addr = relay.local_addr();
    tracing::info!(%addr, allow_public = args.allow_public, "relay listening");
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    relay.serve(shutdown).await.context("serve relay")
}

async fn run_host(args: HostArgs) -> Result<()> {
    let token = resolve_token(args.token)?;
    let backend_password = std::env::var(&args.backend_password_env).ok();
    let e2ee = !args.no_e2ee;
    let security = if e2ee {
        let dir = resolve_state_dir(args.state_dir, "host")?;
        let keystore = if args.use_keyring {
            Keystore::with_keyring(&dir)
        } else {
            Keystore::new(&dir)
        };
        let security =
            HostSecurity::from_keystore(&dir, keystore).context("load host security state")?;
        tracing::info!(fingerprint = %security.fingerprint(), "host E2EE identity loaded");
        Some(Arc::new(security))
    } else {
        None
    };
    let config = HostConfig {
        relay_url: args.relay,
        room: args.room,
        token,
        upstream_url: args.upstream,
        backend_password,
        ping_interval: Duration::from_secs(args.ping_secs.max(1)),
        reconnect_max: Duration::from_secs(args.reconnect_max_secs.max(1)),
        security,
    };
    let agent = HostAgent::new(config).context("host configuration")?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    tracing::info!("host agent starting");
    agent.run(shutdown).await.context("host agent")
}

async fn run_tui(args: TuiArgs) -> Result<()> {
    let e2ee = !args.no_e2ee;
    let (relay_url, room, token, security) = if e2ee {
        let dir = resolve_state_dir(args.state_dir, "client")?;
        let keystore = if args.use_keyring {
            Keystore::with_keyring(&dir)
        } else {
            Keystore::new(&dir)
        };
        let session: ClientSessionFile = keystore
            .read_json(CLIENT_SESSION_FILE)?
            .context("client is not paired; run `oct pair --invite-file <file>` first")?;
        let identity = keystore
            .load_identity()?
            .context("client identity is missing; run `oct pair --invite-file <file>` first")?;
        let pinned_host = parse_public_key(&session.host_public_key)?;
        (
            session.relay_url,
            session.room,
            session.token,
            Some(Arc::new(ClientSecurity::new(
                identity,
                pinned_host,
                session.device_name,
                None,
            ))),
        )
    } else {
        (
            args.relay,
            args.room.context("--room is required with --no-e2ee")?,
            resolve_token(args.token)?,
            None,
        )
    };
    let client = TunnelClient::new(ClientConfig {
        relay_url,
        room,
        token,
        gateway_bind: "127.0.0.1:0".parse().expect("static loopback bind"),
        connect_timeout: Duration::from_secs(args.connect_timeout_secs.max(1)),
        security,
    })
    .context("client configuration")?;
    let shutdown = CancellationToken::new();
    let handle = client
        .start(shutdown.clone())
        .await
        .context("start gateway")?;
    tracing::info!(local_url = %handle.local_url, "local gateway ready");
    if !handle.wait_connected(Duration::from_secs(10)).await {
        tracing::warn!("tunnel is not connected yet; starting the TUI anyway");
    }

    let mut command = tokio::process::Command::new(&args.opencode);
    command.arg("--server").arg(&handle.local_url);
    if args.auto {
        command.arg("--auto");
    }
    let mut child = command
        .args(&args.opencode_args)
        .env("OPENCODE_PASSWORD", &handle.password)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawn {}", args.opencode.display()))?;

    let status = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            let _ = child.start_kill();
            child.wait().await
        }
        status = child.wait() => status,
    };
    handle.shutdown.cancel();
    shutdown.cancel();
    let status = status.context("wait for opencode")?;
    if !status.success() {
        bail!("opencode exited with {status}");
    }
    Ok(())
}

const CLIENT_SESSION_FILE: &str = "client.json";

#[derive(Debug, Serialize, Deserialize)]
struct ClientSessionFile {
    version: u8,
    relay_url: String,
    room: String,
    token: String,
    host_public_key: String,
    device_name: String,
}

async fn run_invite(args: InviteArgs) -> Result<()> {
    let token = match args.token {
        Some(token) => {
            validate_token(&token).context("invalid --token")?;
            token
        }
        None => bail!("invite requires --token or OCT_TOKEN so the host can use the same room"),
    };
    let dir = resolve_state_dir(args.state_dir, "host")?;
    let keystore = if args.use_keyring {
        Keystore::with_keyring(&dir)
    } else {
        Keystore::new(&dir)
    };
    let security =
        HostSecurity::from_keystore(&dir, keystore).context("load host security state")?;
    let invite = Invite::new(
        args.relay,
        args.room,
        token,
        security.identity.public_key(),
        args.ttl_secs,
        args.label,
    )
    .context("create invite")?;
    security.invites.create(&invite).context("store invite")?;
    let uri = invite.encode().context("encode invite")?;
    println!("host_fingerprint={}", security.fingerprint());
    if let Some(path) = args.output {
        write_private_text(&path, &uri)?;
        println!("invite_file={}", path.display());
    } else {
        println!("pairing_uri={uri}");
    }
    Ok(())
}

fn write_private_text(path: &std::path::Path, value: &str) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("create invite directory")?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).context("open invite output")?;
    file.write_all(value.as_bytes())
        .context("write invite output")?;
    Ok(())
}

async fn run_pair(args: PairArgs) -> Result<()> {
    let invite_value = if let Some(path) = args.invite_file {
        std::fs::read_to_string(path).context("read invite file")?
    } else if args.invite_stdin {
        std::io::read_to_string(std::io::stdin()).context("read invite from stdin")?
    } else {
        args.invite
            .context("provide an invite URI, --invite-file, or --invite-stdin")?
    };
    let invite = Invite::decode(invite_value.trim()).context("invalid or expired invite")?;
    let host_key = invite.host_public_key().context("invite host key")?;
    let dir = resolve_state_dir(args.state_dir, "client")?;
    let keystore = if args.use_keyring {
        Keystore::with_keyring(&dir)
    } else {
        Keystore::new(&dir)
    };
    let identity = keystore
        .load_or_create_identity()
        .context("load or create client identity")?;
    let device_name = args.name.unwrap_or_else(|| "paired-device".to_owned());
    let relay_scheme = url::Url::parse(&invite.relay_url)
        .context("parse invite relay URL")?
        .scheme()
        .to_owned();
    let allow_plaintext = relay_scheme == "ws";
    let conn = WsConnection::connect(
        &invite.relay_url,
        WsOptions {
            allow_plaintext,
            ..WsOptions::default()
        },
    )
    .await
    .context("connect relay for pairing")?;
    let hello = RelayControl::Hello {
        protocol: RELAY_PROTOCOL,
        room: invite.room.clone(),
        role: RelayRole::Client,
        token: invite.token.clone(),
        client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    };
    oct_transport::register(&conn, hello, Duration::from_secs(10))
        .await
        .context("register pairing client")?;
    tokio::time::timeout(
        Duration::from_secs(30),
        oct_transport::wait_for_peer(&conn, Duration::from_secs(30)),
    )
    .await
    .context("wait for host to join pairing room")?
    .context("wait for host")?;

    let session = tokio::time::timeout(
        Duration::from_secs(10),
        oct_security::client_handshake(&conn, &identity, &host_key),
    )
    .await
    .context("pairing Noise handshake timed out")?
    .context("pairing Noise handshake failed")?;
    conn.install_noise(Arc::new(session));

    let prelude = ClientPrelude::new(device_name.clone(), Some(invite.secret.clone()));
    conn.send_binary(Bytes::from(prelude.encode().context("encode prelude")?))
        .await
        .context("send pairing prelude")?;
    let response = tokio::time::timeout(Duration::from_secs(10), recv_host_prelude(&conn))
        .await
        .context("pairing response timed out")?
        .context("receive pairing response")?;
    if !response.accepted {
        bail!(
            "host rejected pairing: {}",
            response.reason.unwrap_or_else(|| "not authorized".into())
        );
    }

    let session_file = ClientSessionFile {
        version: 1,
        relay_url: invite.relay_url.clone(),
        room: invite.room.clone(),
        token: invite.token.clone(),
        host_public_key: public_key_hex(&host_key),
        device_name,
    };
    keystore
        .write_devices(CLIENT_SESSION_FILE, &session_file)
        .context("save paired client state")?;
    conn.close().await;
    println!(
        "paired_host_fingerprint={}",
        oct_security::fingerprint(&host_key)
    );
    println!("client_state_dir={}", dir.display());
    Ok(())
}

async fn recv_host_prelude(conn: &WsConnection) -> Result<HostPrelude> {
    loop {
        match conn.recv().await.context("receive pairing message")? {
            Some(oct_transport::WsMessage::Binary(bytes)) => {
                return HostPrelude::decode(&bytes).context("decode pairing response");
            }
            Some(oct_transport::WsMessage::Text(text)) => {
                if let Ok(RelayControl::Ping) = RelayControl::decode(&text) {
                    if let Ok(pong) = RelayControl::Pong.encode() {
                        let _ = conn.send_text(pong).await;
                    }
                    continue;
                }
                bail!("unexpected relay control during pairing");
            }
            None => bail!("relay closed during pairing"),
        }
    }
}

async fn run_devices(args: DevicesArgs) -> Result<()> {
    let dir = resolve_state_dir(args.state_dir, "host")?;
    let devices = DeviceStore::new(&dir)
        .load()
        .context("load device allowlist")?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
        return Ok(());
    }
    if devices.is_empty() {
        println!("no paired devices in {}", dir.display());
        return Ok(());
    }
    println!(
        "{:<18} {:<24} {:<8} {:<10} KEY",
        "ID", "NAME", "ROLE", "STATUS"
    );
    for device in devices {
        let key = device.public_key.get(..16).unwrap_or(&device.public_key);
        println!(
            "{:<18} {:<24} {:<8} {:<10} {}…",
            device.id,
            device.name,
            match device.role {
                oct_security::DeviceRole::Writer => "writer",
                oct_security::DeviceRole::Observer => "observer",
            },
            if device.revoked { "revoked" } else { "active" },
            key
        );
    }
    Ok(())
}

async fn run_revoke(args: RevokeArgs) -> Result<()> {
    let dir = resolve_state_dir(args.state_dir, "host")?;
    let store = DeviceStore::new(&dir);
    let revoked = store
        .revoke(&args.device)
        .context("load or update device allowlist")?;
    match revoked {
        Some(device) => {
            println!("revoked={} name={}", device.id, device.name);
            if args.terminate_active {
                println!("active sessions are closed by the running host within a few seconds");
            }
            Ok(())
        }
        None => bail!("device not found or already revoked"),
    }
}

fn resolve_state_dir(value: Option<PathBuf>, role: &str) -> Result<PathBuf> {
    if let Some(value) = value {
        return Ok(value);
    }
    if let Some(base) = std::env::var_os("OCT_STATE_DIR") {
        return Ok(PathBuf::from(base).join(role));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .context("cannot determine state directory; set --state-dir or HOME")?;
    Ok(base.join("oct").join(role))
}

async fn run_status(args: RelayOnlyArgs) -> Result<()> {
    let health = relay_health_url(&args.relay)?;
    let response = reqwest::get(health).await.context("query relay health")?;
    if !response.status().is_success() {
        bail!("relay health returned {}", response.status());
    }
    let body: serde_json::Value = response.json().await.context("decode relay health")?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

async fn run_doctor(args: RelayOnlyArgs) -> Result<()> {
    let health = relay_health_url(&args.relay)?;
    let response = reqwest::get(health).await.context("relay is unreachable")?;
    if !response.status().is_success() {
        bail!("relay health returned {}", response.status());
    }
    let body: serde_json::Value = response.json().await.context("decode relay health")?;
    println!("relay: ok");
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

fn relay_health_url(relay: &str) -> Result<String> {
    let url = url::Url::parse(relay).context("parse relay URL")?;
    if !matches!(url.scheme(), "ws" | "wss" | "http" | "https") {
        bail!("relay URL must use ws, wss, http, or https");
    }
    let scheme = if matches!(url.scheme(), "ws" | "http") {
        "http"
    } else {
        "https"
    };
    let host = url.host_str().context("relay URL has no host")?;
    let port = url
        .port_or_known_default()
        .context("relay URL has no port")?;
    Ok(format!("{scheme}://{host}:{port}/healthz"))
}

fn resolve_token(token: Option<String>) -> Result<String> {
    match token {
        Some(token) => {
            validate_token(&token).context("invalid --token")?;
            Ok(token)
        }
        None => {
            let (_, token) = generate_room_credentials();
            eprintln!("one-time room token (share with the other endpoint): {token}");
            Ok(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_url_accepts_relay_urls() {
        assert_eq!(
            relay_health_url("ws://127.0.0.1:8080/oct/v1").unwrap(),
            "http://127.0.0.1:8080/healthz"
        );
        assert_eq!(
            relay_health_url("wss://relay.example/oct/v1").unwrap(),
            "https://relay.example:443/healthz"
        );
    }

    #[test]
    fn rejects_unsupported_health_scheme() {
        assert!(relay_health_url("ftp://127.0.0.1:8080").is_err());
    }
}
