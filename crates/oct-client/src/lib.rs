//! Loopback-only authenticated gateway and outbound tunnel client.

mod auth;
mod connection;
mod gateway;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use oct_protocol::relay::{validate_room, validate_token};
use oct_security::ClientSecurity;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::auth::AuthState;
use crate::connection::{run_connection_loop, ConnectionParams};
use crate::gateway::{build_router, GatewayState};

pub struct ClientConfig {
    pub relay_url: String,
    pub room: String,
    pub token: String,
    pub gateway_bind: SocketAddr,
    pub connect_timeout: Duration,
    /// Phase 2 endpoint encryption. When `None`, Phase 1 plaintext transport
    /// is used and the relay must be loopback.
    pub security: Option<Arc<ClientSecurity>>,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid client configuration: {0}")]
    InvalidConfig(String),
    #[error("failed to bind local gateway: {0}")]
    Bind(#[from] std::io::Error),
}

pub struct GatewayHandle {
    pub addr: SocketAddr,
    pub local_url: String,
    /// Per-run password for the local OpenCode client. Do not persist or log.
    pub password: String,
    pub shutdown: CancellationToken,
    connected: tokio::sync::watch::Receiver<bool>,
}

impl GatewayHandle {
    /// Wait until the first mux handshake completes. Returns `false` on
    /// timeout, in which case the caller may still start the TUI and let it
    /// observe explicit `HOST_OFFLINE`/503 responses.
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        let mut connected = self.connected.clone();
        if *connected.borrow() {
            return true;
        }
        let wait = async {
            loop {
                if *connected.borrow() {
                    return;
                }
                if connected.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.is_ok()
    }
}

impl fmt::Debug for GatewayHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayHandle")
            .field("addr", &self.addr)
            .field("local_url", &self.local_url)
            .field("password", &"<redacted>")
            .field("shutdown", &"<cancellation token>")
            .field("connected", &"<watch>")
            .finish()
    }
}

pub struct TunnelClient {
    config: ClientConfig,
    relay: Url,
}

impl TunnelClient {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        validate_room(&config.room)
            .map_err(|_| ClientError::InvalidConfig("invalid room id".into()))?;
        validate_token(&config.token)
            .map_err(|_| ClientError::InvalidConfig("invalid room token".into()))?;
        if config.gateway_bind.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
            return Err(ClientError::InvalidConfig(
                "gateway must bind to 127.0.0.1".into(),
            ));
        }

        let relay = Url::parse(&config.relay_url)
            .map_err(|_| ClientError::InvalidConfig("invalid relay URL".into()))?;
        validate_relay(&relay, config.security.is_some())?;
        Ok(Self { config, relay })
    }

    /// Bind the local gateway before starting the reconnect supervisor. The
    /// returned password is generated per run and is intended only for the
    /// child `opencode --server` process environment.
    pub async fn start(
        self,
        parent_shutdown: CancellationToken,
    ) -> Result<GatewayHandle, ClientError> {
        let listener = TcpListener::bind(self.config.gateway_bind).await?;
        let addr = listener.local_addr()?;
        let password = generate_password();
        let auth = AuthState::new(&password);
        let shutdown = parent_shutdown.child_token();
        let (mux_tx, mux_rx) = tokio::sync::watch::channel(None);
        let (connected_tx, connected_rx) = tokio::sync::watch::channel(false);
        let state = GatewayState {
            mux: mux_rx,
            port: addr.port(),
        };
        let router = build_router(state, auth);

        let server_shutdown = shutdown.child_token();
        tokio::spawn(async move {
            let serve = axum::serve(listener, router)
                .with_graceful_shutdown(server_shutdown.cancelled_owned());
            if serve.await.is_err() {
                tracing::error!("local gateway server stopped unexpectedly");
            }
        });

        let task_shutdown = shutdown.child_token();
        let relay = self.relay;
        let room = self.config.room;
        let token = self.config.token;
        let connect_timeout = self.config.connect_timeout;
        let security = self.config.security;
        tokio::spawn(async move {
            run_connection_loop(
                ConnectionParams {
                    relay,
                    room,
                    token,
                    connect_timeout,
                    security,
                },
                mux_tx,
                connected_tx,
                task_shutdown,
            )
            .await;
        });

        Ok(GatewayHandle {
            addr,
            local_url: format!("http://127.0.0.1:{}", addr.port()),
            password,
            shutdown,
            connected: connected_rx,
        })
    }
}

fn validate_relay(url: &Url, allow_public: bool) -> Result<(), ClientError> {
    if !matches!(url.scheme(), "ws" | "wss")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::InvalidConfig(
            "Phase 1 relay must be a ws(s) URL without userinfo, query, or fragment".into(),
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !loopback && (!allow_public || url.scheme() != "wss") {
        return Err(ClientError::InvalidConfig(
            "non-loopback relay requires E2EE and wss://".into(),
        ));
    }
    Ok(())
}

fn generate_password() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rand::RngCore;

    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oct_protocol::relay::generate_room_credentials;

    fn config(bind: SocketAddr, relay_url: &str) -> ClientConfig {
        let (room, token) = generate_room_credentials();
        ClientConfig {
            relay_url: relay_url.into(),
            room,
            token,
            gateway_bind: bind,
            connect_timeout: Duration::from_secs(5),
            security: None,
        }
    }

    #[test]
    fn rejects_non_loopback_bind_and_relay() {
        assert!(TunnelClient::new(config(
            "0.0.0.0:0".parse().unwrap(),
            "ws://127.0.0.1:8080/oct/v1"
        ))
        .is_err());
        assert!(TunnelClient::new(config(
            "127.0.0.1:0".parse().unwrap(),
            "wss://relay.example.com/oct/v1"
        ))
        .is_err());
    }

    #[test]
    fn e2ee_allows_a_public_wss_relay() {
        let identity = oct_security::Identity::generate();
        let security = Arc::new(ClientSecurity::new(identity, [7u8; 32], "test", None));
        let mut config = config(
            "127.0.0.1:0".parse().unwrap(),
            "wss://relay.example.com/oct/v1",
        );
        config.security = Some(security);
        assert!(TunnelClient::new(config).is_ok());
    }

    #[tokio::test]
    async fn start_binds_before_any_relay_connection_and_redacts_password() {
        let client = TunnelClient::new(config(
            "127.0.0.1:0".parse().unwrap(),
            "ws://127.0.0.1:1/oct/v1",
        ))
        .unwrap();
        let shutdown = CancellationToken::new();
        let handle = client.start(shutdown.clone()).await.unwrap();
        assert_eq!(handle.addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(handle.local_url.ends_with(&handle.addr.port().to_string()));
        assert_eq!(handle.password.len(), 43);
        assert!(!handle.wait_connected(Duration::from_millis(100)).await);
        let debug = format!("{handle:?}");
        assert!(!debug.contains(&handle.password));
        handle.shutdown.cancel();
        shutdown.cancel();
    }

    #[tokio::test]
    async fn gateway_authenticates_every_route_and_rejects_bad_origin() {
        let client = TunnelClient::new(config(
            "127.0.0.1:0".parse().unwrap(),
            "ws://127.0.0.1:1/oct/v1",
        ))
        .unwrap();
        let handle = client.start(CancellationToken::new()).await.unwrap();
        let http = reqwest::Client::new();

        let unauthorized = http
            .get(format!("{}/not-a-route", handle.local_url))
            .send()
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

        let offline = http
            .get(format!("{}/api/info", handle.local_url))
            .basic_auth("opencode", Some(&handle.password))
            .send()
            .await
            .unwrap();
        assert_eq!(offline.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            offline.headers().get("x-oct-error").unwrap(),
            "HOST_OFFLINE"
        );

        let forbidden_origin = http
            .get(format!("{}/api/info", handle.local_url))
            .basic_auth("opencode", Some(&handle.password))
            .header("origin", "http://attacker.example")
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden_origin.status(), reqwest::StatusCode::FORBIDDEN);

        let offline_ws = http
            .get(format!("{}/pty", handle.local_url))
            .basic_auth("opencode", Some(&handle.password))
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .send()
            .await
            .unwrap();
        assert_eq!(
            offline_ws.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            offline_ws.headers().get("x-oct-error").unwrap(),
            "HOST_OFFLINE"
        );

        handle.shutdown.cancel();
    }
}
