use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use oct_protocol::relay::{validate_room, validate_token, RelayControl, RelayRole, RELAY_PROTOCOL};
use oct_protocol::Role;
use oct_security::{ClientPrelude, HostPrelude, HostSecurity, SecurityError};
use oct_transport::{
    Backoff, Mux, MuxConfig, OpenHandler, TransportError, WsConnection, WsOptions,
};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::BackendProxy;

const RELAY_READY_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const MUX_READY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAMS: usize = 128;

pub struct HostConfig {
    pub relay_url: String,
    pub room: String,
    pub token: String,
    pub upstream_url: String,
    pub backend_password: Option<String>,
    pub ping_interval: Duration,
    pub reconnect_max: Duration,
    /// Phase 2 endpoint encryption and device authorization. When `None`, the
    /// loopback-only Phase 1 behavior is used.
    pub security: Option<Arc<HostSecurity>>,
}

impl fmt::Debug for HostConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostConfig")
            .field("relay_url", &"<redacted>")
            .field("room", &self.room)
            .field("token", &"<redacted>")
            .field("upstream_url", &"<fixed loopback origin>")
            .field(
                "backend_password",
                &self.backend_password.as_ref().map(|_| "<redacted>"),
            )
            .field("ping_interval", &self.ping_interval)
            .field("reconnect_max", &self.reconnect_max)
            .field("e2ee", &self.security.is_some())
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("invalid host configuration: {0}")]
    InvalidConfig(String),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("failed to initialize upstream HTTP client")]
    HttpClient,
    #[error("security error: {0}")]
    Security(#[from] SecurityError),
}

pub struct HostAgent {
    config: HostConfig,
    relay: Url,
    proxy: Arc<BackendProxy>,
    security: Option<Arc<HostSecurity>>,
}

impl HostAgent {
    pub fn new(config: HostConfig) -> Result<Self, HostError> {
        validate_room(&config.room)
            .map_err(|_| HostError::InvalidConfig("invalid room id".into()))?;
        validate_token(&config.token)
            .map_err(|_| HostError::InvalidConfig("invalid room token".into()))?;

        let relay = Url::parse(&config.relay_url)
            .map_err(|_| HostError::InvalidConfig("invalid relay URL".into()))?;
        validate_websocket_url(&relay, config.security.is_some())?;

        let upstream = Url::parse(&config.upstream_url)
            .map_err(|_| HostError::InvalidConfig("invalid upstream URL".into()))?;
        validate_upstream_origin(&upstream)?;

        let proxy = Arc::new(BackendProxy::new(
            upstream,
            config.backend_password.clone(),
        )?);
        let security = config.security.clone();
        Ok(Self {
            config,
            relay,
            proxy,
            security,
        })
    }

    /// Connect outbound to the loopback-only Phase 1 relay, serve until the
    /// carrier fails, and reconnect with jitter. Backend process ownership is
    /// deliberately outside this lifecycle.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), HostError> {
        let mut backoff = Backoff::new(Duration::from_secs(1), self.config.reconnect_max);
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }

            match self.run_connection(&shutdown).await {
                ConnectionExit::Shutdown => return Ok(()),
                ConnectionExit::Retry => {
                    tracing::warn!("host relay connection ended; retrying");
                    if backoff.sleep(&shutdown).await.is_err() {
                        return Ok(());
                    }
                }
                ConnectionExit::Fatal(error) => return Err(error),
            }
        }
    }

    async fn run_connection(&self, shutdown: &CancellationToken) -> ConnectionExit {
        let ws_url = self.relay.as_str();
        let options = WsOptions {
            allow_plaintext: self.relay.scheme() == "ws",
            ..WsOptions::default()
        };
        let conn = match WsConnection::connect(ws_url, options).await {
            Ok(conn) => conn,
            Err(TransportError::InvalidUrl(message)) => {
                return ConnectionExit::Fatal(HostError::InvalidConfig(message));
            }
            Err(_) => return ConnectionExit::Retry,
        };

        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: self.config.room.clone(),
            role: RelayRole::Host,
            token: self.config.token.clone(),
            client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        };
        match oct_transport::register(&conn, hello, RELAY_READY_TIMEOUT).await {
            Ok(_) => {}
            Err(TransportError::RelayRejected { code, .. }) if code == "UNAUTHORIZED" => {
                // A different token can pin the room first (for example, a
                // stale or revoked peer). Treat this as transient instead of
                // exiting: a wrong token must not let a third party stop the
                // host process.
                conn.close().await;
                tracing::warn!("relay rejected host registration (room token mismatch); retrying");
                return ConnectionExit::Retry;
            }
            Err(_) => {
                // ROLE_OCCUPIED/ROOM_FULL/SERVER_BUSY are transient during
                // reconnect; retry with backoff instead of exiting permanently.
                conn.close().await;
                return ConnectionExit::Retry;
            }
        }

        let peer = tokio::select! {
            _ = shutdown.cancelled() => {
                conn.close().await;
                return ConnectionExit::Shutdown;
            }
            result = oct_transport::wait_for_peer(&conn, PEER_WAIT_TIMEOUT) => result,
        };
        if peer.is_err() {
            conn.close().await;
            return if shutdown.is_cancelled() {
                ConnectionExit::Shutdown
            } else {
                ConnectionExit::Retry
            };
        }

        let mut revoke_token = None;
        let mut revoke_watch = None;
        if let Some(security) = &self.security {
            let handshake = tokio::time::timeout(
                Duration::from_secs(10),
                oct_security::host_handshake(&conn, &security.identity),
            )
            .await;
            let session = match handshake {
                Ok(Ok(session)) => session,
                _ => {
                    conn.close().await;
                    return ConnectionExit::Retry;
                }
            };
            let client_key = session.peer_static();
            conn.install_noise(Arc::new(session));

            let prelude =
                match tokio::time::timeout(Duration::from_secs(10), recv_client_prelude(&conn))
                    .await
                {
                    Ok(Ok(prelude)) => prelude,
                    _ => {
                        conn.close().await;
                        return ConnectionExit::Retry;
                    }
                };
            let authorization = security.authorize(&client_key, &prelude);
            let writer_lease = match &authorization {
                Ok(device) => security.acquire_writer(&device.id).ok(),
                Err(_) => None,
            };
            let response = match (&authorization, &writer_lease) {
                (Ok(device), Some(_)) => {
                    HostPrelude::accepted(device.id.clone(), device.name.clone())
                }
                _ => HostPrelude::rejected("device is not authorized or writer is active"),
            };
            if send_host_prelude(&conn, &response).await.is_err() {
                conn.close().await;
                return ConnectionExit::Retry;
            }
            let (device, _writer_lease) = match (authorization, writer_lease) {
                (Ok(device), Some(lease)) => (device, lease),
                _ => {
                    conn.close().await;
                    return ConnectionExit::Retry;
                }
            };
            tracing::debug!(device_id = %device.id, "authorized E2EE client");
            let revoke = CancellationToken::new();
            revoke_token = Some(revoke.clone());
            let watch_security = Arc::clone(security);
            let watch_token = revoke;
            revoke_watch = Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                loop {
                    interval.tick().await;
                    if !watch_security.is_authorized(&client_key) {
                        watch_token.cancel();
                        return;
                    }
                }
            }));
        }

        let epoch = rand::random::<u64>().max(1);
        let handler: Arc<dyn OpenHandler> = self.proxy.clone();
        let mux = Mux::new(
            conn,
            MuxConfig {
                role: Role::Host,
                epoch,
                max_streams: MAX_STREAMS,
                ping_interval: Some(self.config.ping_interval),
                idle_timeout: Duration::from_secs(120),
            },
            handler,
        );

        if mux.wait_ready(MUX_READY_TIMEOUT).await.is_err() {
            mux.close().await;
            if let Some(watch) = revoke_watch {
                watch.abort();
            }
            return if shutdown.is_cancelled() {
                ConnectionExit::Shutdown
            } else {
                ConnectionExit::Retry
            };
        }

        let revoke_cancelled = async {
            match &revoke_token {
                Some(token) => token.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };
        let exit = tokio::select! {
            _ = shutdown.cancelled() => {
                mux.close().await;
                ConnectionExit::Shutdown
            }
            _ = revoke_cancelled => {
                tracing::info!("device revoked; closing active tunnel");
                mux.close().await;
                ConnectionExit::Retry
            }
            _ = mux.wait_closed() => ConnectionExit::Retry,
        };
        if let Some(watch) = revoke_watch {
            watch.abort();
        }
        exit
    }
}

enum ConnectionExit {
    Shutdown,
    Retry,
    Fatal(HostError),
}

fn validate_websocket_url(url: &Url, allow_public: bool) -> Result<(), HostError> {
    if !matches!(url.scheme(), "ws" | "wss")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(HostError::InvalidConfig(
            "relay must be a ws(s) URL without userinfo, query, or fragment".into(),
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !loopback && (!allow_public || url.scheme() != "wss") {
        return Err(HostError::InvalidConfig(
            "non-loopback relay requires E2EE and wss://".into(),
        ));
    }
    Ok(())
}

async fn recv_client_prelude(
    conn: &oct_transport::WsConnection,
) -> Result<ClientPrelude, HostError> {
    loop {
        match conn.recv().await? {
            Some(oct_transport::WsMessage::Binary(bytes)) => {
                return Ok(ClientPrelude::decode(&bytes)?);
            }
            Some(oct_transport::WsMessage::Text(text)) => {
                if let Ok(RelayControl::Ping) = RelayControl::decode(&text) {
                    if let Ok(pong) = RelayControl::Pong.encode() {
                        let _ = conn.send_text(pong).await;
                    }
                    continue;
                }
                return Err(HostError::Security(SecurityError::Protocol));
            }
            None => return Err(HostError::Security(SecurityError::Protocol)),
        }
    }
}

async fn send_host_prelude(
    conn: &oct_transport::WsConnection,
    prelude: &HostPrelude,
) -> Result<(), HostError> {
    conn.send_binary(bytes::Bytes::from(prelude.encode()?))
        .await?;
    Ok(())
}

fn validate_upstream_origin(url: &Url) -> Result<(), HostError> {
    if !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "/" && !url.path().is_empty())
    {
        return Err(HostError::InvalidConfig(
            "upstream must be a fixed http(s) origin without credentials, path, query, or fragment"
                .into(),
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !loopback {
        return Err(HostError::InvalidConfig(
            "upstream origin must be loopback".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oct_protocol::relay::generate_room_credentials;

    fn config(relay_url: &str, upstream_url: &str) -> HostConfig {
        let (room, token) = generate_room_credentials();
        HostConfig {
            relay_url: relay_url.into(),
            room,
            token,
            upstream_url: upstream_url.into(),
            backend_password: Some("not-logged".into()),
            ping_interval: Duration::from_secs(20),
            reconnect_max: Duration::from_secs(30),
            security: None,
        }
    }

    #[test]
    fn accepts_only_loopback_phase_one_endpoints() {
        assert!(HostAgent::new(config(
            "ws://127.0.0.1:8080/oct/v1",
            "http://127.0.0.1:4096"
        ))
        .is_ok());
        assert!(HostAgent::new(config(
            "wss://relay.example.com/oct/v1",
            "http://127.0.0.1:4096"
        ))
        .is_err());
        assert!(
            HostAgent::new(config("ws://127.0.0.1:8080/oct/v1", "http://example.com")).is_err()
        );
    }

    #[test]
    fn rejects_upstream_paths_and_credentials() {
        assert!(HostAgent::new(config(
            "ws://127.0.0.1:8080/oct/v1",
            "http://127.0.0.1:4096/api"
        ))
        .is_err());
        assert!(HostAgent::new(config(
            "ws://127.0.0.1:8080/oct/v1",
            "http://user:pass@127.0.0.1:4096"
        ))
        .is_err());
    }

    #[test]
    fn e2ee_allows_a_public_wss_relay() {
        let dir = tempfile::tempdir().unwrap();
        let security = Arc::new(HostSecurity::load_or_create(dir.path()).unwrap());
        let mut config = config("wss://relay.example.com/oct/v1", "http://127.0.0.1:4096");
        config.security = Some(security);
        assert!(HostAgent::new(config).is_ok());
    }

    #[test]
    fn debug_does_not_expose_secrets_or_urls() {
        let config = config(
            "ws://127.0.0.1:8080/oct/v1?secret=token",
            "http://127.0.0.1:4096",
        );
        let text = format!("{config:?}");
        assert!(!text.contains("secret=token"));
        assert!(!text.contains("not-logged"));
    }
}
