use std::sync::Arc;
use std::time::Duration;

use oct_protocol::relay::{RelayControl, RelayRole, RELAY_PROTOCOL};
use oct_protocol::Role;
use oct_security::{ClientSecurity, HostPrelude, SecurityError};
use oct_transport::{Backoff, Mux, MuxConfig, NoopHandler, WsConnection, WsOptions};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use url::Url;

const RELAY_READY_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const MUX_READY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_STREAMS: usize = 128;

pub(crate) struct ConnectionParams {
    pub relay: Url,
    pub room: String,
    pub token: String,
    pub connect_timeout: Duration,
    pub security: Option<Arc<ClientSecurity>>,
}

pub(crate) async fn run_connection_loop(
    params: ConnectionParams,
    current_mux: watch::Sender<Option<Mux>>,
    connected: watch::Sender<bool>,
    shutdown: CancellationToken,
) {
    let ConnectionParams {
        relay,
        room,
        token,
        connect_timeout,
        security,
    } = params;
    let mut backoff = Backoff::default();
    loop {
        if shutdown.is_cancelled() {
            current_mux.send_replace(None);
            connected.send_replace(false);
            return;
        }

        let options = WsOptions {
            connect_timeout,
            allow_plaintext: relay.scheme() == "ws",
            ..WsOptions::default()
        };
        let conn = match WsConnection::connect(relay.as_str(), options).await {
            Ok(conn) => conn,
            Err(_) => {
                if backoff.sleep(&shutdown).await.is_err() {
                    current_mux.send_replace(None);
                    connected.send_replace(false);
                    return;
                }
                continue;
            }
        };

        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: room.clone(),
            role: RelayRole::Client,
            token: token.clone(),
            client_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        };
        if oct_transport::register(&conn, hello, RELAY_READY_TIMEOUT)
            .await
            .is_err()
        {
            conn.close().await;
            if backoff.sleep(&shutdown).await.is_err() {
                current_mux.send_replace(None);
                connected.send_replace(false);
                return;
            }
            continue;
        }

        let peer = tokio::select! {
            _ = shutdown.cancelled() => {
                conn.close().await;
                current_mux.send_replace(None);
                connected.send_replace(false);
                return;
            }
            result = oct_transport::wait_for_peer(&conn, PEER_WAIT_TIMEOUT) => result,
        };
        if peer.is_err() {
            conn.close().await;
            if backoff.sleep(&shutdown).await.is_err() {
                current_mux.send_replace(None);
                connected.send_replace(false);
                return;
            }
            continue;
        }

        if let Some(security) = &security {
            let handshake = tokio::time::timeout(
                Duration::from_secs(10),
                oct_security::client_handshake(&conn, &security.identity, &security.pinned_host),
            )
            .await;
            let session = match handshake {
                Ok(Ok(session)) => session,
                Ok(Err(SecurityError::HostKeyMismatch)) => {
                    tracing::warn!(
                        "host identity mismatch: pinned host key did not match the relay peer"
                    );
                    conn.close().await;
                    if backoff.sleep(&shutdown).await.is_err() {
                        current_mux.send_replace(None);
                        connected.send_replace(false);
                        return;
                    }
                    continue;
                }
                _ => {
                    conn.close().await;
                    if backoff.sleep(&shutdown).await.is_err() {
                        current_mux.send_replace(None);
                        connected.send_replace(false);
                        return;
                    }
                    continue;
                }
            };
            conn.install_noise(Arc::new(session));
            let prelude = security.prelude();
            let accepted = tokio::time::timeout(Duration::from_secs(10), async {
                let encoded = prelude.encode().map_err(|_| ())?;
                conn.send_binary(bytes::Bytes::from(encoded))
                    .await
                    .map_err(|_| ())?;
                loop {
                    match conn.recv().await.map_err(|_| ())? {
                        Some(oct_transport::WsMessage::Binary(bytes)) => {
                            return HostPrelude::decode(&bytes).map_err(|_| ());
                        }
                        Some(oct_transport::WsMessage::Text(text)) => {
                            if let Ok(oct_protocol::relay::RelayControl::Ping) =
                                oct_protocol::relay::RelayControl::decode(&text)
                            {
                                if let Ok(pong) = oct_protocol::relay::RelayControl::Pong.encode() {
                                    let _ = conn.send_text(pong).await;
                                }
                                continue;
                            }
                            return Err(());
                        }
                        None => return Err(()),
                    }
                }
            })
            .await;
            match accepted {
                Ok(Ok(response)) if response.accepted => security.enrollment_accepted(),
                _ => {
                    conn.close().await;
                    if backoff.sleep(&shutdown).await.is_err() {
                        current_mux.send_replace(None);
                        connected.send_replace(false);
                        return;
                    }
                    continue;
                }
            }
        }

        let mux = Mux::new(
            conn,
            MuxConfig {
                role: Role::Client,
                epoch: rand::random::<u64>().max(1),
                max_streams: MAX_STREAMS,
                ping_interval: Some(Duration::from_secs(20)),
                idle_timeout: Duration::from_secs(120),
            },
            std::sync::Arc::new(NoopHandler),
        );
        if mux.wait_ready(MUX_READY_TIMEOUT).await.is_err() {
            mux.close().await;
            if backoff.sleep(&shutdown).await.is_err() {
                current_mux.send_replace(None);
                connected.send_replace(false);
                return;
            }
            continue;
        }

        backoff.reset();
        current_mux.send_replace(Some(mux.clone()));
        connected.send_replace(true);
        tokio::select! {
            _ = shutdown.cancelled() => {
                mux.close().await;
                current_mux.send_replace(None);
                connected.send_replace(false);
                return;
            }
            _ = mux.wait_closed() => {
                current_mux.send_replace(None);
                connected.send_replace(false);
            }
        }

        if shutdown.is_cancelled() {
            connected.send_replace(false);
            return;
        }
        if backoff.sleep(&shutdown).await.is_err() {
            current_mux.send_replace(None);
            connected.send_replace(false);
            return;
        }
    }
}
