use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Extension;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use oct_protocol::relay::{RelayControl, RelayRole, MAX_CONTROL_BYTES, RELAY_PROTOCOL};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::RelayConfig;
use crate::metrics::Metrics;
use crate::rooms::{Outbound, Rooms, SharedRooms, OUTBOUND_QUEUE};
use crate::RelayError;

/// A bound relay. Call [`Relay::serve`] to accept connections.
pub struct Relay {
    listener: TcpListener,
    config: RelayConfig,
    rooms: SharedRooms,
    state: Arc<RelayState>,
}

struct RelayState {
    config: RelayConfig,
    rooms: SharedRooms,
    metrics: Arc<Metrics>,
    next_conn_id: AtomicU64,
    connections: ConnectionRate,
}

struct ConnectionRate {
    state: std::sync::Mutex<(f64, Instant)>,
    rate: f64,
    burst: f64,
}

impl ConnectionRate {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            state: std::sync::Mutex::new((burst as f64, Instant::now())),
            rate: rate as f64,
            burst: burst as f64,
        }
    }

    fn allow(&self) -> bool {
        let mut state = self.state.lock().expect("connection rate lock");
        let now = Instant::now();
        let elapsed = now.duration_since(state.1).as_secs_f64();
        state.0 = (state.0 + elapsed * self.rate).min(self.burst);
        state.1 = now;
        if state.0 >= 1.0 {
            state.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Relay {
    pub async fn bind(config: RelayConfig) -> Result<Self, RelayError> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen).await?;
        let rooms: SharedRooms = Arc::new(Rooms::new(
            config.max_connections_per_room,
            config.room_idle_timeout,
        ));
        let metrics = Arc::new(Metrics::default());
        let state = Arc::new(RelayState {
            config: config.clone(),
            rooms: Arc::clone(&rooms),
            metrics: Arc::clone(&metrics),
            next_conn_id: AtomicU64::new(1),
            connections: ConnectionRate::new(
                config.connection_rate_per_sec,
                config.connection_burst,
            ),
        });
        Ok(Self {
            listener,
            config,
            rooms,
            state,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap_or(self.config.listen)
    }

    pub async fn serve(self, shutdown: CancellationToken) -> Result<(), RelayError> {
        let state = Arc::clone(&self.state);
        let cleanup = tokio::spawn(cleanup_loop(
            Arc::clone(&self.rooms),
            self.config.cleanup_interval,
            shutdown.clone(),
        ));
        let app = Router::new()
            .route("/oct/v1", get(ws_handler))
            .route("/healthz", get(healthz))
            .route("/metrics", get(metrics))
            .layer(Extension(shutdown.clone()))
            .with_state(state);

        let result = axum::serve(self.listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await;
        cleanup.abort();
        result.map_err(RelayError::Io)
    }
}

async fn healthz(State(state): State<Arc<RelayState>>) -> impl IntoResponse {
    let snapshot = state.metrics.snapshot();
    let rooms = state.rooms.room_count().await;
    Json(serde_json::json!({
        "ok": true,
        "protocol": RELAY_PROTOCOL,
        "rooms": rooms,
        "metrics": {
            "connections_total": snapshot.connections_total,
            "connections_active": snapshot.connections_active,
            "joins_total": snapshot.joins_total,
            "rejects_total": snapshot.rejects_total,
            "frames_forwarded_total": snapshot.frames_forwarded_total,
            "bytes_forwarded_total": snapshot.bytes_forwarded_total,
            "peer_left_total": snapshot.peer_left_total,
        }
    }))
}

async fn metrics(State(state): State<Arc<RelayState>>) -> impl IntoResponse {
    let snapshot = state.metrics.snapshot();
    let rooms = state.rooms.room_count().await;
    let body = format!(
        "# HELP oct_rooms Current relay rooms.\n# TYPE oct_rooms gauge\noct_rooms {rooms}\n\
         # HELP oct_connections_total Accepted relay connections.\n# TYPE oct_connections_total counter\noct_connections_total {}\n\
         # HELP oct_connections_active Currently open relay connections.\n# TYPE oct_connections_active gauge\noct_connections_active {}\n\
         # HELP oct_joins_total Successful room joins.\n# TYPE oct_joins_total counter\noct_joins_total {}\n\
         # HELP oct_rejects_total Rejected relay connections.\n# TYPE oct_rejects_total counter\noct_rejects_total {}\n\
         # HELP oct_frames_forwarded_total Opaque frames forwarded.\n# TYPE oct_frames_forwarded_total counter\noct_frames_forwarded_total {}\n\
         # HELP oct_bytes_forwarded_total Opaque bytes forwarded.\n# TYPE oct_bytes_forwarded_total counter\noct_bytes_forwarded_total {}\n\
         # HELP oct_peer_left_total Peer-left events.\n# TYPE oct_peer_left_total counter\noct_peer_left_total {}\n",
        snapshot.connections_total, snapshot.connections_active, snapshot.joins_total,
        snapshot.rejects_total, snapshot.frames_forwarded_total,
        snapshot.bytes_forwarded_total, snapshot.peer_left_total
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

async fn ws_handler(
    State(state): State<Arc<RelayState>>,
    Extension(shutdown): Extension<CancellationToken>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if !state.connections.allow() {
        state.metrics.reject();
        return (StatusCode::TOO_MANY_REQUESTS, "relay connection rate limit").into_response();
    }
    let limit = state.config.max_frame_bytes.max(MAX_CONTROL_BYTES);
    ws.max_message_size(limit)
        .max_frame_size(limit)
        .on_upgrade(move |socket| handle_socket(state, socket, shutdown))
        .into_response()
}

async fn handle_socket(state: Arc<RelayState>, socket: WebSocket, shutdown: CancellationToken) {
    state.metrics.connection_opened();
    let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Outbound>(OUTBOUND_QUEUE);

    let writer = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            match out {
                Outbound::Text(text) => {
                    if sink.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Outbound::Binary(bytes) => {
                    if sink.send(Message::Binary(bytes)).await.is_err() {
                        break;
                    }
                }
                Outbound::Close => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });

    let hello = match read_hello(&state.config, &mut stream).await {
        Ok(hello) => hello,
        Err(err) => {
            state.metrics.reject();
            let code = match err {
                RelayError::HelloTimeout => "HELLO_TIMEOUT",
                RelayError::Oversized => "OVER_LIMIT",
                RelayError::InvalidToken => "UNAUTHORIZED",
                RelayError::RoleOccupied => "ROLE_OCCUPIED",
                RelayError::RoomFull => "ROOM_FULL",
                _ => "BAD_REQUEST",
            };
            let _ = send_error(&tx, code, &err.to_string()).await;
            let _ = tx.send(Outbound::Close).await;
            drop(tx);
            let _ = writer.await;
            state.metrics.connection_closed();
            return;
        }
    };

    let HelloFields {
        room_id,
        role,
        token,
    } = hello;

    let join = match state
        .rooms
        .join(&room_id, role, &token, conn_id, tx.clone())
        .await
    {
        Ok(join) => join,
        Err(err) => {
            state.metrics.reject();
            let code = match err {
                RelayError::InvalidToken => "UNAUTHORIZED",
                RelayError::RoleOccupied => "ROLE_OCCUPIED",
                RelayError::RoomFull => "ROOM_FULL",
                _ => "BAD_REQUEST",
            };
            let _ = send_error(&tx, code, &err.to_string()).await;
            let _ = tx.send(Outbound::Close).await;
            drop(tx);
            let _ = writer.await;
            state.metrics.connection_closed();
            return;
        }
    };
    state.metrics.join();

    let ready = RelayControl::Ready {
        protocol: RELAY_PROTOCOL,
        room: room_id.clone(),
        role,
    };
    if let Ok(text) = ready.encode() {
        let _ = tx.send(Outbound::Text(text)).await;
    }

    if let Some(peer_role) = join.peer_joined {
        let joined = RelayControl::PeerJoined { role: peer_role };
        if let Ok(text) = joined.encode() {
            let _ = tx.send(Outbound::Text(text)).await;
        }
    }

    let max_frame = state.config.max_frame_bytes;
    let mut reason = "closed";
    loop {
        let msg = tokio::select! {
            _ = shutdown.cancelled() => {
                reason = "shutdown";
                None
            }
            msg = stream.next() => msg,
        };
        let Some(msg) = msg else {
            break;
        };
        match msg {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_CONTROL_BYTES {
                    state.metrics.reject();
                    reason = "oversized control";
                    break;
                }
                match RelayControl::decode(text.as_str()) {
                    Ok(RelayControl::Ping) => {
                        if let Ok(pong) = RelayControl::Pong.encode() {
                            let _ = tx.send(Outbound::Text(pong)).await;
                        }
                    }
                    Ok(RelayControl::Pong) => {}
                    Ok(RelayControl::Error { .. }) => {}
                    Ok(_) => {
                        state.metrics.reject();
                        reason = "unexpected control";
                        break;
                    }
                    Err(_) => {
                        state.metrics.reject();
                        reason = "invalid control";
                        break;
                    }
                }
            }
            Ok(Message::Binary(bytes)) => {
                if bytes.len() > max_frame {
                    state.metrics.reject();
                    reason = "oversized binary";
                    break;
                }
                if let Some(peer_tx) = state.rooms.peer_tx(&room_id, role).await {
                    let len = bytes.len();
                    if peer_tx.send(Outbound::Binary(bytes)).await.is_err() {
                        reason = "peer writer closed";
                        break;
                    }
                    state.metrics.forwarded(len);
                } else {
                    // No peer yet: drop. The endpoint's mux will retry or the
                    // connection will be replaced on reconnect.
                    debug!(role = role.label(), "binary frame with no peer");
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) => {
                // WebSocket-level keepalive only; no application meaning.
            }
            Err(err) => {
                debug!(error = %err, "websocket read error");
                break;
            }
        }
    }

    info!(role = role.label(), reason, "relay connection closing");

    if let Some(peer) = state.rooms.leave(&room_id, role, conn_id).await {
        state.metrics.peer_left();
        let _ = send_error(&peer.tx, "PEER_LEFT", "tunnel peer disconnected").await;
        let _ = peer.tx.send(Outbound::Close).await;
    }
    drop(tx);
    let _ = writer.await;
    state.metrics.connection_closed();
}

struct HelloFields {
    room_id: String,
    role: RelayRole,
    token: String,
}

async fn read_hello(
    config: &RelayConfig,
    stream: &mut futures_util::stream::SplitStream<WebSocket>,
) -> Result<HelloFields, RelayError> {
    let first = tokio::time::timeout(config.hello_timeout, stream.next())
        .await
        .map_err(|_| RelayError::HelloTimeout)?
        .ok_or(RelayError::InvalidHello)?;
    let text = match first {
        Ok(Message::Text(text)) => text,
        Ok(Message::Binary(_)) => return Err(RelayError::InvalidHello),
        Ok(_) => return Err(RelayError::InvalidHello),
        Err(_) => return Err(RelayError::InvalidHello),
    };
    if text.len() > MAX_CONTROL_BYTES {
        return Err(RelayError::Oversized);
    }
    let control = RelayControl::decode(text.as_str())?;
    control.validate_hello().map_err(RelayError::Control)?;
    let RelayControl::Hello {
        room, role, token, ..
    } = control
    else {
        return Err(RelayError::InvalidHello);
    };
    Ok(HelloFields {
        room_id: room,
        role,
        token,
    })
}

async fn send_error(tx: &mpsc::Sender<Outbound>, code: &str, message: &str) -> Result<(), ()> {
    let text = RelayControl::Error {
        code: code.to_owned(),
        message: message.to_owned(),
    }
    .encode()
    .map_err(|_| ())?;
    tx.send(Outbound::Text(text)).await.map_err(|_| ())
}

async fn cleanup_loop(
    rooms: SharedRooms,
    interval: std::time::Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                let senders = rooms.evict_idle(Instant::now()).await;
                for tx in senders {
                    warn!("evicting idle relay room");
                    let _ = tx.send(Outbound::Close).await;
                }
            }
        }
    }
}
