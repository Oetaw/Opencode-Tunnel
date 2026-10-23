use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use oct_protocol::httpwire::{
    decode_open_ws, decode_request_head, decode_reset, decode_response_head, decode_ws_close,
    decode_ws_message, encode_request_head, encode_reset,
};
use oct_protocol::relay::RelayControl;
use oct_protocol::types::valid_stream_id;
use oct_protocol::{
    decode_frame_exact, encode_frame_to_vec, ErrorCode, Feature, Frame, Hello, HttpRequestHead,
    HttpResponseHead, Kind, OpenWs, Role, WsOpcode, MAX_WS_MESSAGE,
};
use tokio::sync::{mpsc, watch};

use crate::stream::{
    Credit, Stream, StreamInit, StreamState, CONNECTION_WINDOW, STREAM_QUEUE, STREAM_WINDOW,
};
use crate::{TransportError, WsConnection, WsMessage};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest frame payload that fits through a 64 KiB Noise transport message:
/// 65535-byte Noise limit minus the 16-byte tag, the 32-byte OCT header, and
/// the one-byte secure envelope type.
pub const SECURE_MAX_FRAME_PAYLOAD: usize = 65_535 - 16 - oct_protocol::types::FRAME_HEADER_LEN - 1;

#[derive(Debug)]
pub enum Inbound {
    /// The response head for an inbound HTTP stream. It must arrive before
    /// response body DATA.
    HttpResponse(HttpResponseHead),
    Data(Bytes),
    End,
    Reset {
        code: ErrorCode,
        reason: String,
    },
    /// One complete reassembled nested WebSocket message. Continuation
    /// fragments are never exposed.
    WsMessage {
        opcode: WsOpcode,
        payload: Bytes,
    },
    /// The peer closed the nested WebSocket.
    WsClose {
        code: Option<u16>,
        reason: String,
    },
}

#[async_trait]
pub trait OpenHandler: Send + Sync {
    async fn on_http(&self, stream: Stream, head: HttpRequestHead);
    async fn on_ws(&self, stream: Stream, head: OpenWs);
}

pub struct NoopHandler;

#[async_trait]
impl OpenHandler for NoopHandler {
    async fn on_http(&self, stream: Stream, _head: HttpRequestHead) {
        let response = HttpResponseHead {
            status: 501,
            headers: vec![("content-type".into(), "text/plain".into())],
        };
        if stream.send_response(response).await.is_err() {
            return;
        }
        let _ = stream
            .send_data(Bytes::from_static(b"no handler configured"))
            .await;
        while let Ok(Some(message)) = stream.recv().await {
            if matches!(message, Inbound::End | Inbound::Reset { .. }) {
                break;
            }
        }
        let _ = stream.finish().await;
    }

    async fn on_ws(&self, stream: Stream, _head: OpenWs) {
        let _ = stream.send_ws_close(Some(1000), "no handler").await;
    }
}

#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub role: Role,
    pub epoch: u64,
    pub max_streams: usize,
    pub ping_interval: Option<Duration>,
    pub idle_timeout: Duration,
}

pub(crate) struct MuxInner {
    pub conn: WsConnection,
    role: Role,
    pub epoch: u64,
    peer_epoch: AtomicU64,
    peer_is_host: AtomicBool,
    negotiated_features: AtomicU64,
    max_frame_payload: usize,
    connection_credit: Arc<Credit>,
    local_hello: Hello,
    pub streams: StdMutex<HashMap<u64, Arc<StreamState>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
    handler: Arc<dyn OpenHandler>,
    max_streams: usize,
    ready_tx: watch::Sender<Option<Hello>>,
    ping_interval: Option<Duration>,
    idle_timeout: Duration,
    last_inbound: StdMutex<Instant>,
}

impl MuxInner {
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn max_frame_payload(&self) -> usize {
        self.max_frame_payload
    }

    fn touch_inbound(&self) {
        *self.last_inbound.lock().expect("last inbound lock") = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_inbound
            .lock()
            .expect("last inbound lock")
            .elapsed()
    }

    pub(crate) fn remove_stream(&self, id: u64) {
        let _ = self.streams.lock().expect("stream map lock").remove(&id);
    }

    fn insert_stream(&self, state: Arc<StreamState>) -> Result<(), TransportError> {
        let mut streams = self.streams.lock().expect("stream map lock");
        if streams.len() >= self.max_streams {
            return Err(TransportError::TooManyStreams);
        }
        if streams.contains_key(&state.id) {
            return Err(TransportError::Internal("duplicate stream id".into()));
        }
        streams.insert(state.id, state);
        Ok(())
    }

    fn stream_count(&self) -> usize {
        self.streams.lock().expect("stream map lock").len()
    }

    fn next_stream_id(&self) -> u64 {
        // Client ids are odd, host ids even. The atomic starts at 1 or 2 and
        // increments by two; wrap is practically unreachable but checked by
        // `open_*` before use.
        self.next_id.fetch_add(2, Ordering::Relaxed)
    }

    fn reset_all(&self, code: ErrorCode, reason: &str) {
        self.closed.store(true, Ordering::SeqCst);
        let states: Vec<Arc<StreamState>> = {
            let mut streams = self.streams.lock().expect("stream map lock");
            streams.drain().map(|(_, state)| state).collect()
        };
        for state in states {
            let tx = state.inbound.lock().expect("stream inbound lock").clone();
            if let Some(tx) = tx {
                let _ = tx.try_send(Inbound::Reset {
                    code,
                    reason: reason.to_owned(),
                });
            }
            state.close_inbound();
            state.reset.store(true, Ordering::SeqCst);
            state.cancel.notify_one();
        }
        let _ = self.ready_tx.send(None);
    }

    async fn send_frame(
        &self,
        kind: Kind,
        stream: u64,
        seq: u64,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        if payload.len() > self.max_frame_payload {
            return Err(TransportError::MessageTooLarge);
        }
        let frame = Frame::new(kind, self.epoch, stream, seq, payload);
        let encoded = encode_frame_to_vec(&frame)?;
        self.conn.send_binary(Bytes::from(encoded)).await
    }

    async fn send_reset(&self, stream: u64, code: ErrorCode, reason: &str) {
        let payload = encode_reset(code.as_u16(), reason);
        let _ = self.send_frame(Kind::Reset, stream, 0, payload).await;
    }

    async fn close_with(&self, code: ErrorCode, reason: &str) {
        let payload = encode_reset(code.as_u16(), reason);
        let _ = self.send_frame(Kind::GoAway, 0, 0, payload).await;
        self.reset_all(code, reason);
        self.conn.close().await;
    }
}

pub struct Mux {
    inner: Arc<MuxInner>,
    ready_rx: watch::Receiver<Option<Hello>>,
}

impl Clone for Mux {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            ready_rx: self.ready_rx.clone(),
        }
    }
}

impl std::fmt::Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux")
            .field("role", &self.inner.role)
            .field("epoch", &self.inner.epoch)
            .field("streams", &self.inner.stream_count())
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl Mux {
    pub fn new(conn: WsConnection, config: MuxConfig, handler: Arc<dyn OpenHandler>) -> Self {
        let secure = conn.is_secure();
        let max_frame_payload = if secure {
            SECURE_MAX_FRAME_PAYLOAD
        } else {
            oct_protocol::types::MAX_FRAME_PAYLOAD
        };
        let mut features = vec![Feature::Http, Feature::Sse, Feature::Ws, Feature::Resync];
        if secure {
            features.push(Feature::E2ee);
        }
        let mut local_hello = Hello::new(config.role, &features, None);
        if secure {
            local_hello.limits.max_frame_payload = SECURE_MAX_FRAME_PAYLOAD as u32;
        }
        let (ready_tx, ready_rx) = watch::channel(None);
        let next_id = match config.role {
            Role::Client => 1,
            Role::Host => 2,
        };
        let inner = Arc::new(MuxInner {
            conn,
            role: config.role,
            epoch: config.epoch,
            peer_epoch: AtomicU64::new(0),
            peer_is_host: AtomicBool::new(false),
            negotiated_features: AtomicU64::new(0),
            max_frame_payload,
            connection_credit: Credit::new(CONNECTION_WINDOW, CONNECTION_WINDOW),
            local_hello,
            streams: StdMutex::new(HashMap::new()),
            next_id: AtomicU64::new(next_id),
            closed: AtomicBool::new(false),
            handler,
            max_streams: config.max_streams.max(1),
            ready_tx,
            ping_interval: config.ping_interval,
            idle_timeout: config.idle_timeout,
            last_inbound: StdMutex::new(Instant::now()),
        });
        tokio::spawn(run(Arc::clone(&inner)));
        Self { inner, ready_rx }
    }

    pub async fn wait_ready(&self, timeout: Duration) -> Result<Hello, TransportError> {
        let mut rx = self.ready_rx.clone();
        let wait = async {
            loop {
                if let Some(hello) = rx.borrow().clone() {
                    return Ok(hello);
                }
                if self.inner.is_closed() {
                    return Err(TransportError::MuxClosed);
                }
                if rx.changed().await.is_err() {
                    return Err(TransportError::MuxClosed);
                }
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout("mux ready")),
        }
    }

    pub async fn open_http(&self, head: HttpRequestHead) -> Result<Stream, TransportError> {
        self.wait_ready(OPEN_TIMEOUT).await?;
        head.validate()?;
        let payload = encode_request_head(&head)?;
        self.open_stream(Kind::OpenHttp, payload).await
    }

    pub async fn open_ws(&self, head: OpenWs) -> Result<Stream, TransportError> {
        self.wait_ready(OPEN_TIMEOUT).await?;
        if self.inner.negotiated_features.load(Ordering::SeqCst) & Feature::Ws.bit() == 0 {
            return Err(TransportError::FeatureUnsupported);
        }
        head.validate()?;
        let payload = oct_protocol::httpwire::encode_open_ws(&head)?;
        self.open_stream(Kind::OpenWs, payload).await
    }

    async fn open_stream(&self, kind: Kind, payload: Bytes) -> Result<Stream, TransportError> {
        if self.is_closed() {
            return Err(TransportError::MuxClosed);
        }
        let id = self.inner.next_stream_id();
        if id == 0 || id == u64::MAX {
            return Err(TransportError::Internal("stream id exhausted".into()));
        }
        let (tx, rx) = mpsc::channel(STREAM_QUEUE);
        let is_ws = kind == Kind::OpenWs;
        let state = Arc::new(StreamState::new(
            StreamInit {
                id,
                epoch: self.inner.epoch,
                initiated_local: true,
                is_ws,
                max_frame_payload: self.inner.max_frame_payload(),
                send_credit: Credit::new(STREAM_WINDOW, STREAM_WINDOW),
                connection_credit: Arc::clone(&self.inner.connection_credit),
            },
            self.inner.conn.clone(),
            tx,
            Arc::downgrade(&self.inner),
        ));
        self.inner.insert_stream(Arc::clone(&state))?;
        if let Err(err) = self.inner.send_frame(kind, id, 0, payload).await {
            self.inner.remove_stream(id);
            return Err(err);
        }
        Ok(Stream {
            state,
            rx: tokio::sync::Mutex::new(rx),
        })
    }

    pub async fn close(&self) {
        self.inner
            .close_with(ErrorCode::Cancelled, "local mux close")
            .await;
    }

    /// Wait until the carrier or mux is closed. This is useful to own the
    /// reconnect loop outside the transport crate.
    pub async fn wait_closed(&self) {
        let mut rx = self.ready_rx.clone();
        while !self.is_closed() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}

async fn run(inner: Arc<MuxInner>) {
    let result = handshake_and_run(Arc::clone(&inner)).await;
    if let Err(err) = &result {
        tracing::debug!(error = %err, "mux carrier ended");
    }
    if !inner.is_closed() {
        inner.reset_all(ErrorCode::Unavailable, "carrier lost");
    }
    inner.conn.close().await;
}

async fn handshake_and_run(inner: Arc<MuxInner>) -> Result<(), TransportError> {
    let hello = inner.local_hello.encode()?;
    inner
        .send_frame(Kind::Hello, 0, 0, Bytes::from(hello))
        .await?;

    let first = loop {
        let message = tokio::time::timeout(HANDSHAKE_TIMEOUT, inner.conn.recv())
            .await
            .map_err(|_| TransportError::Timeout("peer hello"))??;
        inner.touch_inbound();
        match message {
            Some(WsMessage::Binary(bytes)) => break bytes,
            Some(WsMessage::Text(text)) => match RelayControl::decode(&text) {
                Ok(RelayControl::Ping) => {
                    let _ = inner.conn.send_text(RelayControl::Pong.encode()?).await;
                }
                Ok(RelayControl::Error { code, message }) => {
                    return Err(TransportError::RelayRejected { code, message });
                }
                Ok(RelayControl::PeerLeft { .. }) => return Err(TransportError::PeerLeft),
                Ok(_) => {}
                Err(_) => {
                    return Err(TransportError::Protocol(
                        oct_protocol::ProtocolError::Malformed {
                            context: "relay control",
                            reason: "invalid control before HELLO".into(),
                        },
                    ))
                }
            },
            None => return Err(TransportError::Closed),
        }
    };
    let frame = decode_frame_exact(&first)?;
    if frame.kind != Kind::Hello || frame.stream != 0 || frame.seq != 0 {
        return Err(TransportError::Protocol(
            oct_protocol::ProtocolError::Malformed {
                context: "peer hello",
                reason: "first binary frame must be HELLO on stream 0".into(),
            },
        ));
    }
    let peer_hello = Hello::decode(&frame.payload)?;
    let mut required = vec![Feature::Http];
    if inner.conn.is_secure() {
        required.push(Feature::E2ee);
    }
    let negotiated = inner.local_hello.negotiate(&peer_hello, &required)?;
    inner
        .negotiated_features
        .store(negotiated.features, Ordering::SeqCst);
    inner.peer_epoch.store(frame.epoch, Ordering::SeqCst);
    inner
        .peer_is_host
        .store(peer_hello.role == Role::Host, Ordering::SeqCst);
    let _ = inner.ready_tx.send(Some(peer_hello));

    let mut ping = inner.ping_interval.map(tokio::time::interval);
    if let Some(ticker) = ping.as_mut() {
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    }

    loop {
        let ping_tick = async {
            match ping.as_mut() {
                Some(ticker) => {
                    ticker.tick().await;
                }
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            _ = ping_tick => {
                if inner.idle_for() > inner.idle_timeout {
                    inner
                        .close_with(ErrorCode::Unavailable, "carrier idle timeout")
                        .await;
                    return Ok(());
                }
                if inner.send_frame(Kind::Ping, 0, 0, Bytes::from_static(b"oct")).await.is_err() {
                    return Ok(());
                }
            }
            message = inner.conn.recv() => {
                inner.touch_inbound();
                match message? {
                    Some(WsMessage::Binary(bytes)) => {
                        let frame = decode_frame_exact(&bytes)?;
                        if frame.payload.len() > inner.max_frame_payload() {
                            inner
                                .close_with(ErrorCode::ProtocolError, "frame exceeds secure limit")
                                .await;
                            return Ok(());
                        }
                        if frame.epoch != inner.peer_epoch.load(Ordering::SeqCst) {
                            return Err(TransportError::Protocol(
                                oct_protocol::ProtocolError::Malformed {
                                    context: "frame epoch",
                                    reason: "peer epoch changed mid-connection".into(),
                                },
                            ));
                        }
                        if !frame.validate() || !frame.validate_stream(inner.peer_is_host.load(Ordering::SeqCst)) {
                            inner.send_reset(frame.stream, ErrorCode::ProtocolError, "invalid frame").await;
                            if !frame.validate_stream(inner.peer_is_host.load(Ordering::SeqCst)) {
                                inner.close_with(ErrorCode::ProtocolError, "invalid stream id").await;
                                return Ok(());
                            }
                            continue;
                        }
                        let result = dispatch(Arc::clone(&inner), frame).await;
                        inner.touch_inbound();
                        result?;
                    }
                    Some(WsMessage::Text(text)) => {
                        match RelayControl::decode(&text) {
                            Ok(RelayControl::Ping) => {
                                let _ = inner.conn.send_text(RelayControl::Pong.encode()?).await;
                            }
                            Ok(RelayControl::Error { .. }) | Ok(RelayControl::PeerLeft { .. }) => {
                                return Ok(());
                            }
                            Ok(_) => {}
                            Err(_) => return Ok(()),
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn dispatch(inner: Arc<MuxInner>, frame: Frame) -> Result<(), TransportError> {
    match frame.kind {
        Kind::Hello => {
            inner
                .close_with(ErrorCode::ProtocolError, "duplicate hello")
                .await;
            Ok(())
        }
        Kind::OpenHttp => {
            if frame.seq != 0 {
                inner
                    .send_reset(frame.stream, ErrorCode::ProtocolError, "open seq")
                    .await;
                return Ok(());
            }
            let head = match decode_request_head(&frame.payload) {
                Ok(head) => head,
                Err(_) => {
                    inner
                        .send_reset(frame.stream, ErrorCode::BadRequest, "invalid request head")
                        .await;
                    return Ok(());
                }
            };
            open_inbound(inner, frame.stream, InboundOpen::Http(head)).await;
            Ok(())
        }
        Kind::OpenWs => {
            if inner.negotiated_features.load(Ordering::SeqCst) & Feature::Ws.bit() == 0 {
                inner
                    .send_reset(frame.stream, ErrorCode::Unavailable, "ws not negotiated")
                    .await;
                return Ok(());
            }
            if frame.seq != 0 {
                inner
                    .send_reset(frame.stream, ErrorCode::ProtocolError, "open seq")
                    .await;
                return Ok(());
            }
            let head = match decode_open_ws(&frame.payload) {
                Ok(head) => head,
                Err(_) => {
                    inner
                        .send_reset(frame.stream, ErrorCode::BadRequest, "invalid ws head")
                        .await;
                    return Ok(());
                }
            };
            open_inbound(inner, frame.stream, InboundOpen::Ws(head)).await;
            Ok(())
        }
        Kind::HttpResponse => {
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "unknown stream")
                        .await;
                    return Ok(());
                }
            };
            if state.is_ws {
                reset_stream(&state, "http response on websocket stream").await;
                return Ok(());
            }
            if !state.initiated_local {
                reset_stream(&state, "response on peer-opened stream").await;
                return Ok(());
            }
            if !check_seq(&state, frame.seq) {
                reset_stream(&state, "response seq").await;
                return Ok(());
            }
            if state.response_seen.swap(true, Ordering::SeqCst) {
                reset_stream(&state, "duplicate response").await;
                return Ok(());
            }
            match decode_response_head(&frame.payload) {
                Ok(head) => {
                    if !state.push(Inbound::HttpResponse(head)).await {
                        reset_stream(&state, "consumer dropped").await;
                    }
                }
                Err(_) => {
                    reset_stream(&state, "invalid response head").await;
                }
            }
            Ok(())
        }
        Kind::Data => {
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "unknown stream")
                        .await;
                    return Ok(());
                }
            };
            if state.is_ws {
                reset_stream(&state, "http data on websocket stream").await;
                return Ok(());
            }
            if state.initiated_local && !state.response_seen.load(Ordering::SeqCst) {
                reset_stream(&state, "body before response head").await;
                return Ok(());
            }
            if !check_seq(&state, frame.seq) {
                reset_stream(&state, "data seq").await;
                return Ok(());
            }
            if !state.push(Inbound::Data(frame.payload)).await {
                reset_stream(&state, "consumer dropped").await;
            }
            Ok(())
        }
        Kind::End => {
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "unknown stream")
                        .await;
                    return Ok(());
                }
            };
            if state.is_ws {
                reset_stream(&state, "http end on websocket stream").await;
                return Ok(());
            }
            if state.initiated_local && !state.response_seen.load(Ordering::SeqCst) {
                reset_stream(&state, "end before response head").await;
                return Ok(());
            }
            if !check_seq(&state, frame.seq) {
                reset_stream(&state, "end seq").await;
                return Ok(());
            }
            let _ = state.push(Inbound::End).await;
            state.remote_finished.store(true, Ordering::SeqCst);
            state.close_inbound();
            state.maybe_remove();
            Ok(())
        }
        Kind::Reset => {
            let (code, reason) = match decode_reset(&frame.payload) {
                Ok(value) => value,
                Err(_) => (
                    ErrorCode::ProtocolError.as_u16(),
                    "invalid reset".to_owned(),
                ),
            };
            let code = ErrorCode::from_u16(code).unwrap_or(ErrorCode::ProtocolError);
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => return Ok(()),
            };
            let _ = state.push(Inbound::Reset { code, reason }).await;
            state.reset.store(true, Ordering::SeqCst);
            state.remote_finished.store(true, Ordering::SeqCst);
            state.close_inbound();
            state.maybe_remove();
            Ok(())
        }
        Kind::WindowUpdate => {
            let credit = match oct_protocol::httpwire::decode_window_update(&frame.payload) {
                Ok(credit) => u64::from(credit),
                Err(_) => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "bad window update")
                        .await;
                    return Ok(());
                }
            };
            if let Some(state) = stream_state(&inner, frame.stream) {
                let outstanding = state.outstanding_credit.load(Ordering::SeqCst);
                let applied = credit.min(outstanding);
                if applied > 0 {
                    let _ = state.outstanding_credit.fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |value| Some(value.saturating_sub(applied)),
                    );
                    inner.connection_credit.release(applied);
                }
                state.send_credit.release(applied);
            }
            Ok(())
        }
        Kind::Ping => {
            inner.send_frame(Kind::Pong, 0, 0, frame.payload).await?;
            Ok(())
        }
        Kind::Pong => Ok(()),
        Kind::GoAway => {
            inner
                .close_with(ErrorCode::Unavailable, "peer goaway")
                .await;
            Ok(())
        }
        Kind::WsMessage => {
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "unknown stream")
                        .await;
                    return Ok(());
                }
            };
            if !state.is_ws {
                reset_stream(&state, "ws message on http stream").await;
                return Ok(());
            }
            if !check_seq(&state, frame.seq) {
                reset_stream(&state, "ws message seq").await;
                return Ok(());
            }
            let (opcode, fin, payload) = match decode_ws_message(&frame.payload) {
                Ok(value) => value,
                Err(_) => {
                    reset_stream(&state, "invalid ws message").await;
                    return Ok(());
                }
            };
            if !reassemble_ws(&state, opcode, fin, payload) {
                reset_stream(&state, "invalid ws fragment").await;
            }
            Ok(())
        }
        Kind::WsClose => {
            let state = match stream_state(&inner, frame.stream) {
                Some(state) => state,
                None => {
                    inner
                        .send_reset(frame.stream, ErrorCode::ProtocolError, "unknown stream")
                        .await;
                    return Ok(());
                }
            };
            if !state.is_ws {
                reset_stream(&state, "ws close on http stream").await;
                return Ok(());
            }
            if !check_seq(&state, frame.seq) {
                reset_stream(&state, "ws close seq").await;
                return Ok(());
            }
            let (code, reason) = match decode_ws_close(&frame.payload) {
                Ok(value) => value,
                Err(_) => {
                    reset_stream(&state, "invalid ws close").await;
                    return Ok(());
                }
            };
            // A close terminates the message stream; an incomplete fragmented
            // message can never be delivered and is discarded.
            let _ = state.ws_frag.lock().expect("stream ws frag lock").take();
            if !state.push_ws(Inbound::WsClose { code, reason }) {
                reset_stream(&state, "ws close queue overflow").await;
                return Ok(());
            }
            state.remote_finished.store(true, Ordering::SeqCst);
            state.close_inbound();
            state.maybe_remove();
            Ok(())
        }
    }
}

/// Append one decoded WS fragment and deliver a complete message on FIN.
/// Returns `false` when the fragment sequence or size is invalid. The std
/// mutex is never held across an `.await`.
fn reassemble_ws(state: &StreamState, opcode: WsOpcode, fin: bool, payload: Bytes) -> bool {
    enum Fragment {
        Pending,
        Complete(WsOpcode, Bytes),
        Invalid,
    }

    let fragment = {
        let mut slot = state.ws_frag.lock().expect("stream ws frag lock");
        match slot.take() {
            Some((start_opcode, mut buf)) => {
                if opcode != WsOpcode::Continuation
                    || buf.len().saturating_add(payload.len()) > MAX_WS_MESSAGE
                {
                    Fragment::Invalid
                } else {
                    buf.extend_from_slice(&payload);
                    if fin {
                        Fragment::Complete(start_opcode, Bytes::from(buf))
                    } else {
                        *slot = Some((start_opcode, buf));
                        Fragment::Pending
                    }
                }
            }
            None => {
                if opcode == WsOpcode::Continuation || payload.len() > MAX_WS_MESSAGE {
                    Fragment::Invalid
                } else if fin {
                    Fragment::Complete(opcode, payload)
                } else {
                    *slot = Some((opcode, payload.to_vec()));
                    Fragment::Pending
                }
            }
        }
    };

    match fragment {
        Fragment::Pending => true,
        Fragment::Invalid => false,
        Fragment::Complete(opcode, payload) => {
            state.push_ws(Inbound::WsMessage { opcode, payload })
        }
    }
}

enum InboundOpen {
    Http(HttpRequestHead),
    Ws(OpenWs),
}

async fn open_inbound(inner: Arc<MuxInner>, id: u64, open: InboundOpen) {
    if !valid_stream_id(id, inner.peer_is_host.load(Ordering::SeqCst)) {
        inner
            .send_reset(id, ErrorCode::ProtocolError, "invalid stream id")
            .await;
        return;
    }
    if stream_state(&inner, id).is_some() {
        inner
            .send_reset(id, ErrorCode::ProtocolError, "duplicate stream")
            .await;
        return;
    }
    let (tx, rx) = mpsc::channel(STREAM_QUEUE);
    let is_ws = matches!(open, InboundOpen::Ws(_));
    let state = Arc::new(StreamState::new(
        StreamInit {
            id,
            epoch: inner.epoch,
            initiated_local: false,
            is_ws,
            max_frame_payload: inner.max_frame_payload(),
            send_credit: Credit::new(STREAM_WINDOW, STREAM_WINDOW),
            connection_credit: Arc::clone(&inner.connection_credit),
        },
        inner.conn.clone(),
        tx,
        Arc::downgrade(&inner),
    ));
    if inner.insert_stream(Arc::clone(&state)).is_err() {
        inner
            .send_reset(id, ErrorCode::OverLimit, "stream limit")
            .await;
        return;
    }
    let stream = Stream {
        state,
        rx: tokio::sync::Mutex::new(rx),
    };
    let handler = Arc::clone(&inner.handler);
    match open {
        InboundOpen::Http(head) => {
            tokio::spawn(async move {
                handler.on_http(stream, head).await;
            });
        }
        InboundOpen::Ws(head) => {
            tokio::spawn(async move {
                handler.on_ws(stream, head).await;
            });
        }
    }
}

fn stream_state(inner: &MuxInner, id: u64) -> Option<Arc<StreamState>> {
    inner
        .streams
        .lock()
        .expect("stream map lock")
        .get(&id)
        .cloned()
}

fn check_seq(state: &StreamState, seq: u64) -> bool {
    let mut expected = state.in_seq.lock().expect("stream in-seq lock");
    if seq != *expected {
        return false;
    }
    *expected = expected.saturating_add(1);
    true
}

async fn reset_stream(state: &StreamState, reason: &str) {
    let _ = state.reset_inner(ErrorCode::ProtocolError, reason).await;
    state.maybe_remove();
}
