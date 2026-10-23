use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use oct_protocol::httpwire::{
    encode_reset, encode_window_update, encode_ws_close, encode_ws_message,
};
use oct_protocol::{encode_frame_to_vec, ErrorCode, Frame, Kind, WsOpcode, MAX_WS_MESSAGE};
use tokio::sync::{mpsc, Mutex, Notify};

use crate::mux::{Inbound, MuxInner};
use crate::{TransportError, WsConnection};

pub(crate) const STREAM_QUEUE: usize = 64;
const MAX_WS_PENDING_BYTES: usize = 2 * MAX_WS_MESSAGE;
const WS_CLOSE_GRACE: Duration = Duration::from_secs(2);
const WINDOW_UPDATE_THRESHOLD: usize = 64 * 1024;

pub(crate) const STREAM_WINDOW: u64 = 256 * 1024;
pub(crate) const CONNECTION_WINDOW: u64 = 8 * 1024 * 1024;

/// Bounded byte-credit window. Credits are consumed before a DATA frame is
/// written and returned only when the peer consumes the bytes and sends
/// WINDOW_UPDATE.
pub(crate) struct Credit {
    available: StdMutex<u64>,
    max: u64,
    notify: Notify,
}

impl Credit {
    pub(crate) fn new(initial: u64, max: u64) -> Arc<Self> {
        Arc::new(Self {
            available: StdMutex::new(initial),
            max,
            notify: Notify::new(),
        })
    }

    pub(crate) fn release(&self, bytes: u64) {
        {
            let mut available = self.available.lock().expect("credit lock");
            *available = (*available).saturating_add(bytes).min(self.max);
        }
        self.notify.notify_waiters();
        self.notify.notify_one();
    }

    /// Reserve from a stream window and the aggregate connection window. The
    /// returned reservation releases its credits if it is dropped before
    /// commit, making cancellation safe.
    pub(crate) async fn reserve_pair(
        stream: &Arc<Credit>,
        connection: &Arc<Credit>,
        want: u64,
    ) -> Reservation {
        loop {
            {
                let mut stream_available = stream.available.lock().expect("credit lock");
                let mut connection_available = connection.available.lock().expect("credit lock");
                if *stream_available > 0 && *connection_available > 0 {
                    let granted = want.min(*stream_available).min(*connection_available);
                    *stream_available -= granted;
                    *connection_available -= granted;
                    return Reservation {
                        stream: Arc::clone(stream),
                        connection: Arc::clone(connection),
                        bytes: granted,
                        active: true,
                    };
                }
            }
            tokio::select! {
                _ = stream.notify.notified() => {}
                _ = connection.notify.notified() => {}
            }
        }
    }
}

pub(crate) struct Reservation {
    stream: Arc<Credit>,
    connection: Arc<Credit>,
    bytes: u64,
    active: bool,
}

impl Reservation {
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn commit(mut self) {
        self.active = false;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.active {
            self.stream.release(self.bytes);
            self.connection.release(self.bytes);
        }
    }
}

/// Tracks bytes whose DATA frame may not have been committed yet. It keeps
/// `outstanding_credit` correct if the send future is cancelled.
struct OutstandingCredit {
    state: Arc<StreamState>,
    bytes: u64,
    active: bool,
}

impl OutstandingCredit {
    fn new(state: Arc<StreamState>, bytes: u64) -> Self {
        state.outstanding_credit.fetch_add(bytes, Ordering::SeqCst);
        Self {
            state,
            bytes,
            active: true,
        }
    }

    fn commit(mut self) {
        self.active = false;
    }
}

impl Drop for OutstandingCredit {
    fn drop(&mut self) {
        if self.active {
            let _ = self.state.outstanding_credit.fetch_update(
                Ordering::SeqCst,
                Ordering::SeqCst,
                |value| Some(value.saturating_sub(self.bytes)),
            );
        }
    }
}

#[derive(Debug)]
pub(crate) struct OutboundState {
    pub seq: u64,
    pub finished: bool,
    pub reset: bool,
}

pub(crate) struct StreamState {
    pub id: u64,
    pub epoch: u64,
    pub initiated_local: bool,
    pub is_ws: bool,
    pub max_frame_payload: usize,
    pub send_credit: Arc<Credit>,
    pub connection_credit: Arc<Credit>,
    pub outstanding_credit: AtomicU64,
    pub recv_window_pending: AtomicUsize,
    pub conn: WsConnection,
    pub out: Mutex<OutboundState>,
    pub in_seq: StdMutex<u64>,
    /// Bounded reassembly buffer for fragmented inbound WS messages. It holds
    /// at most [`MAX_WS_MESSAGE`] application bytes.
    pub ws_frag: StdMutex<Option<(WsOpcode, Vec<u8>)>>,
    /// Bytes of complete WS messages queued for the consumer. Bounded so a
    /// slow reader cannot retain hundreds of megabytes per stream.
    pub ws_pending_bytes: AtomicUsize,
    pub response_seen: AtomicBool,
    pub response_sent: AtomicBool,
    pub local_finished: AtomicBool,
    pub remote_finished: AtomicBool,
    pub reset: AtomicBool,
    pub cancel: Notify,
    pub inbound: StdMutex<Option<mpsc::Sender<Inbound>>>,
    pub mux: Weak<MuxInner>,
}

pub(crate) struct StreamInit {
    pub id: u64,
    pub epoch: u64,
    pub initiated_local: bool,
    pub is_ws: bool,
    pub max_frame_payload: usize,
    pub send_credit: Arc<Credit>,
    pub connection_credit: Arc<Credit>,
}

impl StreamState {
    pub(crate) fn new(
        init: StreamInit,
        conn: WsConnection,
        inbound: mpsc::Sender<Inbound>,
        mux: Weak<MuxInner>,
    ) -> Self {
        Self {
            id: init.id,
            epoch: init.epoch,
            initiated_local: init.initiated_local,
            is_ws: init.is_ws,
            max_frame_payload: init.max_frame_payload,
            send_credit: init.send_credit,
            connection_credit: init.connection_credit,
            outstanding_credit: AtomicU64::new(0),
            recv_window_pending: AtomicUsize::new(0),
            conn,
            out: Mutex::new(OutboundState {
                seq: 0,
                finished: false,
                reset: false,
            }),
            in_seq: StdMutex::new(1),
            ws_frag: StdMutex::new(None),
            ws_pending_bytes: AtomicUsize::new(0),
            response_seen: AtomicBool::new(false),
            response_sent: AtomicBool::new(false),
            local_finished: AtomicBool::new(false),
            remote_finished: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            cancel: Notify::new(),
            inbound: StdMutex::new(Some(inbound)),
            mux,
        }
    }

    pub(crate) fn take_inbound(&self) {
        let _ = self.inbound.lock().expect("stream inbound lock").take();
    }

    pub(crate) async fn push(&self, item: Inbound) -> bool {
        let tx = self.inbound.lock().expect("stream inbound lock").clone();
        match tx {
            Some(tx) => tx.send(item).await.is_ok(),
            None => false,
        }
    }

    /// Enqueue a complete WS message without waiting for a slow consumer.
    /// The total queued WS bytes are capped; overflow resets the stream instead
    /// of stalling the single carrier loop or growing memory without bound.
    pub(crate) fn push_ws(&self, item: Inbound) -> bool {
        let bytes = inbound_ws_bytes(&item);
        let previous = self.ws_pending_bytes.fetch_add(bytes, Ordering::SeqCst);
        if previous.saturating_add(bytes) > MAX_WS_PENDING_BYTES {
            self.ws_pending_bytes.fetch_sub(bytes, Ordering::SeqCst);
            return false;
        }
        let tx = self.inbound.lock().expect("stream inbound lock").clone();
        let sent = tx.is_some_and(|tx| tx.try_send(item).is_ok());
        if !sent {
            self.ws_pending_bytes.fetch_sub(bytes, Ordering::SeqCst);
        }
        sent
    }

    pub(crate) fn close_inbound(&self) {
        self.take_inbound();
    }

    fn mux_closed(&self) -> bool {
        self.mux.upgrade().map(|m| m.is_closed()).unwrap_or(true)
    }

    /// Append one frame to the stream while the caller holds the outbound
    /// mutex. Holding one guard across a multi-frame send prevents concurrent
    /// messages from interleaving on the wire.
    async fn write_frame(
        &self,
        out: &mut OutboundState,
        kind: Kind,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        if out.reset || out.finished {
            return Err(TransportError::StreamClosed);
        }
        let seq = out
            .seq
            .checked_add(1)
            .ok_or_else(|| TransportError::Internal("stream sequence overflow".into()))?;
        let frame = Frame::new(kind, self.epoch, self.id, seq, payload);
        let encoded = encode_frame_to_vec(&frame)?;
        self.conn.send_binary(Bytes::from(encoded)).await?;
        out.seq = seq;
        Ok(())
    }

    async fn send_frame(&self, kind: Kind, payload: Bytes) -> Result<(), TransportError> {
        let mut out = self.out.lock().await;
        if kind == Kind::Data && !self.initiated_local && !self.response_sent.load(Ordering::SeqCst)
        {
            return Err(TransportError::Internal(
                "response body sent before response head".into(),
            ));
        }
        self.write_frame(&mut out, kind, payload).await
    }

    pub(crate) async fn reset_inner(
        &self,
        code: ErrorCode,
        reason: &str,
    ) -> Result<(), TransportError> {
        let mut out = self.out.lock().await;
        if out.reset {
            return Ok(());
        }
        out.reset = true;
        let seq = out
            .seq
            .checked_add(1)
            .ok_or_else(|| TransportError::Internal("stream sequence overflow".into()))?;
        let payload = encode_reset(code.as_u16(), reason);
        let frame = Frame::new(Kind::Reset, self.epoch, self.id, seq, payload);
        let encoded = encode_frame_to_vec(&frame)?;
        if self.conn.send_binary(Bytes::from(encoded)).await.is_err() {
            // The carrier is already gone; the local state is still reset.
        }
        drop(out);
        self.reset.store(true, Ordering::SeqCst);
        let outstanding = self.outstanding_credit.swap(0, Ordering::SeqCst);
        self.connection_credit.release(outstanding);
        self.cancel.notify_one();
        self.close_inbound();
        Ok(())
    }

    pub(crate) fn maybe_remove(&self) {
        if let Some(mux) = self.mux.upgrade() {
            if (self.local_finished.load(Ordering::SeqCst) || self.reset.load(Ordering::SeqCst))
                && (self.remote_finished.load(Ordering::SeqCst)
                    || self.reset.load(Ordering::SeqCst))
            {
                let outstanding = self.outstanding_credit.swap(0, Ordering::SeqCst);
                self.connection_credit.release(outstanding);
                mux.remove_stream(self.id);
            }
        }
    }
}

/// One application stream. The receiver is shared behind a mutex so the same
/// handle can be cloned/moved into a task and still read inbound events.
pub struct Stream {
    pub(crate) state: Arc<StreamState>,
    pub(crate) rx: Mutex<mpsc::Receiver<Inbound>>,
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stream").field("id", &self.id()).finish()
    }
}

impl Stream {
    pub fn id(&self) -> u64 {
        self.state.id
    }

    pub async fn send_data(&self, bytes: Bytes) -> Result<(), TransportError> {
        if self.state.is_ws {
            return Err(TransportError::Internal(
                "send_data is not valid on a websocket stream".into(),
            ));
        }
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return Err(TransportError::StreamClosed);
        }
        if bytes.is_empty() {
            return self.state.send_frame(Kind::Data, bytes).await;
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let want = (bytes.len() - offset).min(self.state.max_frame_payload) as u64;
            let reservation = tokio::select! {
                reservation = Credit::reserve_pair(
                    &self.state.send_credit,
                    &self.state.connection_credit,
                    want,
                ) => reservation,
                _ = self.state.cancel.notified() => return Err(TransportError::StreamClosed),
            };
            let granted = reservation.bytes() as usize;
            if granted == 0 {
                drop(reservation);
                return Err(TransportError::Internal("zero flow-control credit".into()));
            }
            let end = offset + granted;
            let outstanding = OutstandingCredit::new(Arc::clone(&self.state), granted as u64);
            match self
                .state
                .send_frame(Kind::Data, bytes.slice(offset..end))
                .await
            {
                Ok(()) => {
                    outstanding.commit();
                    reservation.commit();
                    offset = end;
                }
                Err(error) => {
                    drop(outstanding);
                    drop(reservation);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Send the response head for an inbound HTTP stream. Exactly one response
    /// head may be sent per stream.
    pub async fn send_response(
        &self,
        head: oct_protocol::HttpResponseHead,
    ) -> Result<(), TransportError> {
        if self.state.is_ws {
            return Err(TransportError::Internal(
                "send_response is not valid on a websocket stream".into(),
            ));
        }
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return Err(TransportError::StreamClosed);
        }
        if self.state.initiated_local {
            return Err(TransportError::Internal(
                "cannot send a response on a locally opened stream".into(),
            ));
        }
        if self.state.response_sent.swap(true, Ordering::SeqCst) {
            return Err(TransportError::Internal(
                "response head already sent".into(),
            ));
        }
        if let Err(err) = head.validate() {
            self.state.response_sent.store(false, Ordering::SeqCst);
            return Err(err.into());
        }
        let payload = match oct_protocol::httpwire::encode_response_head(&head) {
            Ok(payload) => payload,
            Err(err) => {
                self.state.response_sent.store(false, Ordering::SeqCst);
                return Err(err.into());
            }
        };
        if let Err(err) = self.state.send_frame(Kind::HttpResponse, payload).await {
            self.state.response_sent.store(false, Ordering::SeqCst);
            return Err(err);
        }
        Ok(())
    }

    /// Send one complete nested WebSocket message. Messages larger than one
    /// OCT frame are split into continuation fragments while a single
    /// outbound guard is held, so concurrent messages cannot interleave.
    pub async fn send_ws_message(
        &self,
        opcode: WsOpcode,
        payload: Bytes,
    ) -> Result<(), TransportError> {
        if !self.state.is_ws {
            return Err(TransportError::Internal(
                "send_ws_message is only valid on a websocket stream".into(),
            ));
        }
        if !matches!(opcode, WsOpcode::Text | WsOpcode::Binary) {
            return Err(TransportError::Internal(
                "websocket message opcode must be text or binary".into(),
            ));
        }
        if payload.len() > MAX_WS_MESSAGE {
            return Err(TransportError::MessageTooLarge);
        }
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return Err(TransportError::StreamClosed);
        }

        let mut out = self.state.out.lock().await;
        let chunk = self.state.max_frame_payload.saturating_sub(2).max(1);
        let mut offset = 0usize;
        let mut first = true;
        loop {
            let end = offset.saturating_add(chunk).min(payload.len());
            let fin = end == payload.len();
            let frame_opcode = if first {
                opcode
            } else {
                WsOpcode::Continuation
            };
            let encoded = encode_ws_message(frame_opcode, fin, &payload[offset..end])?;
            self.state
                .write_frame(&mut out, Kind::WsMessage, encoded)
                .await?;
            first = false;
            if fin {
                break;
            }
            offset = end;
        }
        Ok(())
    }

    /// Send a nested WebSocket close and finish the local half of the stream.
    pub async fn send_ws_close(
        &self,
        code: Option<u16>,
        reason: &str,
    ) -> Result<(), TransportError> {
        if !self.state.is_ws {
            return Err(TransportError::Internal(
                "send_ws_close is only valid on a websocket stream".into(),
            ));
        }
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return Err(TransportError::StreamClosed);
        }
        let payload = encode_ws_close(code, reason)?;
        let mut out = self.state.out.lock().await;
        if out.reset {
            return Err(TransportError::StreamClosed);
        }
        if out.finished {
            return Ok(());
        }
        self.state
            .write_frame(&mut out, Kind::WsClose, payload)
            .await?;
        out.finished = true;
        drop(out);
        self.state.local_finished.store(true, Ordering::SeqCst);
        self.state.maybe_remove();
        Ok(())
    }

    pub async fn finish(&self) -> Result<(), TransportError> {
        if self.state.is_ws {
            return Err(TransportError::Internal(
                "finish is not valid on a websocket stream; send a WS_CLOSE".into(),
            ));
        }
        {
            let mut out = self.state.out.lock().await;
            if out.finished {
                return Ok(());
            }
            if out.reset {
                return Err(TransportError::StreamClosed);
            }
            if !self.state.initiated_local && !self.state.response_sent.load(Ordering::SeqCst) {
                return Err(TransportError::Internal(
                    "cannot finish before sending response head".into(),
                ));
            }
            let seq = out
                .seq
                .checked_add(1)
                .ok_or_else(|| TransportError::Internal("stream sequence overflow".into()))?;
            let frame = Frame::new(
                Kind::End,
                self.state.epoch,
                self.state.id,
                seq,
                Bytes::new(),
            );
            let encoded = encode_frame_to_vec(&frame)?;
            self.state.conn.send_binary(Bytes::from(encoded)).await?;
            out.seq = seq;
            out.finished = true;
        }
        self.state.local_finished.store(true, Ordering::SeqCst);
        self.state.maybe_remove();
        Ok(())
    }

    pub async fn reset(&self, code: ErrorCode, reason: &str) -> Result<(), TransportError> {
        self.state.reset_inner(code, reason).await?;
        self.state.maybe_remove();
        Ok(())
    }

    pub async fn recv(&self) -> Result<Option<Inbound>, TransportError> {
        let item = self.rx.lock().await.recv().await;
        if let Some(item) = &item {
            let bytes = inbound_ws_bytes(item);
            if bytes > 0 {
                self.state
                    .ws_pending_bytes
                    .fetch_sub(bytes, Ordering::SeqCst);
            }
            if let Inbound::Data(data) = item {
                if !data.is_empty() {
                    let pending = self
                        .state
                        .recv_window_pending
                        .fetch_add(data.len(), Ordering::SeqCst)
                        .saturating_add(data.len());
                    if pending >= WINDOW_UPDATE_THRESHOLD {
                        let credit = self.state.recv_window_pending.swap(0, Ordering::SeqCst);
                        if credit > 0 {
                            self.send_window_update(credit as u32).await;
                        }
                    }
                }
            }
        }
        Ok(item)
    }

    async fn send_window_update(&self, bytes: u32) {
        if bytes == 0 || self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return;
        }
        let payload = encode_window_update(bytes);
        let frame = Frame::new(
            Kind::WindowUpdate,
            self.state.epoch,
            self.state.id,
            0,
            payload,
        );
        if let Ok(encoded) = encode_frame_to_vec(&frame) {
            let _ = self.state.conn.send_binary(Bytes::from(encoded)).await;
        }
    }

    /// Resolves when the stream is reset or its carrier is closed. A request
    /// half-close (`END`) does not resolve this; callers streaming a response
    /// use it to cancel the upstream request when the peer disappears.
    pub async fn wait_reset(&self) {
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return;
        }
        self.state.cancel.notified().await;
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let local_finished = self.state.local_finished.load(Ordering::SeqCst);
        let remote_finished = self.state.remote_finished.load(Ordering::SeqCst);
        if self.state.reset.load(Ordering::SeqCst) || self.state.mux_closed() {
            return;
        }
        if self.state.is_ws && (local_finished || remote_finished) {
            // Give a cooperative peer a short window to acknowledge the close;
            // then reap the entry even if it never does.
            let mux = self.state.mux.clone();
            let id = self.state.id;
            tokio::spawn(async move {
                tokio::time::sleep(WS_CLOSE_GRACE).await;
                if let Some(mux) = mux.upgrade() {
                    mux.remove_stream(id);
                }
            });
            return;
        }
        if local_finished && remote_finished {
            return;
        }
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            let _ = state
                .reset_inner(ErrorCode::Cancelled, "stream handle dropped")
                .await;
            state.maybe_remove();
        });
    }
}

fn inbound_ws_bytes(item: &Inbound) -> usize {
    match item {
        Inbound::WsMessage { payload, .. } => payload.len(),
        Inbound::WsClose { reason, .. } => reason.len(),
        _ => 0,
    }
}
