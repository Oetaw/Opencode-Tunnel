use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_with_config, WebSocketStream};

use oct_security::{NoiseIo, NoiseSession, SecurityError};

use crate::TransportError;

const COMMAND_QUEUE: usize = 64;
const INBOUND_QUEUE: usize = 64;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_MESSAGE: usize = oct_protocol::types::MAX_FRAME_LEN;
const DEFAULT_USER_AGENT: &str = concat!("oct/", env!("CARGO_PKG_VERSION"));
const DEFAULT_REKEY_BYTES: u64 = 1 << 30;
const SECURE_DATA: u8 = 1;
const SECURE_REKEY: u8 = 2;

#[derive(Debug, Clone)]
pub struct WsOptions {
    pub connect_timeout: Duration,
    pub max_message_bytes: usize,
    pub user_agent: String,
    /// Only for tests / loopback. Public deployments must use `wss://`.
    pub allow_plaintext: bool,
}

impl Default for WsOptions {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_message_bytes: DEFAULT_MAX_MESSAGE,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            allow_plaintext: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    Text(String),
    Binary(Bytes),
}

enum Command {
    Text(String),
    Binary(Bytes),
    Ping(Bytes),
    Close,
}

struct Inner {
    commands: mpsc::Sender<Command>,
    inbound: Mutex<mpsc::Receiver<WsMessage>>,
    closed: Arc<AtomicBool>,
    relay_role: Mutex<Option<oct_protocol::relay::RelayRole>>,
    noise: StdMutex<Option<Arc<NoiseSession>>>,
    send_order: Mutex<()>,
    rekey_threshold: AtomicU64,
    bytes_since_rekey: AtomicU64,
}

/// A clonable handle to one websocket connection. A single I/O task owns the
/// socket; writes go through a bounded command queue and reads through a
/// bounded inbound queue, so slow consumers apply backpressure instead of
/// growing memory.
#[derive(Clone)]
pub struct WsConnection {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection")
            .field("closed", &self.is_closed())
            .field("secure", &self.is_secure())
            .finish_non_exhaustive()
    }
}

impl WsConnection {
    pub async fn connect(url: &str, options: WsOptions) -> Result<Self, TransportError> {
        let parsed = url::Url::parse(url).map_err(|e| TransportError::InvalidUrl(e.to_string()))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(TransportError::InvalidUrl(
                "userinfo is not allowed in relay URLs".into(),
            ));
        }
        match parsed.scheme() {
            "wss" => {}
            "ws" if options.allow_plaintext => {}
            "ws" => {
                return Err(TransportError::InvalidUrl(
                    "plaintext ws:// is only allowed for loopback tests".into(),
                ))
            }
            other => {
                return Err(TransportError::InvalidUrl(format!(
                    "unsupported scheme {other}"
                )))
            }
        }

        let mut request = url
            .into_client_request()
            .map_err(|e| TransportError::InvalidUrl(e.to_string()))?;
        let user_agent = HeaderValue::from_str(&options.user_agent)
            .map_err(|_| TransportError::InvalidUrl("invalid user agent".into()))?;
        request.headers_mut().insert("user-agent", user_agent);

        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(options.max_message_bytes);
        config.max_frame_size = Some(options.max_message_bytes);
        let connect = connect_async_with_config(request, Some(config), true);
        let (stream, _response) = tokio::time::timeout(options.connect_timeout, connect)
            .await
            .map_err(|_| TransportError::ConnectTimeout)??;
        Ok(Self::spawn(stream))
    }

    /// Adopt an already-upgraded websocket. Used by tests and future server
    /// paths. The caller is responsible for having validated the upgrade.
    pub async fn from_stream<S>(stream: WebSocketStream<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::spawn(stream)
    }

    fn spawn<S>(stream: WebSocketStream<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            run_socket(stream, command_rx, inbound_tx, task_closed).await;
        });
        Self {
            inner: Arc::new(Inner {
                commands: command_tx,
                inbound: Mutex::new(inbound_rx),
                closed,
                relay_role: Mutex::new(None),
                noise: StdMutex::new(None),
                send_order: Mutex::new(()),
                rekey_threshold: AtomicU64::new(DEFAULT_REKEY_BYTES),
                bytes_since_rekey: AtomicU64::new(0),
            }),
        }
    }

    pub async fn send_text(&self, text: String) -> Result<(), TransportError> {
        self.command(Command::Text(text)).await
    }

    pub async fn send_binary(&self, bytes: Bytes) -> Result<(), TransportError> {
        // Noise transport nonces are ordered, so encryption and enqueue must be
        // one critical section. Without this, concurrent stream tasks can
        // enqueue nonce n+1 before n and force the peer to reject the carrier.
        let _send_order = self.inner.send_order.lock().await;
        let Some(session) = self.noise_session() else {
            return self.command(Command::Binary(bytes)).await;
        };
        if self.inner.bytes_since_rekey.load(Ordering::SeqCst)
            >= self.inner.rekey_threshold.load(Ordering::SeqCst)
        {
            self.send_rekey_locked(&session).await?;
        }
        let mut plaintext = Vec::with_capacity(bytes.len() + 1);
        plaintext.push(SECURE_DATA);
        plaintext.extend_from_slice(&bytes);
        let ciphertext = Bytes::from(session.seal(&plaintext)?);
        self.command(Command::Binary(ciphertext)).await?;
        let sent = bytes.len() as u64 + 1;
        let total = self
            .inner
            .bytes_since_rekey
            .fetch_add(sent, Ordering::SeqCst)
            .saturating_add(sent);
        if total >= self.inner.rekey_threshold.load(Ordering::SeqCst) {
            self.send_rekey_locked(&session).await?;
        }
        Ok(())
    }

    async fn send_rekey_locked(&self, session: &NoiseSession) -> Result<(), TransportError> {
        let ciphertext = Bytes::from(session.seal(&[SECURE_REKEY])?);
        self.command(Command::Binary(ciphertext)).await?;
        session.rekey_outgoing();
        self.inner.bytes_since_rekey.store(0, Ordering::SeqCst);
        Ok(())
    }

    /// Override the automatic transport rekey interval. Intended for tests and
    /// high-throughput deployments; zero is treated as the default interval.
    pub fn set_rekey_threshold(&self, bytes: u64) {
        self.inner.rekey_threshold.store(
            if bytes == 0 {
                DEFAULT_REKEY_BYTES
            } else {
                bytes
            },
            Ordering::SeqCst,
        );
    }

    pub async fn send_ping(&self, payload: Bytes) -> Result<(), TransportError> {
        self.command(Command::Ping(payload)).await
    }

    async fn command(&self, command: Command) -> Result<(), TransportError> {
        if self.is_closed() {
            return Err(TransportError::Closed);
        }
        self.inner
            .commands
            .send(command)
            .await
            .map_err(|_| TransportError::Closed)
    }

    /// Receive the next application message. Ping/Pong/Close are handled by
    /// the I/O task. Returns `None` when the peer or carrier closed.
    pub async fn recv(&self) -> Result<Option<WsMessage>, TransportError> {
        let mut rx = self.inner.inbound.lock().await;
        loop {
            let message = rx.recv().await;
            let Some(WsMessage::Binary(bytes)) = message else {
                return Ok(message);
            };
            let Some(session) = self.noise_session() else {
                return Ok(Some(WsMessage::Binary(bytes)));
            };
            let plaintext = session.open(&bytes)?;
            let Some((kind, payload)) = plaintext.split_first() else {
                return Err(TransportError::Security(SecurityError::Protocol));
            };
            match *kind {
                SECURE_DATA => return Ok(Some(WsMessage::Binary(Bytes::copy_from_slice(payload)))),
                SECURE_REKEY => {
                    session.rekey_incoming();
                    continue;
                }
                _ => return Err(TransportError::Security(SecurityError::Protocol)),
            }
        }
    }

    /// Install the authenticated transport cipher. This happens only after the
    /// Noise XX handshake and secure prelude have completed.
    pub fn install_noise(&self, session: Arc<NoiseSession>) {
        *self.inner.noise.lock().expect("noise session lock") = Some(session);
    }

    pub fn is_secure(&self) -> bool {
        self.inner
            .noise
            .lock()
            .expect("noise session lock")
            .is_some()
    }

    fn noise_session(&self) -> Option<Arc<NoiseSession>> {
        self.inner.noise.lock().expect("noise session lock").clone()
    }

    pub async fn close(&self) {
        let _send_order = self.inner.send_order.lock().await;
        let _ = self.inner.commands.send(Command::Close).await;
        self.inner.closed.store(true, Ordering::SeqCst);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub(crate) async fn set_relay_role(&self, role: oct_protocol::relay::RelayRole) {
        *self.inner.relay_role.lock().await = Some(role);
    }

    pub(crate) async fn relay_role(&self) -> Option<oct_protocol::relay::RelayRole> {
        *self.inner.relay_role.lock().await
    }
}

#[async_trait::async_trait]
impl NoiseIo for WsConnection {
    async fn send_handshake(&self, message: Vec<u8>) -> Result<(), SecurityError> {
        self.send_binary(Bytes::from(message))
            .await
            .map_err(|_| SecurityError::Handshake)
    }

    async fn recv_handshake(&self) -> Result<Vec<u8>, SecurityError> {
        loop {
            match self.recv().await.map_err(|_| SecurityError::Handshake)? {
                Some(WsMessage::Binary(bytes)) => return Ok(bytes.to_vec()),
                Some(WsMessage::Text(text)) => {
                    if let Ok(oct_protocol::relay::RelayControl::Ping) =
                        oct_protocol::relay::RelayControl::decode(&text)
                    {
                        if let Ok(pong) = oct_protocol::relay::RelayControl::Pong.encode() {
                            let _ = self.send_text(pong).await;
                        }
                        continue;
                    }
                    return Err(SecurityError::Handshake);
                }
                None => return Err(SecurityError::Handshake),
            }
        }
    }
}

async fn run_socket<S>(
    stream: WebSocketStream<S>,
    mut commands: mpsc::Receiver<Command>,
    inbound: mpsc::Sender<WsMessage>,
    closed: Arc<AtomicBool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut events) = stream.split();
    let mut close_sent = false;

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break; };
                let result = match command {
                    Command::Text(text) => sink.send(Message::Text(text.into())).await,
                    Command::Binary(bytes) => sink.send(Message::Binary(bytes)).await,
                    Command::Ping(payload) => sink.send(Message::Ping(payload)).await,
                    Command::Close => {
                        close_sent = true;
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                };
                if let Err(err) = result {
                    tracing::debug!(error = %err, "websocket write failed");
                    break;
                }
            }
            event = events.next() => {
                match event {
                    Some(Ok(Message::Text(text))) => {
                        if inbound.send(WsMessage::Text(text.as_str().to_owned())).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        if inbound.send(WsMessage::Binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sink.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) => {
                        close_sent = true;
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    Some(Err(err)) => {
                        tracing::debug!(error = %err, "websocket read failed");
                        break;
                    }
                    None => break,
                }
            }
        }
    }

    closed.store(true, Ordering::SeqCst);
    if !close_sent {
        let _ = sink.close().await;
    }
    drop(inbound);
}
