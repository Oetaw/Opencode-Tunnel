//! Transport: outbound WSS, relay control handshake, and the OCT stream mux.
//!
//! This crate owns framing and lifecycle only. It has no OpenCode knowledge
//! and no decryption keys in Phase 1.

mod backoff;
mod mux;
mod ping;
mod relay;
mod socket;
mod stream;

pub use backoff::Backoff;
pub use mux::{Inbound, Mux, MuxConfig, NoopHandler, OpenHandler};
pub use ping::{run_periodic_ping, send_ws_ping};
pub use relay::{register, wait_for_peer};
pub use socket::{WsConnection, WsMessage, WsOptions};
pub use stream::Stream;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("invalid websocket URL: {0}")]
    InvalidUrl(String),
    #[error("websocket error: {0}")]
    WebSocket(String),
    #[error("websocket connect timed out")]
    ConnectTimeout,
    #[error("websocket message exceeds the configured bound")]
    MessageTooLarge,
    #[error("transport is closed")]
    Closed,
    #[error("protocol error: {0}")]
    Protocol(#[from] oct_protocol::ProtocolError),
    #[error("security error: {0}")]
    Security(#[from] oct_security::SecurityError),
    #[error("relay control error: {0}")]
    Relay(#[from] oct_protocol::relay::RelayError),
    #[error("relay rejected the connection: {code}: {message}")]
    RelayRejected { code: String, message: String },
    #[error("relay peer left")]
    PeerLeft,
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("stream is closed")]
    StreamClosed,
    #[error("mux is not ready for streams")]
    NotReady,
    #[error("too many concurrent streams")]
    TooManyStreams,
    #[error("requested protocol feature was not negotiated")]
    FeatureUnsupported,
    #[error("mux is closed")]
    MuxClosed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("operation cancelled")]
    Cancelled,
    #[error("internal transport error: {0}")]
    Internal(String),
}

impl From<tokio_tungstenite::tungstenite::Error> for TransportError {
    fn from(value: tokio_tungstenite::tungstenite::Error) -> Self {
        use tokio_tungstenite::tungstenite::Error as E;
        match value {
            E::Capacity(tokio_tungstenite::tungstenite::error::CapacityError::MessageTooLong {
                ..
            }) => Self::MessageTooLarge,
            other => Self::WebSocket(other.to_string()),
        }
    }
}
