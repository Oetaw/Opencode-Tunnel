//! Public OCT relay: opaque room routing for host and client WSS connections.
//!
//! The relay is intentionally dumb. It validates outer control metadata,
//! matches one host with one client, and forwards binary messages verbatim.
//! It never parses OCT inner frames, HTTP heads, prompts, or application
//! bodies, and it has no decryption keys.

mod config;
mod metrics;
mod rooms;
mod server;

pub use config::RelayConfig;
pub use metrics::{Metrics, MetricsSnapshot};
pub use rooms::{Outbound, SharedRooms};
pub use server::Relay;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("invalid relay configuration: {0}")]
    Config(String),
    #[error("relay I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] oct_protocol::ProtocolError),
    #[error("relay control error: {0}")]
    Control(#[from] oct_protocol::relay::RelayError),
    #[error("role already connected")]
    RoleOccupied,
    #[error("invalid room token")]
    InvalidToken,
    #[error("room is full")]
    RoomFull,
    #[error("relay is at its room capacity")]
    AtCapacity,
    #[error("peer is offline")]
    PeerOffline,
    #[error("relay handshake timed out")]
    HelloTimeout,
    #[error("first relay message must be a valid hello")]
    InvalidHello,
    #[error("relay control or binary frame exceeds the configured limit")]
    Oversized,
    #[error("relay internal error: {0}")]
    Internal(String),
}
