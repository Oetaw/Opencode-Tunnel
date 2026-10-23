//! OCT/1 wire protocol.
//!
//! The protocol has two layers:
//!
//! * [`relay`] — the clear-text control envelope spoken between an endpoint and
//!   the public relay. It contains routing metadata only.
//! * the inner [`Frame`] model — a bounded, deterministic binary framing that
//!   is carried inside the relay's opaque binary messages. In Phase 1 it is
//!   sent directly over WSS; from Phase 2 onward it is wrapped in Noise AEAD.

pub mod codec;
pub mod errors;
pub mod hello;
pub mod httpwire;
pub mod relay;
pub mod types;

pub use codec::{decode_frame, decode_frame_exact, encode_frame, encode_frame_to_vec};
pub use errors::{ErrorCode, ProtocolError};
pub use hello::{Feature, Hello, Limits, Role};
pub use httpwire::{
    HttpRequestHead, HttpResponseHead, OpenWs, WsOpcode, MAX_WS_CLOSE_REASON, MAX_WS_MESSAGE,
};
pub use types::{Flags, Frame, Kind, MAX_FRAME_PAYLOAD, PROTOCOL_MAJOR, PROTOCOL_MINOR};
