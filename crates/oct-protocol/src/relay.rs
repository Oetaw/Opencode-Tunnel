//! Clear-text relay control envelope.
//!
//! The relay sees only: room id, role, admission/client credentials, timing,
//! and opaque binary frame sizes. Application HTTP headers and bodies are
//! inside the opaque binary messages and are never parsed here.
//!
//! Control messages are JSON text websocket messages; every binary websocket
//! message is relayed verbatim to the peer.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const RELAY_PATH: &str = "/oct/v1";
/// Relay control protocol version.
///
/// Version 2 separates the host admission credential from the client
/// credential and reserves room creation for authenticated hosts.
pub const RELAY_PROTOCOL: u8 = 2;
pub const MAX_CONTROL_BYTES: usize = 16 * 1024;
pub const MAX_ROOM_ID_LEN: usize = 128;
pub const MIN_ROOM_ID_LEN: usize = 16;
pub const MAX_TOKEN_LEN: usize = 256;
pub const MAX_RELAY_BINARY_FRAME: usize = crate::types::MAX_FRAME_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    Host,
    Client,
}

impl RelayRole {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Client => "client",
        }
    }

    pub const fn peer(self) -> Self {
        match self {
            Self::Host => Self::Client,
            Self::Client => Self::Host,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayControl {
    Hello {
        protocol: u8,
        room: String,
        role: RelayRole,
        /// Host admission credential for `host`, client room credential for
        /// `client`.
        token: String,
        /// Client credential a host installs when it creates a room. Clients
        /// never send this field. Optional so plaintext loopback rooms can use
        /// the legacy single-token mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_token: Option<String>,
        #[serde(default)]
        client_version: Option<String>,
    },
    Ready {
        protocol: u8,
        room: String,
        role: RelayRole,
    },
    PeerJoined {
        role: RelayRole,
    },
    PeerLeft {
        role: RelayRole,
    },
    /// Host-only request to remove the client slot after a failed device
    /// authorization or Noise handshake. A revoked client must not be able to
    /// hold the client slot forever.
    Evict {
        role: RelayRole,
    },
    Ping,
    Pong,
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("invalid room id")]
    InvalidRoom,
    #[error("invalid token")]
    InvalidToken,
    #[error("unsupported relay protocol {0}")]
    UnsupportedProtocol(u8),
    #[error("invalid control message: {0}")]
    InvalidControl(String),
    #[error("room is full")]
    RoomFull,
    #[error("role already connected")]
    RoleOccupied,
    #[error("peer is offline")]
    PeerOffline,
    #[error("control message too large")]
    ControlTooLarge,
    #[error("binary frame too large")]
    FrameTooLarge,
}

impl fmt::Debug for RelayControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello {
                protocol,
                room,
                role,
                token: _,
                client_token,
                client_version,
            } => f
                .debug_struct("Hello")
                .field("protocol", protocol)
                .field("room", room)
                .field("role", role)
                .field("token", &"<redacted>")
                .field("client_token", &client_token.as_ref().map(|_| "<redacted>"))
                .field("client_version", client_version)
                .finish(),
            Self::Ready {
                protocol,
                room,
                role,
            } => f
                .debug_struct("Ready")
                .field("protocol", protocol)
                .field("room", room)
                .field("role", role)
                .finish(),
            Self::PeerJoined { role } => f.debug_struct("PeerJoined").field("role", role).finish(),
            Self::PeerLeft { role } => f.debug_struct("PeerLeft").field("role", role).finish(),
            Self::Evict { role } => f.debug_struct("Evict").field("role", role).finish(),
            Self::Ping => f.write_str("Ping"),
            Self::Pong => f.write_str("Pong"),
            Self::Error { code, message: _ } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", &"<redacted>")
                .finish(),
        }
    }
}

impl RelayControl {
    /// Validate a relay hello envelope before it reaches room state. This is
    /// the fail-closed entry point for relays; `decode` alone only parses.
    pub fn validate_hello(&self) -> Result<(), RelayError> {
        let Self::Hello {
            protocol,
            room,
            role,
            token,
            client_token,
            client_version,
        } = self
        else {
            return Err(RelayError::InvalidControl("expected hello".into()));
        };
        if *protocol != RELAY_PROTOCOL {
            return Err(RelayError::UnsupportedProtocol(*protocol));
        }
        validate_room(room)?;
        validate_token(token)?;
        if let Some(client_token) = client_token {
            validate_token(client_token)?;
            if *role == RelayRole::Client {
                return Err(RelayError::InvalidControl(
                    "client_token is host-only".into(),
                ));
            }
        }
        if let Some(version) = client_version {
            if version.len() > 128 || !version.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
                return Err(RelayError::InvalidControl("client_version".into()));
            }
        }
        Ok(())
    }

    pub fn validate_ready(
        &self,
        expected_room: &str,
        expected_role: RelayRole,
    ) -> Result<(), RelayError> {
        match self {
            Self::Ready {
                protocol,
                room,
                role,
            } if *protocol == RELAY_PROTOCOL && room == expected_room && *role == expected_role => {
                Ok(())
            }
            _ => Err(RelayError::InvalidControl("unexpected ready".into())),
        }
    }

    pub fn validate_peer_joined(&self, expected: RelayRole) -> Result<(), RelayError> {
        match self {
            Self::PeerJoined { role } if *role == expected => Ok(()),
            _ => Err(RelayError::InvalidControl("unexpected peer_joined".into())),
        }
    }

    pub fn encode(&self) -> Result<String, RelayError> {
        let text =
            serde_json::to_string(self).map_err(|e| RelayError::InvalidControl(e.to_string()))?;
        if text.len() > MAX_CONTROL_BYTES {
            return Err(RelayError::ControlTooLarge);
        }
        Ok(text)
    }

    pub fn decode(text: &str) -> Result<Self, RelayError> {
        if text.len() > MAX_CONTROL_BYTES {
            return Err(RelayError::ControlTooLarge);
        }
        serde_json::from_str(text).map_err(|e| RelayError::InvalidControl(e.to_string()))
    }
}

pub fn validate_room(room: &str) -> Result<(), RelayError> {
    if room.len() < MIN_ROOM_ID_LEN || room.len() > MAX_ROOM_ID_LEN {
        return Err(RelayError::InvalidRoom);
    }
    if !room
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(RelayError::InvalidRoom);
    }
    Ok(())
}

pub fn validate_token(token: &str) -> Result<(), RelayError> {
    if token.len() < 32 || token.len() > MAX_TOKEN_LEN {
        return Err(RelayError::InvalidToken);
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(RelayError::InvalidToken);
    }
    Ok(())
}

/// Generate a 128-bit room id and a 256-bit pre-shared token.
pub fn generate_room_credentials() -> (String, String) {
    use rand::RngCore;
    let mut room = [0u8; 16];
    let mut token = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut room);
    rand::thread_rng().fill_bytes(&mut token);
    (hex::encode(room), hex::encode(token))
}

/// Constant-time token comparison for the relay. A malformed length is always
/// rejected; equal-length tokens are compared without early exit.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    if expected.len() != presented.len() {
        return false;
    }
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_roundtrip() {
        let msg = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: "0123456789abcdef".into(),
            role: RelayRole::Host,
            token: "x".repeat(64),
            client_token: Some("y".repeat(64)),
            client_version: None,
        };
        let text = msg.encode().unwrap();
        assert_eq!(RelayControl::decode(&text).unwrap(), msg);
    }

    #[test]
    fn rejects_short_room() {
        assert!(validate_room("short").is_err());
    }

    #[test]
    fn rejects_slash_in_room() {
        assert!(validate_room("0123456789abcde/").is_err());
    }

    #[test]
    fn token_compare() {
        let a = "a".repeat(64);
        assert!(token_matches(&a, &a));
        assert!(!token_matches(&a, &"b".repeat(64)));
        assert!(!token_matches(&a, "short"));
    }

    #[test]
    fn generated_credentials_are_valid() {
        let (room, token) = generate_room_credentials();
        assert!(validate_room(&room).is_ok());
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn validate_hello_rejects_empty_token() {
        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: "0123456789abcdef".into(),
            role: RelayRole::Host,
            token: String::new(),
            client_token: None,
            client_version: None,
        };
        assert!(hello.validate_hello().is_err());
    }

    #[test]
    fn client_hello_must_not_install_a_client_token() {
        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: "0123456789abcdef".into(),
            role: RelayRole::Client,
            token: "x".repeat(64),
            client_token: Some("y".repeat(64)),
            client_version: None,
        };
        assert!(hello.validate_hello().is_err());
    }

    #[test]
    fn old_relay_protocol_is_rejected() {
        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL - 1,
            room: "0123456789abcdef".into(),
            role: RelayRole::Host,
            token: "x".repeat(64),
            client_token: Some("y".repeat(64)),
            client_version: None,
        };
        assert!(matches!(
            hello.validate_hello(),
            Err(RelayError::UnsupportedProtocol(_))
        ));
    }

    #[test]
    fn debug_redacts_token_and_message() {
        let hello = RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: "0123456789abcdef".into(),
            role: RelayRole::Host,
            token: "secret-token".into(),
            client_token: Some("client-secret-token".into()),
            client_version: None,
        };
        let text = format!("{hello:?}");
        assert!(!text.contains("secret-token"));
        assert!(!text.contains("client-secret-token"));
        assert!(text.contains("<redacted>"));
    }
}
