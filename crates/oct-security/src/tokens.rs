//! Relay credential separation.
//!
//! The host keeps an admission credential. Clients never receive it. Instead,
//! the host derives one client credential per room with a keyed hash. The
//! relay learns the derived client credential when the host creates the room;
//! a client that receives an invite can join that room, but cannot derive the
//! host credential or create another room.

use hmac::{Hmac, Mac};
use oct_protocol::relay::{validate_room, validate_token};
use sha2::Sha256;

use crate::error::SecurityError;

type HmacSha256 = Hmac<Sha256>;

/// Derive the room-scoped client credential from the host admission token.
///
/// This is deliberately one-way: knowing the client token does not reveal the
/// admission token. Different rooms produce unrelated client tokens.
pub fn derive_client_token(host_token: &str, room: &str) -> Result<String, SecurityError> {
    validate_token(host_token).map_err(|_| SecurityError::InvalidCredential)?;
    validate_room(room).map_err(|_| SecurityError::InvalidCredential)?;

    let mut mac = HmacSha256::new_from_slice(host_token.as_bytes())
        .map_err(|_| SecurityError::InvalidCredential)?;
    mac.update(b"oct/client-token/v2\0");
    mac.update(room.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "0123456789abcdef";

    #[test]
    fn derivation_is_deterministic_and_room_scoped() {
        let host = "a".repeat(64);
        let first = derive_client_token(&host, ROOM).unwrap();
        let second = derive_client_token(&host, ROOM).unwrap();
        let other_room = derive_client_token(&host, "fedcba9876543210").unwrap();

        assert_eq!(first, second);
        assert_ne!(first, other_room);
        assert_ne!(first, host);
        assert!(validate_token(&first).is_ok());
    }

    #[test]
    fn different_host_tokens_produce_different_client_tokens() {
        let first = derive_client_token(&"a".repeat(64), ROOM).unwrap();
        let second = derive_client_token(&"b".repeat(64), ROOM).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_malformed_credentials() {
        assert!(derive_client_token("short", ROOM).is_err());
        assert!(derive_client_token(&"a".repeat(64), "short").is_err());
    }
}
