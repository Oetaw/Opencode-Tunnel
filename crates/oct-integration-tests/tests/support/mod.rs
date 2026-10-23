//! Shared relay credentials for integration tests.
//!
//! Relays now require a host admission token. E2EE rooms install a distinct,
//! room-scoped client token so a client cannot claim the host role.

#![allow(dead_code)]

use oct_protocol::relay::generate_room_credentials;
use oct_security::derive_client_token;

/// Deterministic admission token used by tests. Never use in production.
pub const ADMISSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Room plus the credentials for an E2EE host/client pair.
pub fn e2ee_credentials() -> (String, String, String) {
    let (room, _) = generate_room_credentials();
    let client_token = derive_client_token(ADMISSION, &room).expect("derive client token");
    (room, ADMISSION.to_owned(), client_token)
}

/// Room plus the shared credential for the explicit legacy plaintext mode.
pub fn plaintext_credentials() -> (String, String) {
    let (room, _) = generate_room_credentials();
    (room, ADMISSION.to_owned())
}
