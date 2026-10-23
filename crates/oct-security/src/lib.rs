//! OCT Phase 2 identities, Noise XX transport encryption, one-time invites and
//! host-side device authorization.
//!
//! The relay never sees plaintext application frames. Each reconnect performs
//! a fresh Noise handshake and derives fresh transport keys; the pinned host
//! key comes from the invite and is checked before the client sends its third
//! handshake message.

pub mod authorizer;
pub mod devices;
pub mod error;
pub mod identity;
pub mod invite;
pub mod keystore;
pub mod noise;
pub mod prelude;

pub use authorizer::{ClientSecurity, HostSecurity};
pub use devices::{Device, DeviceRole, DeviceStore};
pub use error::SecurityError;
pub use identity::{fingerprint, parse_public_key, public_key_hex, Identity, PublicKeyBytes};
pub use invite::{Invite, InviteStore, DEFAULT_TTL_SECS as DEFAULT_INVITE_TTL};
pub use keystore::Keystore;
pub use noise::{client_handshake, host_handshake, NoiseHandshake, NoiseIo, NoiseSession};
pub use prelude::{ClientPrelude, HostPrelude};
