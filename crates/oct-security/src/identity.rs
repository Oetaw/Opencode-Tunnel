use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::SecurityError;

pub type PublicKeyBytes = [u8; 32];

const FINGERPRINT_DOMAIN: &[u8] = b"oct-identity-fingerprint-v1\0";

/// A persistent X25519 static identity. The private bytes are zeroized on drop
/// and are never included in `Debug`.
pub struct Identity {
    secret: [u8; 32],
    public: PublicKeyBytes,
}

impl Identity {
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self::from_secret_bytes(secret)
    }

    pub fn from_secret_bytes(mut secret: [u8; 32]) -> Self {
        let static_secret = StaticSecret::from(secret);
        let public = X25519PublicKey::from(&static_secret).to_bytes();
        secret.zeroize();
        let stored = *static_secret.as_bytes();
        drop(static_secret);
        Self {
            secret: stored,
            public,
        }
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        self.public
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

pub fn fingerprint(public: &PublicKeyBytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(public);
    hex::encode(hasher.finalize())
}

pub fn parse_public_key(value: &str) -> Result<PublicKeyBytes, SecurityError> {
    let bytes = hex::decode(value).map_err(|_| SecurityError::InvalidPublicKey)?;
    bytes
        .try_into()
        .map_err(|_| SecurityError::InvalidPublicKey)
}

pub fn public_key_hex(public: &PublicKeyBytes) -> String {
    hex::encode(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_domain_separated_and_stable() {
        let key = [7u8; 32];
        let value = fingerprint(&key);
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(value, fingerprint(&key));
        assert_ne!(value, hex::encode(key));
    }

    #[test]
    fn generated_identity_roundtrips_public_key() {
        let identity = Identity::generate();
        let encoded = hex::encode(identity.secret());
        let restored =
            Identity::from_secret_bytes(hex::decode(&encoded).unwrap().try_into().unwrap());
        assert_eq!(identity.public_key(), restored.public_key());
        assert_eq!(identity.fingerprint(), restored.fingerprint());
        assert!(!format!("{identity:?}").contains(&encoded));
    }
}
