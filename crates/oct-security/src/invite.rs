use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::devices::unix_now;
use crate::error::SecurityError;
use crate::identity::{parse_public_key, public_key_hex, PublicKeyBytes};
use crate::keystore::Keystore;
use oct_protocol::relay::{validate_room, validate_token};
use url::Url;

pub const INVITE_PREFIX: &str = "octpair1:";
pub const DEFAULT_TTL_SECS: u64 = 300;
const INVITE_VERSION: u8 = 1;
const MAX_INVITE_LEN: usize = 8192;
const SECRET_LEN: usize = 32;

#[derive(Clone, Serialize, Deserialize)]
pub struct Invite {
    pub version: u8,
    pub relay_url: String,
    pub room: String,
    pub token: String,
    pub host_public_key: String,
    pub secret: String,
    pub expires_at: u64,
    #[serde(default)]
    pub label: Option<String>,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("version", &self.version)
            .field("relay_url", &self.relay_url)
            .field("room", &self.room)
            .field("token", &"<redacted>")
            .field("host_public_key", &self.host_public_key)
            .field("secret", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("label", &self.label)
            .finish()
    }
}

impl Invite {
    pub fn new(
        relay_url: impl Into<String>,
        room: impl Into<String>,
        token: impl Into<String>,
        host_public_key: PublicKeyBytes,
        ttl_secs: u64,
        label: Option<String>,
    ) -> Result<Self, SecurityError> {
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        let invite = Self {
            version: INVITE_VERSION,
            relay_url: relay_url.into(),
            room: room.into(),
            token: token.into(),
            host_public_key: public_key_hex(&host_public_key),
            secret: URL_SAFE_NO_PAD.encode(secret),
            expires_at: unix_now() + ttl_secs.clamp(30, 3600),
            label,
        };
        invite.validate(unix_now())?;
        Ok(invite)
    }

    pub fn host_public_key(&self) -> Result<PublicKeyBytes, SecurityError> {
        parse_public_key(&self.host_public_key)
    }

    pub fn secret_bytes(&self) -> Result<[u8; SECRET_LEN], SecurityError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(self.secret.as_bytes())
            .map_err(|_| SecurityError::InvalidInvite)?;
        bytes.try_into().map_err(|_| SecurityError::InvalidInvite)
    }

    pub fn secret_hash(&self) -> Result<String, SecurityError> {
        Ok(secret_hash(&self.secret_bytes()?))
    }

    pub fn validate(&self, now: u64) -> Result<(), SecurityError> {
        if self.version != INVITE_VERSION
            || self.relay_url.len() > 512
            || self.expires_at <= now
            || self.secret_bytes().is_err()
        {
            return Err(if self.expires_at <= now {
                SecurityError::InviteExpired
            } else {
                SecurityError::InvalidInvite
            });
        }
        validate_room(&self.room).map_err(|_| SecurityError::InvalidInvite)?;
        validate_token(&self.token).map_err(|_| SecurityError::InvalidInvite)?;
        let relay = Url::parse(&self.relay_url).map_err(|_| SecurityError::InvalidInvite)?;
        if !matches!(relay.scheme(), "ws" | "wss")
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.query().is_some()
            || relay.fragment().is_some()
        {
            return Err(SecurityError::InvalidInvite);
        }
        let loopback = match relay.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            None => false,
        };
        if relay.scheme() == "ws" && !loopback {
            return Err(SecurityError::InvalidInvite);
        }
        self.host_public_key()?;
        Ok(())
    }

    /// Canonical pair deep link. The invite contains the relay token and the
    /// one-time secret, so callers must not log the result.
    pub fn encode(&self) -> Result<String, SecurityError> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_INVITE_LEN {
            return Err(SecurityError::TooLarge);
        }
        Ok(format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
    }

    pub fn decode(value: &str) -> Result<Self, SecurityError> {
        let value = value.trim();
        if value.len() > MAX_INVITE_LEN + INVITE_PREFIX.len() {
            return Err(SecurityError::TooLarge);
        }
        let encoded = value
            .strip_prefix(INVITE_PREFIX)
            .ok_or(SecurityError::InvalidInvite)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| SecurityError::InvalidInvite)?;
        if bytes.len() > MAX_INVITE_LEN {
            return Err(SecurityError::TooLarge);
        }
        let invite: Self = serde_json::from_slice(&bytes)?;
        invite.validate(unix_now())?;
        Ok(invite)
    }
}

fn secret_hash(secret: &[u8; SECRET_LEN]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"oct-invite-secret-v1\0");
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

#[derive(Serialize, Deserialize)]
struct InviteRecord {
    version: u8,
    expires_at: u64,
    label: Option<String>,
}

/// Host-side one-time invite records. Consuming claims a `.used` marker with
/// `create_new`, so concurrent attempts have exactly one winner.
#[derive(Debug, Clone)]
pub struct InviteStore {
    dir: PathBuf,
}

impl InviteStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn create(&self, invite: &Invite) -> Result<(), SecurityError> {
        fs::create_dir_all(&self.dir)?;
        let record = InviteRecord {
            version: INVITE_VERSION,
            expires_at: invite.expires_at,
            label: invite.label.clone(),
        };
        let hash = invite.secret_hash()?;
        Keystore::new(&self.dir).write_devices(&format!("{hash}.json"), &record)
    }

    /// Consume the invite matching `secret`. The record is read and validated
    /// before an atomic claim marker is created.
    pub fn consume(&self, secret: &str) -> Result<(), SecurityError> {
        let secret = URL_SAFE_NO_PAD
            .decode(secret.as_bytes())
            .map_err(|_| SecurityError::InvalidInvite)?;
        let secret: [u8; SECRET_LEN] = secret
            .try_into()
            .map_err(|_| SecurityError::InvalidInvite)?;
        let hash = secret_hash(&secret);
        let record_path = self.dir.join(format!("{hash}.json"));
        let record_bytes = fs::read(&record_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SecurityError::InvalidInvite
            } else {
                SecurityError::Io(error)
            }
        })?;
        let record: InviteRecord = serde_json::from_slice(&record_bytes)?;
        if record.version != INVITE_VERSION {
            return Err(SecurityError::InvalidInvite);
        }
        if record.expires_at <= unix_now() {
            return Err(SecurityError::InviteExpired);
        }
        let claim = self.dir.join(format!("{hash}.used"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(&claim) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(SecurityError::InviteUsed);
            }
            Err(error) => return Err(error.into()),
        };
        let _ = file.write_all(b"used\n");
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Invite {
        Invite::new(
            "ws://127.0.0.1:8080/oct/v1",
            "room-0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            [3u8; 32],
            DEFAULT_TTL_SECS,
            Some("test".into()),
        )
        .unwrap()
    }

    #[test]
    fn encode_decode_roundtrip_and_expiry() {
        let invite = invite();
        let encoded = invite.encode().unwrap();
        assert!(encoded.starts_with(INVITE_PREFIX));
        let decoded = Invite::decode(&encoded).unwrap();
        assert_eq!(decoded.host_public_key().unwrap(), [3u8; 32]);
        assert!(matches!(
            Invite::decode("octpair1:not-base64!"),
            Err(SecurityError::InvalidInvite)
        ));
    }

    #[test]
    fn debug_redacts_token_and_secret() {
        let invite = invite();
        let text = format!("{invite:?}");
        assert!(!text.contains(&invite.token));
        assert!(!text.contains(&invite.secret));
        assert!(text.contains("<redacted>"));
    }

    #[test]
    fn invite_can_be_consumed_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path());
        let invite = invite();
        store.create(&invite).unwrap();
        assert!(store.consume(&invite.secret).is_ok());
        assert!(matches!(
            store.consume(&invite.secret),
            Err(SecurityError::InviteUsed)
        ));
    }

    #[test]
    fn unknown_secret_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path());
        let mut invite = invite();
        invite.secret = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert!(matches!(
            store.consume(&invite.secret),
            Err(SecurityError::InvalidInvite)
        ));
    }
}
