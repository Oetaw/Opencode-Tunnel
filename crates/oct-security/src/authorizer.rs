use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::devices::{Device, DeviceStore};
use crate::error::SecurityError;
use crate::identity::{Identity, PublicKeyBytes};
use crate::invite::InviteStore;
use crate::keystore::Keystore;
use crate::prelude::ClientPrelude;

/// Host security state: persistent identity, authorized-device allowlist and
/// one-time invite store.
pub struct HostSecurity {
    pub identity: Identity,
    pub devices: DeviceStore,
    pub invites: InviteStore,
    writer: Arc<Mutex<Option<String>>>,
}

impl HostSecurity {
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let dir = dir.as_ref();
        Self::from_keystore(dir, Keystore::new(dir))
    }

    /// Load the host identity from a chosen backend (file or OS keyring) while
    /// keeping devices/invites in the state directory.
    pub fn from_keystore(dir: impl AsRef<Path>, keystore: Keystore) -> Result<Self, SecurityError> {
        let dir = dir.as_ref();
        keystore.ensure_dir()?;
        let identity = keystore.load_or_create_identity()?;
        Ok(Self {
            identity,
            devices: DeviceStore::new(dir),
            invites: InviteStore::new(dir.join("invites")),
            writer: Arc::new(Mutex::new(None)),
        })
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Authorize a Noise-authenticated client. Existing authorized devices are
    /// accepted without an invite; a new device must present a valid,
    /// unconsumed, unexpired one-time invite.
    pub fn authorize(
        &self,
        public_key: &PublicKeyBytes,
        prelude: &ClientPrelude,
    ) -> Result<Device, SecurityError> {
        if let Some(device) = self.devices.authorize_existing(public_key)? {
            return Ok(device);
        }
        if self
            .devices
            .find(public_key)?
            .is_some_and(|device| device.revoked)
        {
            return Err(SecurityError::Unauthorized);
        }
        let invite = prelude
            .invite
            .as_deref()
            .ok_or(SecurityError::Unauthorized)?;
        self.invites.consume(invite)?;
        self.devices.authorize(public_key, &prelude.device_name)
    }

    pub fn is_authorized(&self, public_key: &PublicKeyBytes) -> bool {
        self.devices.is_authorized(public_key).unwrap_or(false)
    }

    /// Acquire the single active writer lease. The lease is released when the
    /// returned guard is dropped. Observers/multi-writer support is a later
    /// protocol extension; this prevents stale writers from overlapping by
    /// construction.
    pub fn acquire_writer(&self, device_id: &str) -> Result<WriterLease, SecurityError> {
        let mut lease = self.writer.lock().expect("writer lease lock");
        if lease.is_some() {
            return Err(SecurityError::Unauthorized);
        }
        *lease = Some(device_id.to_owned());
        Ok(WriterLease {
            writer: Arc::clone(&self.writer),
            device_id: device_id.to_owned(),
        })
    }
}

pub struct WriterLease {
    writer: Arc<Mutex<Option<String>>>,
    device_id: String,
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        let mut lease = self.writer.lock().expect("writer lease lock");
        if lease.as_deref() == Some(self.device_id.as_str()) {
            *lease = None;
        }
    }
}

impl std::fmt::Debug for WriterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterLease")
            .field("device_id", &self.device_id)
            .finish()
    }
}

/// Client security state used for every reconnect. The invite is only sent
/// until the host accepts it; after enrollment the pinned key and device
/// identity are sufficient.
pub struct ClientSecurity {
    pub identity: Identity,
    pub pinned_host: PublicKeyBytes,
    pub device_name: String,
    invite: std::sync::Mutex<Option<String>>,
}

impl ClientSecurity {
    pub fn new(
        identity: Identity,
        pinned_host: PublicKeyBytes,
        device_name: impl Into<String>,
        invite: Option<String>,
    ) -> Self {
        Self {
            identity,
            pinned_host,
            device_name: device_name.into(),
            invite: std::sync::Mutex::new(invite),
        }
    }

    pub fn prelude(&self) -> ClientPrelude {
        let invite = self.invite.lock().expect("invite lock").clone();
        ClientPrelude::new(self.device_name.clone(), invite)
    }

    pub fn enrollment_accepted(&self) {
        *self.invite.lock().expect("invite lock") = None;
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::Invite;

    #[test]
    fn new_device_requires_a_valid_unconsumed_invite() {
        let dir = tempfile::tempdir().unwrap();
        let host = HostSecurity::load_or_create(dir.path()).unwrap();
        let client = Identity::generate();
        let key = client.public_key();

        assert!(matches!(
            host.authorize(&key, &ClientPrelude::new("laptop", None)),
            Err(SecurityError::Unauthorized)
        ));

        let invite = Invite::new(
            "ws://127.0.0.1:8080/oct/v1",
            "room-0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            host.identity.public_key(),
            300,
            None,
        )
        .unwrap();
        host.invites.create(&invite).unwrap();
        assert!(matches!(
            host.authorize(&key, &ClientPrelude::new("laptop", Some("wrong".into()))),
            Err(SecurityError::InvalidInvite)
        ));
        let device = host
            .authorize(
                &key,
                &ClientPrelude::new("laptop", Some(invite.secret.clone())),
            )
            .unwrap();
        assert_eq!(device.name, "laptop");
        host.devices.revoke(&device.id).unwrap();
        assert!(matches!(
            host.authorize(&key, &ClientPrelude::new("laptop", Some(invite.secret))),
            Err(SecurityError::Unauthorized)
        ));
    }

    #[test]
    fn writer_lease_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let host = HostSecurity::load_or_create(dir.path()).unwrap();
        let first = host.acquire_writer("device-a").unwrap();
        assert!(matches!(
            host.acquire_writer("device-b"),
            Err(SecurityError::Unauthorized)
        ));
        drop(first);
        assert!(host.acquire_writer("device-b").is_ok());
    }
}
