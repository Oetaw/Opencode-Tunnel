use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::error::SecurityError;
use crate::identity::{public_key_hex, PublicKeyBytes};
use crate::keystore::Keystore;

pub const DEVICES_FILE: &str = "devices.json";
const DEVICES_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    Writer,
    Observer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub role: DeviceRole,
    pub created_at: u64,
    #[serde(default)]
    pub last_seen: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
}

impl Device {
    pub fn public_key_bytes(&self) -> Result<PublicKeyBytes, SecurityError> {
        crate::identity::parse_public_key(&self.public_key)
    }

    pub fn fingerprint(&self) -> Result<String, SecurityError> {
        Ok(crate::identity::fingerprint(&self.public_key_bytes()?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DevicesFile {
    version: u8,
    devices: Vec<Device>,
}

impl Default for DevicesFile {
    fn default() -> Self {
        Self {
            version: DEVICES_VERSION,
            devices: Vec::new(),
        }
    }
}

/// Host-side device allowlist. Every mutation reloads under a process-local
/// mutex, writes atomically, and only then updates memory. A running host also
/// reloads this file periodically so `oct revoke` takes effect on future
/// handshakes and active sessions.
pub struct DeviceStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl DeviceStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir: PathBuf = dir.into();
        Self {
            path: dir.join(DEVICES_FILE),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_file(&self) -> Result<File, SecurityError> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        Keystore::new(dir).ensure_dir()?;
        let lock_path = self.path.with_extension("json.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(lock_path)?;
        file.lock_exclusive()?;
        Ok(file)
    }

    pub fn load(&self) -> Result<Vec<Device>, SecurityError> {
        let _guard = self.lock.lock().expect("device store lock");
        let _file = self.lock_file()?;
        Ok(self.load_unlocked()?.devices)
    }

    fn load_unlocked(&self) -> Result<DevicesFile, SecurityError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let file: DevicesFile = serde_json::from_slice(&bytes)?;
                if file.version != DEVICES_VERSION {
                    return Err(SecurityError::Json(serde_json::Error::io(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "unsupported device file version",
                        ),
                    )));
                }
                Ok(file)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DevicesFile::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn save_unlocked(&self, file: &DevicesFile) -> Result<(), SecurityError> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        Keystore::new(dir).write_devices(DEVICES_FILE, file)
    }

    pub fn is_authorized(&self, public_key: &PublicKeyBytes) -> Result<bool, SecurityError> {
        let expected = public_key_hex(public_key);
        Ok(self
            .load()?
            .into_iter()
            .any(|device| device.public_key == expected && !device.revoked))
    }

    pub fn find(&self, public_key: &PublicKeyBytes) -> Result<Option<Device>, SecurityError> {
        let expected = public_key_hex(public_key);
        Ok(self
            .load()?
            .into_iter()
            .find(|device| device.public_key == expected))
    }

    /// Authorize a new device after a valid one-time invite was consumed.
    /// Returns the existing active device for repeat connections.
    pub fn authorize(
        &self,
        public_key: &PublicKeyBytes,
        name: &str,
    ) -> Result<Device, SecurityError> {
        let _guard = self.lock.lock().expect("device store lock");
        let _file = self.lock_file()?;
        let mut file = self.load_unlocked()?;
        let expected = public_key_hex(public_key);
        if let Some(existing) = file
            .devices
            .iter()
            .find(|device| device.public_key == expected)
        {
            if existing.revoked {
                return Err(SecurityError::Unauthorized);
            }
            return Ok(existing.clone());
        }
        let now = unix_now();
        let device = Device {
            id: crate::identity::fingerprint(public_key)[..16].to_owned(),
            name: bounded_name(name),
            public_key: expected,
            role: DeviceRole::Writer,
            created_at: now,
            last_seen: Some(now),
            revoked: false,
        };
        file.devices.push(device.clone());
        self.save_unlocked(&file)?;
        Ok(device)
    }

    /// Atomically verify and update an existing authorized device. Returns
    /// `None` if the device is unknown or revoked; the caller must not fall
    /// back to invite enrollment for a revoked key.
    pub fn authorize_existing(
        &self,
        public_key: &PublicKeyBytes,
    ) -> Result<Option<Device>, SecurityError> {
        let expected = public_key_hex(public_key);
        let _guard = self.lock.lock().expect("device store lock");
        let _file = self.lock_file()?;
        let mut file = self.load_unlocked()?;
        let Some(device) = file
            .devices
            .iter_mut()
            .find(|device| device.public_key == expected && !device.revoked)
        else {
            return Ok(None);
        };
        device.last_seen = Some(unix_now());
        let result = device.clone();
        self.save_unlocked(&file)?;
        Ok(Some(result))
    }

    /// Revoke by device id or public-key fingerprint prefix. Returns the
    /// revoked device, if found.
    pub fn revoke(&self, selector: &str) -> Result<Option<Device>, SecurityError> {
        let _guard = self.lock.lock().expect("device store lock");
        let _file = self.lock_file()?;
        let mut file = self.load_unlocked()?;
        let selector = selector.trim();
        let mut revoked = None;
        for device in &mut file.devices {
            let matches = device.id == selector || device.public_key.eq_ignore_ascii_case(selector);

            if matches && !device.revoked {
                device.revoked = true;
                revoked = Some(device.clone());
                break;
            }
        }
        if revoked.is_some() {
            self.save_unlocked(&file)?;
        }
        Ok(revoked)
    }
}

fn bounded_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "device".to_owned();
    }
    trimmed.chars().take(64).collect()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKeyBytes {
        [byte; 32]
    }

    #[test]
    fn authorize_then_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path());
        let device = store.authorize(&key(1), "laptop").unwrap();
        assert!(store.is_authorized(&key(1)).unwrap());
        assert!(store.revoke(&device.id).unwrap().is_some());
        assert!(!store.is_authorized(&key(1)).unwrap());
        assert!(matches!(
            store.authorize(&key(1), "again"),
            Err(SecurityError::Unauthorized)
        ));
    }

    #[test]
    fn concurrent_cross_instance_revoke_is_not_lost() {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let initial = DeviceStore::new(dir.path());
        let device = initial.authorize(&key(4), "phone").unwrap();
        let barrier = Arc::new(Barrier::new(2));

        let d1 = DeviceStore::new(dir.path());
        let id = device.id.clone();
        let barrier1 = Arc::clone(&barrier);
        let revoker = std::thread::spawn(move || {
            barrier1.wait();
            d1.revoke(&id).unwrap()
        });
        let d2 = DeviceStore::new(dir.path());
        let barrier2 = Arc::clone(&barrier);
        let checker = std::thread::spawn(move || {
            barrier2.wait();
            d2.authorize_existing(&key(4)).unwrap()
        });

        assert!(revoker.join().unwrap().is_some());
        let _ = checker.join().unwrap();
        assert!(!initial.is_authorized(&key(4)).unwrap());
    }

    #[test]
    fn second_device_is_also_authorized() {
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path());
        store.authorize(&key(2), "one").unwrap();
        store.authorize(&key(3), "two").unwrap();
        assert_eq!(store.load().unwrap().len(), 2);
    }
}
