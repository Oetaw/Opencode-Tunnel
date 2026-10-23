use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::error::SecurityError;
use crate::identity::{parse_public_key, public_key_hex, Identity};

pub const IDENTITY_FILE: &str = "identity.json";
const IDENTITY_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    public_key: String,
}

/// Directory-backed secret storage with restrictive permissions and atomic
/// replacement. The directory is `0700`; secret files are `0600` on Unix.
#[derive(Debug, Clone)]
pub struct Keystore {
    dir: PathBuf,
    use_keyring: bool,
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            use_keyring: false,
        }
    }

    /// Store the private identity in the OS credential store. Only the public
    /// key and metadata remain in `identity.json`.
    pub fn with_keyring(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            use_keyring: true,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn ensure_dir(&self) -> Result<(), SecurityError> {
        fs::create_dir_all(&self.dir)?;
        set_dir_permissions(&self.dir)?;
        Ok(())
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir.join(IDENTITY_FILE)
    }

    pub fn load_identity(&self) -> Result<Option<Identity>, SecurityError> {
        let path = self.identity_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let file: IdentityFile = serde_json::from_slice(&bytes)?;
        if file.version != IDENTITY_VERSION {
            return Err(SecurityError::InvalidIdentity);
        }
        let secret = if let Some(secret_key) = &file.secret_key {
            STANDARD_NO_PAD
                .decode(secret_key.as_bytes())
                .map_err(|_| SecurityError::InvalidIdentity)?
        } else if self.use_keyring {
            keyring_entry(&file.public_key)?
                .get_secret()
                .map_err(|error| SecurityError::Keyring(error.to_string()))?
        } else {
            return Err(SecurityError::InvalidIdentity);
        };
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| SecurityError::InvalidIdentity)?;
        let identity = Identity::from_secret_bytes(secret);
        let expected = parse_public_key(&file.public_key)?;
        if identity.public_key() != expected {
            return Err(SecurityError::InvalidIdentity);
        }
        if self.use_keyring && file.secret_key.is_some() {
            self.save_identity(&identity)?;
        }
        Ok(Some(identity))
    }

    pub fn load_or_create_identity(&self) -> Result<Identity, SecurityError> {
        self.ensure_dir()?;
        let _file = self.lock_identity()?;
        if let Some(identity) = self.load_identity()? {
            if self.use_keyring && self.identity_has_file_secret()? {
                // Migrate a legacy 0600 file secret into the OS keyring.
                self.save_identity(&identity)?;
            }
            return Ok(identity);
        }
        let identity = Identity::generate();
        self.save_identity(&identity)?;
        Ok(identity)
    }

    fn lock_identity(&self) -> Result<File, SecurityError> {
        let lock_path = self.dir.join("identity.json.lock");
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

    pub fn save_identity(&self, identity: &Identity) -> Result<(), SecurityError> {
        self.ensure_dir()?;
        let public_key = public_key_hex(&identity.public_key());
        let file = if self.use_keyring {
            keyring_entry(&public_key)?
                .set_secret(identity.secret())
                .map_err(|error| SecurityError::Keyring(error.to_string()))?;
            IdentityFile {
                version: IDENTITY_VERSION,
                secret_key: None,
                public_key,
            }
        } else {
            IdentityFile {
                version: IDENTITY_VERSION,
                secret_key: Some(STANDARD_NO_PAD.encode(identity.secret())),
                public_key,
            }
        };
        write_private_json(&self.identity_path(), &file)
    }

    fn identity_has_file_secret(&self) -> Result<bool, SecurityError> {
        let bytes = fs::read(self.identity_path())?;
        let file: IdentityFile = serde_json::from_slice(&bytes)?;
        Ok(file.secret_key.is_some())
    }

    /// Save a public device list with the same atomic-write discipline.
    pub fn write_devices<T: Serialize>(&self, name: &str, value: &T) -> Result<(), SecurityError> {
        self.ensure_dir()?;
        write_private_json(&self.dir.join(name), value)
    }

    pub fn read_json<T: for<'de> Deserialize<'de>>(
        &self,
        name: &str,
    ) -> Result<Option<T>, SecurityError> {
        let path = self.dir.join(name);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
}

fn keyring_entry(public_key: &str) -> Result<keyring::Entry, SecurityError> {
    keyring::Entry::new("oct", &format!("identity:{public_key}"))
        .map_err(|error| SecurityError::Keyring(error.to_string()))
}

fn write_private_json<T: Serialize>(path: &Path, value: &T) -> Result<(), SecurityError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_dir_permissions(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let tmp = path.with_extension(format!("tmp-{}", rand_suffix()));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn rand_suffix() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<(), SecurityError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_persisted_with_restrictive_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::new(dir.path().join("oct"));
        let identity = store.load_or_create_identity().unwrap();
        let loaded = store.load_identity().unwrap().unwrap();
        assert_eq!(identity.public_key(), loaded.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.identity_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            let dir_mode = fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
        }
    }

    #[test]
    fn keyring_backend_keeps_the_secret_out_of_the_metadata_file() {
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::with_keyring(dir.path());
        let identity = store.load_or_create_identity().unwrap();
        let metadata = fs::read_to_string(store.identity_path()).unwrap();
        assert!(!metadata.contains("secret_key"));
        let loaded = store.load_identity().unwrap().unwrap();
        assert_eq!(identity.public_key(), loaded.public_key());
    }

    #[test]
    fn tampered_public_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Keystore::new(dir.path());
        let identity = Identity::generate();
        store.save_identity(&identity).unwrap();
        let path = store.identity_path();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["public_key"] = serde_json::Value::String(public_key_hex(&[9u8; 32]));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            store.load_identity(),
            Err(SecurityError::InvalidIdentity)
        ));
    }
}
