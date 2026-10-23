use serde::{Deserialize, Serialize};

use crate::error::SecurityError;

pub const PRELUDE_VERSION: u8 = 1;
pub const MAX_PRELUDE_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPrelude {
    pub version: u8,
    pub device_name: String,
    #[serde(default)]
    pub invite: Option<String>,
}

impl ClientPrelude {
    pub fn new(device_name: impl Into<String>, invite: Option<String>) -> Self {
        Self {
            version: PRELUDE_VERSION,
            device_name: device_name.into(),
            invite,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SecurityError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PRELUDE_BYTES {
            return Err(SecurityError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() > MAX_PRELUDE_BYTES {
            return Err(SecurityError::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), SecurityError> {
        if self.version != PRELUDE_VERSION
            || self.device_name.is_empty()
            || self.device_name.len() > 128
            || !self
                .device_name
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte))
            || self.invite.as_ref().is_some_and(|value| value.len() > 8192)
        {
            return Err(SecurityError::Protocol);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPrelude {
    pub version: u8,
    pub accepted: bool,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

impl HostPrelude {
    pub fn accepted(device_id: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            version: PRELUDE_VERSION,
            accepted: true,
            device_id: Some(device_id.into()),
            device_name: Some(device_name.into()),
            reason: None,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            version: PRELUDE_VERSION,
            accepted: false,
            device_id: None,
            device_name: None,
            reason: Some(reason.chars().take(160).collect()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SecurityError> {
        if self.version != PRELUDE_VERSION
            || self
                .device_id
                .as_ref()
                .is_some_and(|id| !printable(id, 128))
            || self
                .device_name
                .as_ref()
                .is_some_and(|name| !printable(name, 128))
            || self
                .reason
                .as_ref()
                .is_some_and(|reason| !printable(reason, 512))
        {
            return Err(SecurityError::Protocol);
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PRELUDE_BYTES {
            return Err(SecurityError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() > MAX_PRELUDE_BYTES {
            return Err(SecurityError::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)?;
        if value.version != PRELUDE_VERSION
            || value
                .device_id
                .as_ref()
                .is_some_and(|id| !printable(id, 128))
            || value
                .device_name
                .as_ref()
                .is_some_and(|name| !printable(name, 128))
            || value
                .reason
                .as_ref()
                .is_some_and(|reason| !printable(reason, 512))
        {
            return Err(SecurityError::Protocol);
        }
        Ok(value)
    }
}

fn printable(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preludes_roundtrip_and_bound() {
        let client = ClientPrelude::new("laptop", Some("octpair1:secret".into()));
        assert_eq!(
            ClientPrelude::decode(&client.encode().unwrap())
                .unwrap()
                .device_name,
            "laptop"
        );
        let host = HostPrelude::accepted("device-1", "laptop");
        assert!(
            HostPrelude::decode(&host.encode().unwrap())
                .unwrap()
                .accepted
        );
    }

    #[test]
    fn oversized_prelude_is_rejected() {
        let bytes = vec![b' '; MAX_PRELUDE_BYTES + 1];
        assert!(matches!(
            ClientPrelude::decode(&bytes),
            Err(SecurityError::TooLarge)
        ));
    }
}
