//! Capability and compatibility negotiation.

use serde::{Deserialize, Serialize};

use crate::errors::ProtocolError;
use crate::types::{PROTOCOL_MAJOR, PROTOCOL_MINOR};

pub const MAX_HELLO_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Host,
    Client,
}

/// Additive feature flags. A peer must only use a feature if both sides
/// advertised it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Feature {
    /// HTTP request/response bridging.
    Http = 1,
    /// Server-sent events pass through as ordinary DATA chunks.
    Sse = 2,
    /// Nested PTY WebSocket bridging.
    Ws = 3,
    /// End-to-end encrypted inner frames.
    E2ee = 4,
    /// Client can request an authoritative resync after reconnect.
    Resync = 5,
}

impl Feature {
    pub const fn bit(self) -> u64 {
        1 << (self as u8)
    }

    pub const fn from_bit(bit: u8) -> Option<Self> {
        match bit {
            1 => Some(Self::Http),
            2 => Some(Self::Sse),
            3 => Some(Self::Ws),
            4 => Some(Self::E2ee),
            5 => Some(Self::Resync),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub max_frame_payload: u32,
    pub max_streams: u16,
    pub max_header_bytes: u32,
    pub max_pending_bytes: u32,
}

impl Limits {
    pub const fn is_valid(&self) -> bool {
        self.max_frame_payload > 0
            && self.max_frame_payload <= crate::types::MAX_FRAME_PAYLOAD as u32
            && self.max_streams > 0
            && self.max_header_bytes > 0
            && self.max_header_bytes <= crate::httpwire::MAX_HEADER_BYTES as u32
            && self.max_pending_bytes > 0
    }
}

/// Effective limits and features after intersecting both HELLOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub limits: Limits,
    pub features: u64,
}

impl Negotiated {
    pub const fn supports(&self, feature: Feature) -> bool {
        self.features & feature.bit() != 0
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_payload: crate::types::MAX_FRAME_PAYLOAD as u32,
            max_streams: 128,
            max_header_bytes: crate::httpwire::MAX_HEADER_BYTES as u32,
            max_pending_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub major: u8,
    pub minor: u8,
    pub role: Role,
    pub features: u64,
    pub limits: Limits,
    pub opencode_version: Option<String>,
    pub agent: String,
}

impl Hello {
    pub fn new(role: Role, features: &[Feature], opencode_version: Option<String>) -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
            role,
            features: features.iter().fold(0, |acc, f| acc | f.bit()),
            limits: Limits::default(),
            opencode_version,
            agent: format!("oct/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    pub fn supports(&self, feature: Feature) -> bool {
        self.features & feature.bit() != 0
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate_fields()?;
        let bytes = serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed {
            context: "hello",
            reason: e.to_string(),
        })?;
        if bytes.len() > MAX_HELLO_BYTES {
            return Err(ProtocolError::PayloadTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_HELLO_BYTES {
            return Err(ProtocolError::PayloadTooLarge(payload.len()));
        }
        let hello: Self =
            serde_json::from_slice(payload).map_err(|e| ProtocolError::Malformed {
                context: "hello",
                reason: e.to_string(),
            })?;
        hello.validate_fields()?;
        Ok(hello)
    }

    fn validate_fields(&self) -> Result<(), ProtocolError> {
        if !self.limits.is_valid() {
            return Err(ProtocolError::InvalidValue("hello limits"));
        }
        if !valid_short_string(&self.agent, 128) {
            return Err(ProtocolError::InvalidValue("hello agent"));
        }
        if let Some(version) = &self.opencode_version {
            if !valid_short_string(version, 128) {
                return Err(ProtocolError::InvalidValue("opencode version"));
            }
        }
        Ok(())
    }

    /// Reject incompatible major versions, same-role peers, missing required
    /// features, and impossible/zero limits. The returned negotiated values
    /// are the intersection of the two advertisements.
    pub fn negotiate(
        &self,
        peer: &Hello,
        required_features: &[Feature],
    ) -> Result<Negotiated, ProtocolError> {
        if self.major != peer.major || self.major != PROTOCOL_MAJOR {
            return Err(ProtocolError::UnsupportedVersion(peer.major));
        }
        if self.role == peer.role {
            return Err(ProtocolError::InvalidValue("hello peer role"));
        }
        if !self.limits.is_valid() || !peer.limits.is_valid() {
            return Err(ProtocolError::InvalidValue("hello limits"));
        }
        let limits = Limits {
            max_frame_payload: self
                .limits
                .max_frame_payload
                .min(peer.limits.max_frame_payload)
                .min(crate::types::MAX_FRAME_PAYLOAD as u32),
            max_streams: self.limits.max_streams.min(peer.limits.max_streams),
            max_header_bytes: self
                .limits
                .max_header_bytes
                .min(peer.limits.max_header_bytes)
                .min(crate::httpwire::MAX_HEADER_BYTES as u32),
            max_pending_bytes: self
                .limits
                .max_pending_bytes
                .min(peer.limits.max_pending_bytes),
        };
        if !limits.is_valid() {
            return Err(ProtocolError::InvalidValue("negotiated hello limits"));
        }
        let features = self.features & peer.features;
        for required in required_features {
            if features & required.bit() == 0 {
                return Err(ProtocolError::InvalidValue("required feature"));
            }
        }
        Ok(Negotiated { limits, features })
    }

    /// Backwards-compatible compatibility check with no required features.
    pub fn check_compatible(&self, peer: &Hello) -> Result<(), ProtocolError> {
        self.negotiate(peer, &[]).map(|_| ())
    }
}

fn valid_short_string(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let hello = Hello::new(Role::Host, &[Feature::Http, Feature::Sse], None);
        let encoded = hello.encode().unwrap();
        assert_eq!(Hello::decode(&encoded).unwrap(), hello);
    }

    #[test]
    fn rejects_major_mismatch() {
        let a = Hello::new(Role::Host, &[Feature::Http], None);
        let mut b = a.clone();
        b.major = 2;
        assert!(a.check_compatible(&b).is_err());
    }

    #[test]
    fn feature_negotiation_is_explicit() {
        let a = Hello::new(Role::Host, &[Feature::Http], None);
        assert!(a.supports(Feature::Http));
        assert!(!a.supports(Feature::Ws));
    }

    #[test]
    fn rejects_same_role_peer() {
        let a = Hello::new(Role::Host, &[Feature::Http], None);
        let b = Hello::new(Role::Host, &[Feature::Http], None);
        assert!(a.negotiate(&b, &[]).is_err());
    }

    #[test]
    fn requires_explicit_features() {
        let host = Hello::new(Role::Host, &[Feature::Http], None);
        let client = Hello::new(Role::Client, &[Feature::Http, Feature::E2ee], None);
        assert!(host.negotiate(&client, &[Feature::E2ee]).is_err());
        assert!(host.negotiate(&client, &[Feature::Http]).is_ok());
    }

    #[test]
    fn rejects_zero_limits() {
        let a = Hello::new(Role::Host, &[Feature::Http], None);
        let mut b = Hello::new(Role::Client, &[Feature::Http], None);
        b.limits.max_header_bytes = 0;
        assert!(a.negotiate(&b, &[]).is_err());
        assert!(b.encode().is_err());
    }

    #[test]
    fn rejects_control_characters_in_metadata() {
        let mut hello = Hello::new(Role::Host, &[Feature::Http], None);
        hello.agent = "oct\nX-Evil: 1".into();
        assert!(hello.encode().is_err());
    }
}
