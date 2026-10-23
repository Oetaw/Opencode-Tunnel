use std::net::SocketAddr;
use std::time::Duration;

use crate::RelayError;

/// Relay process configuration.
///
/// The relay is a ciphertext/opaque-message router. It has no decryption keys
/// and no upstream/OpenCode configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// TCP listen address. Public deployments should bind loopback or a
    /// private interface behind a TLS-terminating reverse proxy.
    pub listen: SocketAddr,
    /// Explicit opt-in for a non-loopback listener. The relay remains an
    /// opaque ciphertext router; endpoints MUST use Phase 2 E2EE and WSS.
    pub allow_public: bool,
    /// Public WSS URL, if known. Diagnostic only; never trusted for routing.
    pub public_url: Option<String>,
    /// Maximum accepted binary websocket message. This bounds opaque inner
    /// frames and, later, Noise ciphertext chunks.
    pub max_frame_bytes: usize,
    /// Maximum simultaneously connected sockets in one room. OCT/1 MVP has
    /// exactly one host and one client; keep a little headroom for a
    /// reconnecting peer.
    pub max_connections_per_room: usize,
    /// Global new-connection token bucket rate and burst. This is a coarse
    /// anti-flood control; per-IP limits belong at the TLS terminator.
    pub connection_rate_per_sec: u32,
    pub connection_burst: u32,
    /// Time a room may sit with no connected peer before eviction.
    pub room_idle_timeout: Duration,
    /// Deadline for the first RelayControl::Hello message.
    pub hello_timeout: Duration,
    /// Interval for idle-room cleanup.
    pub cleanup_interval: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("static loopback address"),
            allow_public: false,
            public_url: None,
            max_frame_bytes: oct_protocol::types::MAX_FRAME_LEN,
            max_connections_per_room: 2,
            connection_rate_per_sec: 100,
            connection_burst: 200,
            room_idle_timeout: Duration::from_secs(120),
            hello_timeout: Duration::from_secs(10),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

impl RelayConfig {
    pub fn validate(&self) -> Result<(), RelayError> {
        if !self.listen.ip().is_loopback() && !self.allow_public {
            return Err(RelayError::Config(
                "non-loopback relay bind requires explicit --allow-public and Phase 2 E2EE".into(),
            ));
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > oct_protocol::types::MAX_FRAME_LEN {
            return Err(RelayError::Config(
                "max_frame_bytes must be between 1 and MAX_FRAME_LEN".into(),
            ));
        }
        if self.max_connections_per_room < 2 {
            return Err(RelayError::Config(
                "max_connections_per_room must be at least 2".into(),
            ));
        }
        if self.connection_rate_per_sec == 0 || self.connection_burst == 0 {
            return Err(RelayError::Config(
                "connection rate and burst must be non-zero".into(),
            ));
        }
        if self.hello_timeout.is_zero()
            || self.room_idle_timeout.is_zero()
            || self.cleanup_interval.is_zero()
        {
            return Err(RelayError::Config("timeouts must be non-zero".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_loopback_listeners_require_explicit_opt_in() {
        let config = RelayConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());
        let config = RelayConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            allow_public: true,
            ..RelayConfig::default()
        };
        assert!(config.validate().is_ok());
        let config = RelayConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_ok());
    }
}
