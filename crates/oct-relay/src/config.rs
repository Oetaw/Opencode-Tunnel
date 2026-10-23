use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::RelayError;

/// Relay process configuration.
///
/// The relay is a ciphertext/opaque-message router. It has no decryption keys
/// and no upstream/OpenCode configuration.
#[derive(Clone)]
pub struct RelayConfig {
    /// TCP listen address. Public deployments should bind loopback or a
    /// private interface behind a TLS-terminating reverse proxy.
    pub listen: SocketAddr,
    /// Explicit opt-in for a non-loopback listener. The relay remains an
    /// opaque ciphertext router; endpoints MUST use Phase 2 E2EE and WSS.
    pub allow_public: bool,
    /// Shared host admission credential. Hosts must present this to create a
    /// room or occupy the host role. Clients receive only a room-scoped token
    /// derived from it.
    pub admission_token: Option<String>,
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
    /// Maximum number of rooms held in memory at once.
    pub max_rooms: usize,
    /// Maximum aggregate bytes queued for delivery to relay peers. This is a
    /// hard backpressure bound; a slow peer cannot make the relay buffer an
    /// unbounded number of opaque frames.
    pub max_queued_bytes: usize,
    /// Time a room may sit with no connected peer before eviction.
    pub room_idle_timeout: Duration,
    /// Deadline for the first RelayControl::Hello message.
    pub hello_timeout: Duration,
    /// Interval for idle-room cleanup.
    pub cleanup_interval: Duration,
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayConfig")
            .field("listen", &self.listen)
            .field("allow_public", &self.allow_public)
            .field(
                "admission_token",
                &self.admission_token.as_ref().map(|_| "<redacted>"),
            )
            .field("public_url", &self.public_url)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .field("max_connections_per_room", &self.max_connections_per_room)
            .field("connection_rate_per_sec", &self.connection_rate_per_sec)
            .field("connection_burst", &self.connection_burst)
            .field("max_rooms", &self.max_rooms)
            .field("max_queued_bytes", &self.max_queued_bytes)
            .field("room_idle_timeout", &self.room_idle_timeout)
            .field("hello_timeout", &self.hello_timeout)
            .field("cleanup_interval", &self.cleanup_interval)
            .finish()
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().expect("static loopback address"),
            allow_public: false,
            admission_token: None,
            public_url: None,
            max_frame_bytes: oct_protocol::types::MAX_FRAME_LEN,
            max_connections_per_room: 2,
            connection_rate_per_sec: 100,
            connection_burst: 200,
            max_rooms: 512,
            max_queued_bytes: 32 * 1024 * 1024,
            room_idle_timeout: Duration::from_secs(120),
            hello_timeout: Duration::from_secs(10),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

impl RelayConfig {
    pub fn validate(&self) -> Result<(), RelayError> {
        let Some(admission_token) = &self.admission_token else {
            return Err(RelayError::Config(
                "relay admission token is required; set --admission-token or \
                 OCT_RELAY_ADMISSION_TOKEN (generate with `openssl rand -hex 32`)"
                    .into(),
            ));
        };
        oct_protocol::relay::validate_token(admission_token).map_err(|_| {
            RelayError::Config("admission token must be 32-256 printable ASCII characters".into())
        })?;
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
        if self.max_rooms == 0 {
            return Err(RelayError::Config("max_rooms must be non-zero".into()));
        }
        if self.max_queued_bytes < self.max_frame_bytes {
            return Err(RelayError::Config(
                "max_queued_bytes must be at least max_frame_bytes".into(),
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

    fn admission_token() -> String {
        "a".repeat(64)
    }

    #[test]
    fn non_loopback_listeners_require_explicit_opt_in() {
        let config = RelayConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            admission_token: Some(admission_token()),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());
        let config = RelayConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            allow_public: true,
            admission_token: Some(admission_token()),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_ok());
        let config = RelayConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            admission_token: Some(admission_token()),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn admission_token_is_required() {
        let config = RelayConfig::default();
        assert!(config.validate().is_err());
    }

    #[test]
    fn malformed_admission_token_is_rejected() {
        let config = RelayConfig {
            admission_token: Some("too-short".into()),
            ..RelayConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_redacts_admission_token() {
        let token = admission_token();
        let config = RelayConfig {
            admission_token: Some(token.clone()),
            ..RelayConfig::default()
        };
        let text = format!("{config:?}");
        assert!(!text.contains(&token));
        assert!(text.contains("<redacted>"));
    }
}
