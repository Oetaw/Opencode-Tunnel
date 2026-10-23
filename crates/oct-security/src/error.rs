use thiserror::Error;

/// Security-layer error. Messages are deliberately generic: callers may log
/// the variant, but no variant contains key material or invite secrets.
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("invalid identity key")]
    InvalidIdentity,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid invite")]
    InvalidInvite,
    #[error("invite has expired")]
    InviteExpired,
    #[error("invite has already been used")]
    InviteUsed,
    #[error("peer is not authorized")]
    Unauthorized,
    #[error("pinned host identity does not match")]
    HostKeyMismatch,
    #[error("noise handshake failed")]
    Handshake,
    #[error("noise transport failed")]
    Transport,
    #[error("secure protocol message is invalid")]
    Protocol,
    #[error("secure message is too large")]
    TooLarge,
    #[error("secure prelude was rejected")]
    PreludeRejected,
    #[error("keystore i/o failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("keystore data is invalid")]
    Json(#[from] serde_json::Error),
    #[error("OS keyring operation failed: {0}")]
    Keyring(String),
    #[error("invalid base64 data")]
    Base64,
}
