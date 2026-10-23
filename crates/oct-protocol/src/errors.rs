use std::fmt;

use thiserror::Error;

/// Stable OCT/1 error taxonomy. The wire encoding is a `u16`; the numeric
/// values are frozen. HTTP mappings are applied by the gateway, never by the
/// relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ErrorCode {
    Unavailable = 1,
    Unauthorized = 2,
    Denied = 3,
    OverLimit = 4,
    BadRequest = 5,
    Cancelled = 6,
    BackendError = 7,
    ProtocolError = 8,
    RequestTimeout = 9,
    HostOffline = 10,
    HostRevoked = 11,
    VersionUnsupported = 12,
    ReconciliationRequired = 13,
}

impl ErrorCode {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Unavailable),
            2 => Some(Self::Unauthorized),
            3 => Some(Self::Denied),
            4 => Some(Self::OverLimit),
            5 => Some(Self::BadRequest),
            6 => Some(Self::Cancelled),
            7 => Some(Self::BackendError),
            8 => Some(Self::ProtocolError),
            9 => Some(Self::RequestTimeout),
            10 => Some(Self::HostOffline),
            11 => Some(Self::HostRevoked),
            12 => Some(Self::VersionUnsupported),
            13 => Some(Self::ReconciliationRequired),
            _ => None,
        }
    }

    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Denied => 403,
            Self::OverLimit => 413,
            Self::BadRequest | Self::ProtocolError => 400,
            Self::RequestTimeout => 504,
            Self::Unavailable
            | Self::HostOffline
            | Self::HostRevoked
            | Self::VersionUnsupported
            | Self::ReconciliationRequired
            | Self::Cancelled
            | Self::BackendError => 503,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "UNAVAILABLE",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Denied => "DENIED",
            Self::OverLimit => "OVER_LIMIT",
            Self::BadRequest => "BAD_REQUEST",
            Self::Cancelled => "CANCELLED",
            Self::BackendError => "BACKEND_ERROR",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::RequestTimeout => "REQUEST_TIMEOUT",
            Self::HostOffline => "HOST_OFFLINE",
            Self::HostRevoked => "HOST_REVOKED",
            Self::VersionUnsupported => "VERSION_UNSUPPORTED",
            Self::ReconciliationRequired => "RECONCILIATION_REQUIRED",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame is truncated: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("frame payload exceeds limit: {0} > {max}", max = crate::types::MAX_FRAME_PAYLOAD)]
    PayloadTooLarge(usize),
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported frame kind {0}")]
    UnsupportedKind(u8),
    #[error("invalid frame flags 0x{0:04x}")]
    InvalidFlags(u16),
    #[error("frame kind {kind:?} may not carry a payload")]
    UnexpectedPayload { kind: crate::types::Kind },
    #[error("malformed {context}: {reason}")]
    Malformed {
        context: &'static str,
        reason: String,
    },
    #[error("field {field} is too long: {len} > {max}")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    #[error("too many {field}: {count} > {max}")]
    TooMany {
        field: &'static str,
        count: usize,
        max: usize,
    },
    #[error("reserved or invalid value for {0}")]
    InvalidValue(&'static str),
    #[error("unknown error code {0}")]
    UnknownErrorCode(u16),
    #[error("not enough bytes for {0}")]
    UnexpectedEof(&'static str),
}

impl ProtocolError {
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::ProtocolError
    }
}

/// A stream reset as it appears on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetReason {
    pub code: ErrorCode,
    pub reason: String,
}

impl ResetReason {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        let mut reason = reason.into();
        if reason.len() > 512 {
            let mut end = 512;
            while end > 0 && !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason.truncate(end);
        }
        Self { code, reason }
    }
}
