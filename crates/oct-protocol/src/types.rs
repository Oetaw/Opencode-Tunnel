use bytes::Bytes;

/// Major protocol version. Peers with a different major version must not
/// negotiate a session.
pub const PROTOCOL_MAJOR: u8 = 1;
/// Minor protocol version. Additive only; feature negotiation decides use.
pub const PROTOCOL_MINOR: u8 = 0;

/// Absolute maximum application payload in one inner frame. The transport
/// chunk bound is 64 KiB; the extra 32 bytes are the frame header.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
pub const FRAME_HEADER_LEN: usize = 32;
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD;

/// Inner frame type. Values are frozen for OCT/1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    OpenHttp = 2,
    HttpResponse = 3,
    Data = 4,
    End = 5,
    Reset = 6,
    OpenWs = 7,
    WsMessage = 8,
    WsClose = 9,
    WindowUpdate = 10,
    Ping = 11,
    Pong = 12,
    GoAway = 13,
}

impl Kind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Hello),
            2 => Some(Self::OpenHttp),
            3 => Some(Self::HttpResponse),
            4 => Some(Self::Data),
            5 => Some(Self::End),
            6 => Some(Self::Reset),
            7 => Some(Self::OpenWs),
            8 => Some(Self::WsMessage),
            9 => Some(Self::WsClose),
            10 => Some(Self::WindowUpdate),
            11 => Some(Self::Ping),
            12 => Some(Self::Pong),
            13 => Some(Self::GoAway),
            _ => None,
        }
    }

    /// True when the frame is allowed to carry a non-empty payload.
    ///
    /// `END` is a pure half-close marker in OCT/1 and must not carry trailers.
    /// `PING`/`PONG` may carry an opaque bounded challenge so a peer can echo
    /// it end to end. `WS_MESSAGE`/`WS_CLOSE` payloads are defined in Phase 4.
    pub const fn payload_allowed(self) -> bool {
        !matches!(self, Self::End)
    }
}

/// Frame flags. Unknown bits below `FLAG_CRITICAL` may be ignored; any unknown
/// bit combined with `FLAG_CRITICAL` must fail the connection.
pub const FLAG_CRITICAL: u16 = 0x8000;
pub const FLAG_FIN: u16 = 0x0001;
pub const FLAG_HALF_CLOSE: u16 = 0x0002;
pub const KNOWN_FLAGS: u16 = FLAG_CRITICAL | FLAG_FIN | FLAG_HALF_CLOSE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u16);

impl Flags {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, flag: u16) -> bool {
        self.0 & flag == flag
    }

    pub const fn is_critical(self) -> bool {
        self.0 & FLAG_CRITICAL != 0
    }

    /// Reject unknown critical extensions. Unknown non-critical extensions are
    /// safe to ignore and are preserved by proxies.
    pub const fn validate(self) -> bool {
        !(self.is_critical() && (self.0 & !KNOWN_FLAGS) != 0)
    }
}

/// One OCT/1 inner frame.
///
/// Header layout (big endian):
///
/// ```text
/// u8  version | u8 kind | u16 flags | u64 epoch | u64 stream | u64 seq | u32 payload_len
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub kind: Kind,
    pub flags: Flags,
    pub epoch: u64,
    pub stream: u64,
    pub seq: u64,
    pub payload: Bytes,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("version", &self.version)
            .field("kind", &self.kind)
            .field("flags", &self.flags)
            .field("epoch", &self.epoch)
            .field("stream", &self.stream)
            .field("seq", &self.seq)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl Frame {
    pub fn new(kind: Kind, epoch: u64, stream: u64, seq: u64, payload: impl Into<Bytes>) -> Self {
        Self {
            version: PROTOCOL_MAJOR,
            kind,
            flags: Flags::empty(),
            epoch,
            stream,
            seq,
            payload: payload.into(),
        }
    }

    pub fn with_flags(mut self, flags: Flags) -> Self {
        self.flags = flags;
        self
    }

    pub fn validate(&self) -> bool {
        self.version == PROTOCOL_MAJOR
            && self.flags.validate()
            && self.payload.len() <= MAX_FRAME_PAYLOAD
            && (self.kind.payload_allowed() || self.payload.is_empty())
            && (self.kind != Kind::Hello || self.stream == 0)
    }

    /// Validate stream scope and enforce opener parity. Stream ids keep their
    /// owner's parity in both directions, so non-OPEN frames only require a
    /// nonzero id; the mux verifies that the id is already registered.
    pub fn validate_stream(&self, sender_is_host: bool) -> bool {
        match self.kind {
            Kind::Hello | Kind::Ping | Kind::Pong | Kind::GoAway => self.stream == 0,
            Kind::OpenHttp | Kind::OpenWs => valid_stream_id(self.stream, sender_is_host),
            _ => self.stream != 0,
        }
    }
}

/// Validate a peer-allocated stream id. Clients allocate odd ids, hosts even
/// ids. Zero is reserved.
pub const fn valid_stream_id(id: u64, host_role: bool) -> bool {
    if id == 0 {
        return false;
    }
    (id & 1 == 1) != host_role
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_is_role_specific() {
        assert!(valid_stream_id(1, false));
        assert!(valid_stream_id(2, true));
        assert!(!valid_stream_id(2, false));
        assert!(!valid_stream_id(1, true));
        assert!(!valid_stream_id(0, false));
    }

    #[test]
    fn unknown_critical_flag_is_rejected() {
        assert!(Flags(FLAG_CRITICAL | FLAG_FIN).validate());
        assert!(!Flags(FLAG_CRITICAL | 0x4000).validate());
        assert!(Flags(0x4000).validate());
    }
}
