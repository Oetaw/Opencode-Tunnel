//! Bounded encoding for the HTTP and WebSocket metadata carried in OCT frames.
//!
//! We deliberately do not use an HTTP crate here: the host reconstructs a
//! request against a fixed loopback origin and must not accept absolute-form
//! targets, `CONNECT`, or hop-by-hop routing headers from the wire.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};

use crate::errors::{ErrorCode, ProtocolError};
use crate::types::MAX_FRAME_PAYLOAD;

pub const MAX_METHOD_LEN: usize = 16;
pub const MAX_TARGET_LEN: usize = 8192;
pub const MAX_HEADER_FIELDS: usize = 128;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_REASON_LEN: usize = 512;
pub const MAX_SUBPROTOCOLS: usize = 8;
/// Upper bound on a complete nested WebSocket message after reassembly. The
/// transport never buffers more than this per stream.
pub const MAX_WS_MESSAGE: usize = 8 * 1024 * 1024;
/// RFC 6455 limits a close reason to 123 bytes of UTF-8.
pub const MAX_WS_CLOSE_REASON: usize = 123;
/// Upper bound on a single WINDOW_UPDATE credit. This keeps aggregate window
/// arithmetic bounded and prevents a peer from disabling backpressure.
pub const MAX_WINDOW_CREDIT: u32 = 8 * 1024 * 1024;

/// Data/control opcode carried inside a `WS_MESSAGE` frame. Continuation is
/// only valid for fragments after the first; the transport reassembles the
/// complete message before exposing it to the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WsOpcode {
    Continuation = 0,
    Text = 1,
    Binary = 2,
}

impl WsOpcode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Continuation),
            1 => Some(Self::Text),
            2 => Some(Self::Binary),
            _ => None,
        }
    }
}

pub type Header = (String, String);

#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequestHead {
    pub method: String,
    /// Origin-form target: path plus optional raw query. Must start with `/`.
    pub target: String,
    pub headers: Vec<Header>,
}

impl HttpRequestHead {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_method(&self.method)?;
        validate_target(&self.target)?;
        validate_request_headers(&self.headers)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: Vec<Header>,
}

impl HttpResponseHead {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        // 1xx responses (including 101 Switching Protocols) are not final
        // response heads on the OCT HTTP stream; PTY upgrades use OPEN_WS.
        if !(200..=599).contains(&self.status) {
            return Err(ProtocolError::InvalidValue("http status"));
        }
        validate_response_headers(&self.headers)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OpenWs {
    pub target: String,
    pub subprotocols: Vec<String>,
    pub headers: Vec<Header>,
}

impl OpenWs {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_target(&self.target)?;
        if self.subprotocols.len() > MAX_SUBPROTOCOLS {
            return Err(ProtocolError::TooMany {
                field: "websocket subprotocols",
                count: self.subprotocols.len(),
                max: MAX_SUBPROTOCOLS,
            });
        }
        for p in &self.subprotocols {
            validate_ws_subprotocol(p)?;
        }
        validate_ws_headers(&self.headers)
    }
}

impl fmt::Debug for HttpRequestHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequestHead")
            .field("method", &self.method)
            .field("target", &RedactedTarget(&self.target))
            .field("headers", &HeaderNames(&self.headers))
            .finish()
    }
}

impl fmt::Debug for HttpResponseHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponseHead")
            .field("status", &self.status)
            .field("headers", &HeaderNames(&self.headers))
            .finish()
    }
}

impl fmt::Debug for OpenWs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenWs")
            .field("target", &RedactedTarget(&self.target))
            .field("subprotocols", &self.subprotocols)
            .field("headers", &HeaderNames(&self.headers))
            .finish()
    }
}

struct RedactedTarget<'a>(&'a str);

impl fmt::Debug for RedactedTarget<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.split_once('?') {
            Some((path, _)) => write!(f, "{path}?<redacted>"),
            None => f.write_str(self.0),
        }
    }
}

struct HeaderNames<'a>(&'a [Header]);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(n, _)| n))
            .finish()
    }
}

pub fn validate_method(method: &str) -> Result<(), ProtocolError> {
    if method.is_empty() || method.len() > MAX_METHOD_LEN {
        return Err(ProtocolError::FieldTooLong {
            field: "method",
            len: method.len(),
            max: MAX_METHOD_LEN,
        });
    }
    // Canonical uppercase allowlist. No TRACE/TRACK (credential reflection),
    // no CONNECT (authority tunnel), no extension methods on the fixed API.
    match method {
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" => Ok(()),
        _ => Err(ProtocolError::InvalidValue("http method")),
    }
}

pub fn validate_target(target: &str) -> Result<(), ProtocolError> {
    if target.is_empty() || target.len() > MAX_TARGET_LEN {
        return Err(ProtocolError::FieldTooLong {
            field: "target",
            len: target.len(),
            max: MAX_TARGET_LEN,
        });
    }
    if !target.starts_with('/') {
        return Err(ProtocolError::InvalidValue("origin-form target"));
    }
    // `//host` is network-path reference, `://` is absolute-form, and `\` is
    // treated as `/` by WHATWG URL parsers. Reject all three before the host
    // ever joins this target with its fixed origin.
    if target.starts_with("//") || target.contains("://") || target.contains('\\') {
        return Err(ProtocolError::InvalidValue("absolute or authority target"));
    }
    // Origin-form is visible ASCII; fragments are never sent on the wire and
    // all non-ASCII/control bytes must be percent-encoded.
    if target
        .bytes()
        .any(|b| !(0x21..=0x7e).contains(&b) || b == b'#' || b == b'\\')
    {
        return Err(ProtocolError::InvalidValue("target characters"));
    }
    Ok(())
}

/// RFC 9110 token characters (used for header names and WS subprotocols).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub fn validate_headers(headers: &[Header]) -> Result<(), ProtocolError> {
    if headers.len() > MAX_HEADER_FIELDS {
        return Err(ProtocolError::TooMany {
            field: "header fields",
            count: headers.len(),
            max: MAX_HEADER_FIELDS,
        });
    }
    let mut total = 0usize;
    for (name, value) in headers {
        if name.is_empty() || name.len() > 256 {
            return Err(ProtocolError::InvalidValue("header name"));
        }
        if !is_token(name) {
            return Err(ProtocolError::InvalidValue("header name characters"));
        }
        if value.len() > 8192 {
            return Err(ProtocolError::FieldTooLong {
                field: "header value",
                len: value.len(),
                max: 8192,
            });
        }
        // Visible ASCII plus space only. Tabs and other CTLs are rejected to
        // avoid parser differentials and log injection.
        if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(ProtocolError::InvalidValue("header value"));
        }
        total += name.len() + value.len() + 4;
    }
    if total > MAX_HEADER_BYTES {
        return Err(ProtocolError::FieldTooLong {
            field: "combined headers",
            len: total,
            max: MAX_HEADER_BYTES,
        });
    }
    Ok(())
}

fn header_is(name: &str, denied: &[&str]) -> bool {
    denied.iter().any(|d| name.eq_ignore_ascii_case(d))
}

/// Headers that must never cross the OCT request boundary. Framing is carried
/// by DATA/END, the upstream origin is fixed, and local credentials must not
/// be forwarded to OpenCode.
const DENIED_REQUEST_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "authorization",
    "proxy-authorization",
];

/// Response framing/hop-by-hop headers are regenerated by the gateway.
const DENIED_RESPONSE_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

const DENIED_WS_HEADERS: &[&str] = &[
    "host",
    "connection",
    "upgrade",
    "origin",
    "authorization",
    "proxy-authorization",
    "cookie",
    "sec-websocket-key",
    "sec-websocket-version",
    "sec-websocket-extensions",
    "sec-websocket-protocol",
    "sec-websocket-accept",
];

pub fn validate_request_headers(headers: &[Header]) -> Result<(), ProtocolError> {
    validate_headers(headers)?;
    for (name, _) in headers {
        if header_is(name, DENIED_REQUEST_HEADERS) {
            return Err(ProtocolError::InvalidValue("forbidden request header"));
        }
    }
    Ok(())
}

pub fn validate_response_headers(headers: &[Header]) -> Result<(), ProtocolError> {
    validate_headers(headers)?;
    for (name, _) in headers {
        if header_is(name, DENIED_RESPONSE_HEADERS) {
            return Err(ProtocolError::InvalidValue("forbidden response header"));
        }
    }
    Ok(())
}

pub fn validate_ws_headers(headers: &[Header]) -> Result<(), ProtocolError> {
    validate_headers(headers)?;
    for (name, _) in headers {
        if header_is(name, DENIED_WS_HEADERS) {
            return Err(ProtocolError::InvalidValue("forbidden websocket header"));
        }
    }
    Ok(())
}

pub fn validate_ws_subprotocol(subprotocol: &str) -> Result<(), ProtocolError> {
    if subprotocol.len() > 128 || !is_token(subprotocol) {
        return Err(ProtocolError::InvalidValue("websocket subprotocol"));
    }
    Ok(())
}

fn put_str(
    dst: &mut BytesMut,
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if value.len() > max {
        return Err(ProtocolError::FieldTooLong {
            field,
            len: value.len(),
            max,
        });
    }
    dst.put_u16(value.len() as u16);
    dst.put_slice(value.as_bytes());
    Ok(())
}

fn put_headers(dst: &mut BytesMut, headers: &[Header]) -> Result<(), ProtocolError> {
    validate_headers(headers)?;
    dst.put_u16(headers.len() as u16);
    for (name, value) in headers {
        put_str(dst, name, 256, "header name")?;
        put_str(dst, value, 8192, "header value")?;
    }
    Ok(())
}

pub fn encode_request_head(req: &HttpRequestHead) -> Result<Bytes, ProtocolError> {
    req.validate()?;
    let mut dst = BytesMut::with_capacity(
        req.method.len()
            + req.target.len()
            + req
                .headers
                .iter()
                .map(|(n, v)| n.len() + v.len() + 4)
                .sum::<usize>()
            + 8,
    );
    put_str(&mut dst, &req.method, MAX_METHOD_LEN, "method")?;
    put_str(&mut dst, &req.target, MAX_TARGET_LEN, "target")?;
    put_headers(&mut dst, &req.headers)?;
    Ok(dst.freeze())
}

pub fn decode_request_head(payload: &[u8]) -> Result<HttpRequestHead, ProtocolError> {
    let mut r = Reader::new(payload);
    let method = r.string(MAX_METHOD_LEN, "method")?;
    let target = r.string(MAX_TARGET_LEN, "target")?;
    let headers = r.headers()?;
    r.finish("http request head")?;
    let head = HttpRequestHead {
        method,
        target,
        headers,
    };
    head.validate()?;
    Ok(head)
}

pub fn encode_response_head(res: &HttpResponseHead) -> Result<Bytes, ProtocolError> {
    res.validate()?;
    let mut dst = BytesMut::with_capacity(
        2 + res
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len() + 4)
            .sum::<usize>(),
    );
    dst.put_u16(res.status);
    put_headers(&mut dst, &res.headers)?;
    Ok(dst.freeze())
}

pub fn decode_response_head(payload: &[u8]) -> Result<HttpResponseHead, ProtocolError> {
    let mut r = Reader::new(payload);
    let status = r.u16("http status")?;
    let headers = r.headers()?;
    r.finish("http response head")?;
    let head = HttpResponseHead { status, headers };
    head.validate()?;
    Ok(head)
}

pub fn encode_open_ws(ws: &OpenWs) -> Result<Bytes, ProtocolError> {
    ws.validate()?;
    let mut dst = BytesMut::new();
    put_str(&mut dst, &ws.target, MAX_TARGET_LEN, "target")?;
    dst.put_u16(ws.subprotocols.len() as u16);
    for p in &ws.subprotocols {
        put_str(&mut dst, p, 128, "subprotocol")?;
    }
    put_headers(&mut dst, &ws.headers)?;
    Ok(dst.freeze())
}

pub fn decode_open_ws(payload: &[u8]) -> Result<OpenWs, ProtocolError> {
    let mut r = Reader::new(payload);
    let target = r.string(MAX_TARGET_LEN, "target")?;
    let count = r.u16("subprotocol count")? as usize;
    if count > MAX_SUBPROTOCOLS {
        return Err(ProtocolError::TooMany {
            field: "websocket subprotocols",
            count,
            max: MAX_SUBPROTOCOLS,
        });
    }
    let mut subprotocols = Vec::with_capacity(count);
    for _ in 0..count {
        subprotocols.push(r.string(128, "subprotocol")?);
    }
    let headers = r.headers()?;
    r.finish("open ws")?;
    let ws = OpenWs {
        target,
        subprotocols,
        headers,
    };
    ws.validate()?;
    Ok(ws)
}

/// Nested WebSocket message payload: `u8 opcode | u8 flags | opaque bytes`.
///
/// Bit 0 of `flags` is FIN. The encoded payload must fit in one OCT frame;
/// callers split larger messages into fragments before calling this.
pub fn encode_ws_message(
    opcode: WsOpcode,
    fin: bool,
    payload: &[u8],
) -> Result<Bytes, ProtocolError> {
    let total = payload.len() + 2;
    if total > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(total));
    }
    let mut dst = BytesMut::with_capacity(total);
    dst.put_u8(opcode.as_u8());
    dst.put_u8(u8::from(fin));
    dst.put_slice(payload);
    Ok(dst.freeze())
}

pub fn decode_ws_message(payload: &[u8]) -> Result<(WsOpcode, bool, Bytes), ProtocolError> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(payload.len()));
    }
    if payload.len() < 2 {
        return Err(ProtocolError::UnexpectedEof("ws message"));
    }
    let opcode =
        WsOpcode::from_u8(payload[0]).ok_or(ProtocolError::InvalidValue("websocket opcode"))?;
    let flags = payload[1];
    if flags & !0x01 != 0 {
        return Err(ProtocolError::InvalidFlags(u16::from(flags)));
    }
    Ok((
        opcode,
        flags & 0x01 != 0,
        Bytes::copy_from_slice(&payload[2..]),
    ))
}

/// Nested WebSocket close payload: `u16 code (0 = none) | u16 len | reason`.
///
/// The reason is truncated on a UTF-8 boundary to [`MAX_WS_CLOSE_REASON`]
/// bytes. Reserved close codes that must never appear on the wire are rejected.
pub fn encode_ws_close(code: Option<u16>, reason: &str) -> Result<Bytes, ProtocolError> {
    if let Some(code) = code {
        validate_ws_close_code(code)?;
    }
    let reason = truncate_utf8(reason, MAX_WS_CLOSE_REASON);
    validate_ws_close_reason(reason)?;
    let mut dst = BytesMut::with_capacity(4 + reason.len());
    dst.put_u16(code.unwrap_or(0));
    dst.put_u16(reason.len() as u16);
    dst.put_slice(reason.as_bytes());
    Ok(dst.freeze())
}

pub fn decode_ws_close(payload: &[u8]) -> Result<(Option<u16>, String), ProtocolError> {
    let mut r = Reader::new(payload);
    let raw_code = r.u16("ws close code")?;
    let code = if raw_code == 0 {
        None
    } else {
        validate_ws_close_code(raw_code)?;
        Some(raw_code)
    };
    let reason = r.string(MAX_WS_CLOSE_REASON, "ws close reason")?;
    validate_ws_close_reason(&reason)?;
    r.finish("ws close")?;
    Ok((code, reason))
}

fn validate_ws_close_reason(reason: &str) -> Result<(), ProtocolError> {
    if reason.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidValue("websocket close reason"));
    }
    Ok(())
}

fn validate_ws_close_code(code: u16) -> Result<(), ProtocolError> {
    if !(1000..=4999).contains(&code) || matches!(code, 1004 | 1005 | 1006 | 1015) {
        return Err(ProtocolError::InvalidValue("websocket close code"));
    }
    Ok(())
}

/// Reset body: `u16 code | u16 reason_len | reason`.
pub fn encode_reset(code: u16, reason: &str) -> Bytes {
    let reason = truncate_utf8(reason, MAX_REASON_LEN);
    let mut dst = BytesMut::with_capacity(4 + reason.len());
    dst.put_u16(code);
    dst.put_u16(reason.len() as u16);
    dst.put_slice(reason.as_bytes());
    dst.freeze()
}

fn truncate_utf8(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub fn decode_reset(payload: &[u8]) -> Result<(u16, String), ProtocolError> {
    let mut r = Reader::new(payload);
    let code = r.u16("reset code")?;
    if ErrorCode::from_u16(code).is_none() {
        return Err(ProtocolError::UnknownErrorCode(code));
    }
    let reason = r.string(MAX_REASON_LEN, "reset reason")?;
    r.finish("reset")?;
    Ok((code, reason))
}

/// Window update body: `u32 credit`.
pub fn encode_window_update(credit: u32) -> Bytes {
    let mut dst = BytesMut::with_capacity(4);
    dst.put_u32(credit);
    dst.freeze()
}

pub fn decode_window_update(payload: &[u8]) -> Result<u32, ProtocolError> {
    if payload.len() != 4 {
        return Err(ProtocolError::Malformed {
            context: "window update",
            reason: format!("expected 4 bytes, got {}", payload.len()),
        });
    }
    let credit = u32::from_be_bytes(payload.try_into().expect("4 bytes"));
    if credit == 0 || credit > MAX_WINDOW_CREDIT {
        return Err(ProtocolError::InvalidValue("window update credit"));
    }
    Ok(credit)
}

/// GoAway body: `u16 code | u16 reason_len | reason`.
pub fn encode_goaway(code: u16, reason: &str) -> Bytes {
    encode_reset(code, reason)
}

pub fn decode_goaway(payload: &[u8]) -> Result<(u16, String), ProtocolError> {
    decode_reset(payload)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize, what: &'static str) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(ProtocolError::UnexpectedEof(what))?;
        if end > self.buf.len() {
            return Err(ProtocolError::UnexpectedEof(what));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, ProtocolError> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn string(&mut self, max: usize, what: &'static str) -> Result<String, ProtocolError> {
        let len = self.u16(what)? as usize;
        if len > max {
            return Err(ProtocolError::FieldTooLong {
                field: what,
                len,
                max,
            });
        }
        let bytes = self.take(len, what)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::InvalidValue(what))
    }

    fn headers(&mut self) -> Result<Vec<Header>, ProtocolError> {
        let count = self.u16("header count")? as usize;
        if count > MAX_HEADER_FIELDS {
            return Err(ProtocolError::TooMany {
                field: "header fields",
                count,
                max: MAX_HEADER_FIELDS,
            });
        }
        let mut headers = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let name = self.string(256, "header name")?;
            let value = self.string(8192, "header value")?;
            total += name.len() + value.len();
            if total > MAX_HEADER_BYTES {
                return Err(ProtocolError::FieldTooLong {
                    field: "combined headers",
                    len: total,
                    max: MAX_HEADER_BYTES,
                });
            }
            headers.push((name, value));
        }
        Ok(headers)
    }

    fn finish(&self, what: &'static str) -> Result<(), ProtocolError> {
        if self.pos != self.buf.len() {
            return Err(ProtocolError::Malformed {
                context: what,
                reason: format!("{} trailing bytes", self.buf.len() - self.pos),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_head_roundtrip() {
        let head = HttpRequestHead {
            method: "POST".into(),
            target: "/api/session?x=1".into(),
            headers: vec![("content-type".into(), "application/json".into())],
        };
        let bytes = encode_request_head(&head).unwrap();
        assert_eq!(decode_request_head(&bytes).unwrap(), head);
    }

    #[test]
    fn rejects_absolute_target() {
        let head = HttpRequestHead {
            method: "GET".into(),
            target: "http://evil.example/".into(),
            headers: vec![],
        };
        assert!(head.validate().is_err());
    }

    #[test]
    fn rejects_connect() {
        let head = HttpRequestHead {
            method: "CONNECT".into(),
            target: "evil.example:443".into(),
            headers: vec![],
        };
        assert!(head.validate().is_err());
    }

    #[test]
    fn rejects_header_injection() {
        let head = HttpRequestHead {
            method: "GET".into(),
            target: "/".into(),
            headers: vec![("x".into(), "a\r\nInjected: yes".into())],
        };
        assert!(head.validate().is_err());
    }

    #[test]
    fn rejects_oversized_header_count() {
        let head = HttpRequestHead {
            method: "GET".into(),
            target: "/".into(),
            headers: (0..200).map(|i| (format!("h{i}"), "v".into())).collect(),
        };
        assert!(head.validate().is_err());
    }

    #[test]
    fn rejects_backslash_and_control_targets() {
        for target in [
            "/\\evil.example/",
            "/%5Cok", // percent-encoded backslash is fine; raw is not
            "/foo bar",
            "/foo\tbar",
            "/foo#frag",
            "//evil.example/",
        ] {
            let head = HttpRequestHead {
                method: "GET".into(),
                target: target.into(),
                headers: vec![],
            };
            let valid = head.validate().is_ok();
            if target == "/%5Cok" {
                assert!(valid, "percent-encoded path must remain valid");
            } else {
                assert!(!valid, "target must be rejected: {target:?}");
            }
        }
    }

    #[test]
    fn rejects_dangerous_methods() {
        for method in ["CONNECT", "TRACE", "TRACK", "get", "PROPFIND"] {
            let head = HttpRequestHead {
                method: method.into(),
                target: "/".into(),
                headers: vec![],
            };
            assert!(
                head.validate().is_err(),
                "method must be rejected: {method}"
            );
        }
    }

    #[test]
    fn rejects_smuggling_headers() {
        for name in [
            "Content-Length",
            "transfer-encoding",
            "Host",
            "Connection",
            "Upgrade",
            "Authorization",
        ] {
            let head = HttpRequestHead {
                method: "GET".into(),
                target: "/".into(),
                headers: vec![(name.into(), "x".into())],
            };
            assert!(head.validate().is_err(), "header must be rejected: {name}");
        }
    }

    #[test]
    fn rejects_ws_subprotocol_injection() {
        let ws = OpenWs {
            target: "/api/pty".into(),
            subprotocols: vec!["x\r\nX-Evil: 1".into()],
            headers: vec![],
        };
        assert!(ws.validate().is_err());
    }

    #[test]
    fn rejects_reserved_ws_headers() {
        let ws = OpenWs {
            target: "/api/pty".into(),
            subprotocols: vec![],
            headers: vec![("sec-websocket-key".into(), "abc".into())],
        };
        assert!(ws.validate().is_err());
    }

    #[test]
    fn rejects_informational_response_heads() {
        let head = HttpResponseHead {
            status: 101,
            headers: vec![],
        };
        assert!(head.validate().is_err());
    }

    #[test]
    fn reset_truncation_is_utf8_safe() {
        let reason = "é".repeat(300);
        let encoded = encode_reset(ErrorCode::ProtocolError.as_u16(), &reason);
        let (_, decoded) = decode_reset(&encoded).unwrap();
        assert!(decoded.len() <= MAX_REASON_LEN);
        assert!(decoded.is_char_boundary(decoded.len()));
    }

    #[test]
    fn ws_message_roundtrip() {
        for (opcode, fin, payload) in [
            (WsOpcode::Text, true, b"hello".as_slice()),
            (WsOpcode::Binary, false, b"\x00\x01\x02".as_slice()),
            (WsOpcode::Continuation, true, b"".as_slice()),
        ] {
            let encoded = encode_ws_message(opcode, fin, payload).unwrap();
            let (got_opcode, got_fin, got_payload) = decode_ws_message(&encoded).unwrap();
            assert_eq!(got_opcode, opcode);
            assert_eq!(got_fin, fin);
            assert_eq!(got_payload.as_ref(), payload);
        }
    }

    #[test]
    fn ws_message_accepts_maximum_frame_payload() {
        let payload = vec![0x5a; MAX_FRAME_PAYLOAD - 2];
        let encoded = encode_ws_message(WsOpcode::Binary, true, &payload).unwrap();
        assert_eq!(encoded.len(), MAX_FRAME_PAYLOAD);
        assert_eq!(
            decode_ws_message(&encoded).unwrap().2.as_ref(),
            payload.as_slice()
        );
    }

    #[test]
    fn ws_message_rejects_oversized_payload() {
        let payload = vec![0u8; MAX_FRAME_PAYLOAD];
        let error = encode_ws_message(WsOpcode::Binary, true, &payload).unwrap_err();
        assert!(matches!(error, ProtocolError::PayloadTooLarge(_)));

        let mut encoded = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        encoded[0] = WsOpcode::Binary.as_u8();
        assert!(matches!(
            decode_ws_message(&encoded),
            Err(ProtocolError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn ws_message_rejects_unknown_flags() {
        let encoded = [WsOpcode::Text.as_u8(), 0x02, b'x'];
        assert!(matches!(
            decode_ws_message(&encoded),
            Err(ProtocolError::InvalidFlags(2))
        ));
    }

    #[test]
    fn ws_message_rejects_invalid_opcode() {
        for opcode in [3u8, 8, 10, 0xff] {
            let encoded = [opcode, 0x01];
            assert!(matches!(
                decode_ws_message(&encoded),
                Err(ProtocolError::InvalidValue("websocket opcode"))
            ));
        }
    }

    #[test]
    fn ws_message_rejects_truncated_payloads() {
        assert!(matches!(
            decode_ws_message(&[]),
            Err(ProtocolError::UnexpectedEof("ws message"))
        ));
        assert!(matches!(
            decode_ws_message(&[WsOpcode::Text.as_u8()]),
            Err(ProtocolError::UnexpectedEof("ws message"))
        ));
    }

    #[test]
    fn ws_close_roundtrip() {
        let cases = [
            (Some(1000u16), "normal closure"),
            (Some(4999), "app"),
            (None, ""),
            (Some(3000), "é"),
        ];
        for (code, reason) in cases {
            let encoded = encode_ws_close(code, reason).unwrap();
            let (got_code, got_reason) = decode_ws_close(&encoded).unwrap();
            assert_eq!(got_code, code);
            assert_eq!(got_reason, reason);
        }
    }

    #[test]
    fn ws_close_rejects_invalid_codes() {
        for code in [0u16, 1, 999, 1004, 1005, 1006, 1015, 5000, u16::MAX] {
            assert!(
                encode_ws_close(Some(code), "bad").is_err(),
                "code must be rejected: {code}"
            );
        }

        // Wire code 0 means "no close code", so only nonzero invalid values
        // are malformed on decode.
        for code in [1u16, 999, 1004, 1005, 1006, 1015, 5000, u16::MAX] {
            let mut payload = Vec::new();
            payload.extend_from_slice(&code.to_be_bytes());
            payload.extend_from_slice(&0u16.to_be_bytes());
            assert!(
                decode_ws_close(&payload).is_err(),
                "decoded code must be rejected: {code}"
            );
        }
    }

    #[test]
    fn ws_close_truncates_reason_safely() {
        let reason = "é".repeat(200);
        let encoded = encode_ws_close(Some(1000), &reason).unwrap();
        let (_, decoded) = decode_ws_close(&encoded).unwrap();
        assert!(decoded.len() <= MAX_WS_CLOSE_REASON);
        assert!(decoded.is_char_boundary(decoded.len()));
        assert!(reason.starts_with(&decoded));
    }

    #[test]
    fn ws_close_rejects_control_characters_in_reason() {
        assert!(encode_ws_close(Some(1000), "line\nbreak").is_err());
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&5u16.to_be_bytes());
        payload.extend_from_slice(b"bad\x1b");
        assert!(decode_ws_close(&payload).is_err());
    }

    #[test]
    fn ws_close_rejects_truncated_payloads() {
        assert!(matches!(
            decode_ws_close(&[]),
            Err(ProtocolError::UnexpectedEof("ws close code"))
        ));
        assert!(matches!(
            decode_ws_close(&[0x03, 0xe8]),
            Err(ProtocolError::UnexpectedEof("ws close reason"))
        ));
        assert!(matches!(
            decode_ws_close(&[0x03, 0xe8, 0x00, 0x05, b'a']),
            Err(ProtocolError::UnexpectedEof("ws close reason"))
        ));
    }

    #[test]
    fn ws_close_rejects_invalid_utf8_and_trailing_bytes() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.push(0xff);
        assert!(decode_ws_close(&payload).is_err());

        let mut trailing = Vec::new();
        trailing.extend_from_slice(&1000u16.to_be_bytes());
        trailing.extend_from_slice(&0u16.to_be_bytes());
        trailing.push(0);
        assert!(decode_ws_close(&trailing).is_err());
    }

    #[test]
    fn ws_close_reason_length_is_bounded_on_decode() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1000u16.to_be_bytes());
        payload.extend_from_slice(&((MAX_WS_CLOSE_REASON + 1) as u16).to_be_bytes());
        payload.resize(payload.len() + MAX_WS_CLOSE_REASON + 1, b'a');
        assert!(matches!(
            decode_ws_close(&payload),
            Err(ProtocolError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn window_credit_is_bounded() {
        assert!(decode_window_update(&0u32.to_be_bytes()).is_err());
        assert!(decode_window_update(&(MAX_WINDOW_CREDIT + 1).to_be_bytes()).is_err());
        assert_eq!(decode_window_update(&1024u32.to_be_bytes()).unwrap(), 1024);
    }

    #[test]
    fn debug_output_redacts_values_and_query() {
        let head = HttpRequestHead {
            method: "GET".into(),
            target: "/api/session?token=secret".into(),
            headers: vec![("cookie".into(), "session=secret".into())],
        };
        let text = format!("{head:?}");
        assert!(text.contains("/api/session?<redacted>"));
        assert!(!text.contains("secret"));
    }
}
