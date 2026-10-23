use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::errors::ProtocolError;
use crate::types::{Flags, Frame, Kind, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD, PROTOCOL_MAJOR};

/// Encode one frame into `dst`. The caller must treat `dst` as a stream of
/// independent websocket messages; frame boundaries are preserved by the
/// carrier.
pub fn encode_frame(frame: &Frame, dst: &mut BytesMut) -> Result<(), ProtocolError> {
    if !frame.validate() {
        if frame.version != PROTOCOL_MAJOR {
            return Err(ProtocolError::UnsupportedVersion(frame.version));
        }
        if !frame.flags.validate() {
            return Err(ProtocolError::InvalidFlags(frame.flags.0));
        }
        if frame.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge(frame.payload.len()));
        }
        return Err(ProtocolError::UnexpectedPayload { kind: frame.kind });
    }

    dst.reserve(FRAME_HEADER_LEN + frame.payload.len());
    dst.put_u8(frame.version);
    dst.put_u8(frame.kind.as_u8());
    dst.put_u16(frame.flags.0);
    dst.put_u64(frame.epoch);
    dst.put_u64(frame.stream);
    dst.put_u64(frame.seq);
    dst.put_u32(frame.payload.len() as u32);
    dst.extend_from_slice(&frame.payload);
    Ok(())
}

/// Decode one complete frame from the front of `src`.
///
/// Returns `Ok(None)` when more bytes are required. The function validates
/// lengths *before* allocating or advancing so a hostile peer cannot make the
/// process reserve unbounded memory.
pub fn decode_frame(src: &mut BytesMut) -> Result<Option<Frame>, ProtocolError> {
    if src.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }

    let version = src[0];
    if version != PROTOCOL_MAJOR {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = Kind::from_u8(src[1]).ok_or(ProtocolError::UnsupportedKind(src[1]))?;
    let flags = Flags(u16::from_be_bytes([src[2], src[3]]));
    if !flags.validate() {
        return Err(ProtocolError::InvalidFlags(flags.0));
    }
    let epoch = u64::from_be_bytes(src[4..12].try_into().expect("header slice"));
    let stream = u64::from_be_bytes(src[12..20].try_into().expect("header slice"));
    let seq = u64::from_be_bytes(src[20..28].try_into().expect("header slice"));
    let payload_len = u32::from_be_bytes(src[28..32].try_into().expect("header slice")) as usize;

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(payload_len));
    }
    if !kind.payload_allowed() && payload_len != 0 {
        return Err(ProtocolError::UnexpectedPayload { kind });
    }
    let total = FRAME_HEADER_LEN + payload_len;
    if src.len() < total {
        return Err(ProtocolError::Truncated {
            need: total,
            have: src.len(),
        });
    }

    src.advance(FRAME_HEADER_LEN);
    let payload = src.split_to(payload_len).freeze();
    Ok(Some(Frame {
        version,
        kind,
        flags,
        epoch,
        stream,
        seq,
        payload,
    }))
}

/// Encode a single frame to a freshly allocated buffer. Used by tests and the
/// relay framing fallback where a one-shot message is convenient.
pub fn encode_frame_to_vec(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    // Validate the peer-influenced length before reserving memory.
    if frame.payload.len() > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::PayloadTooLarge(frame.payload.len()));
    }
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_LEN + frame.payload.len());
    encode_frame(frame, &mut buf)?;
    Ok(buf.to_vec())
}

/// Decode exactly one frame and reject trailing bytes.
pub fn decode_frame_exact(bytes: &[u8]) -> Result<Frame, ProtocolError> {
    let mut buf = BytesMut::from(bytes);
    let frame = decode_frame(&mut buf)?.ok_or(ProtocolError::Truncated {
        need: FRAME_HEADER_LEN,
        have: bytes.len(),
    })?;
    if !buf.is_empty() {
        return Err(ProtocolError::Malformed {
            context: "frame message",
            reason: format!("{} trailing bytes", buf.len()),
        });
    }
    Ok(frame)
}

/// Convert a payload into a `Bytes` frame body without copying.
pub fn payload(bytes: impl Into<Bytes>) -> Bytes {
    bytes.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FLAG_CRITICAL, MAX_FRAME_PAYLOAD};

    fn sample(kind: Kind, payload: &[u8]) -> Frame {
        Frame::new(kind, 7, 3, 42, Bytes::copy_from_slice(payload))
    }

    #[test]
    fn roundtrip() {
        let frame = sample(Kind::Data, b"hello world").with_flags(Flags(FLAG_CRITICAL));
        let encoded = encode_frame_to_vec(&frame).unwrap();
        let decoded = decode_frame_exact(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn empty_data_roundtrip() {
        let frame = sample(Kind::Data, b"");
        let encoded = encode_frame_to_vec(&frame).unwrap();
        let decoded = decode_frame_exact(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn rejects_oversized_payload_before_allocating() {
        let mut buf = BytesMut::new();
        buf.put_u8(PROTOCOL_MAJOR);
        buf.put_u8(Kind::Data.as_u8());
        buf.put_u16(0);
        buf.put_u64(1);
        buf.put_u64(1);
        buf.put_u64(1);
        buf.put_u32((MAX_FRAME_PAYLOAD + 1) as u32);
        let err = decode_frame(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::PayloadTooLarge(_)));
    }

    #[test]
    fn returns_none_for_partial_header() {
        let mut buf = BytesMut::from(&[PROTOCOL_MAJOR, 4, 0][..]);
        assert!(decode_frame(&mut buf).unwrap().is_none());
    }

    #[test]
    fn rejects_payload_on_end() {
        let mut frame = sample(Kind::End, b"nope");
        // Bypass `validate` to exercise the decoder's independent check.
        frame.flags = Flags::empty();
        let mut buf = BytesMut::new();
        buf.put_u8(PROTOCOL_MAJOR);
        buf.put_u8(Kind::End.as_u8());
        buf.put_u16(0);
        buf.put_u64(1);
        buf.put_u64(1);
        buf.put_u64(1);
        buf.put_u32(4);
        buf.extend_from_slice(b"nope");
        let err = decode_frame(&mut buf).unwrap_err();
        assert!(matches!(err, ProtocolError::UnexpectedPayload { .. }));
    }

    #[test]
    fn pong_challenge_roundtrip() {
        let frame = sample(Kind::Pong, b"challenge-123");
        let encoded = encode_frame_to_vec(&frame).unwrap();
        let decoded = decode_frame_exact(&encoded).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let frame = sample(Kind::Ping, b"x");
        let mut encoded = encode_frame_to_vec(&frame).unwrap();
        encoded.push(0xff);
        assert!(decode_frame_exact(&encoded).is_err());
    }
}
