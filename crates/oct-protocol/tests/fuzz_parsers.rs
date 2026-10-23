use oct_protocol::httpwire::{
    decode_open_ws, decode_request_head, decode_response_head, decode_ws_close, decode_ws_message,
};
use oct_protocol::{decode_frame, decode_frame_exact, Hello};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_in_wire_decoders(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let mut framed = bytes::BytesMut::from(bytes.as_slice());
        let _ = decode_frame(&mut framed);
        let _ = decode_frame_exact(&bytes);
        let _ = decode_request_head(&bytes);
        let _ = decode_response_head(&bytes);
        let _ = decode_open_ws(&bytes);
        let _ = decode_ws_message(&bytes);
        let _ = decode_ws_close(&bytes);
        let _ = Hello::decode(&bytes);
    }
}
