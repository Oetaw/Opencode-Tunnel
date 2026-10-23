//! Criterion benchmarks for the OCT/1 wire codec.
//!
//! The timing configuration is intentionally short (sub-second per case) so
//! the whole suite stays around ten seconds and can be run manually in CI.
//! Run with:
//!
//! ```text
//! cargo bench -p oct-protocol --bench codec
//! ```
//!
//! The benchmarks cover the paths that sit on the mux data plane:
//!
//! * inner frame encode/decode for 64 B, 4 KiB and 64 KiB payloads,
//! * HTTP request head encode/decode with representative proxy headers,
//! * HELLO JSON encode/decode,
//! * quick rejection paths: a partial header (`Ok(None)`), a truncated
//!   payload, and an oversized declared length (rejected before any
//!   allocation).

use std::hint::black_box;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use oct_protocol::codec::{decode_frame, encode_frame};
use oct_protocol::hello::{Feature, Hello, Role};
use oct_protocol::httpwire::{decode_request_head, encode_request_head, HttpRequestHead};
use oct_protocol::types::{
    Flags, Frame, Kind, FLAG_FIN, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD, PROTOCOL_MAJOR,
};
use oct_protocol::ProtocolError;

const PAYLOAD_SIZES: [usize; 3] = [64, 4 * 1024, 64 * 1024];

/// Deterministic payload so runs are comparable across machines.
fn payload_of(len: usize) -> Bytes {
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len {
        bytes.push((i % 251) as u8);
    }
    Bytes::from(bytes)
}

fn data_frame(payload_len: usize) -> Frame {
    Frame::new(
        Kind::Data,
        0x0102_0304_0506_0708,
        42,
        7,
        payload_of(payload_len),
    )
    .with_flags(Flags(FLAG_FIN))
}

fn write_frame_header(dst: &mut BytesMut, kind: Kind, payload_len: u32) {
    dst.put_u8(PROTOCOL_MAJOR);
    dst.put_u8(kind.as_u8());
    dst.put_u16(0);
    dst.put_u64(1);
    dst.put_u64(42);
    dst.put_u64(7);
    dst.put_u32(payload_len);
}

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encode");
    for &size in &PAYLOAD_SIZES {
        let frame = data_frame(size);
        let mut dst = BytesMut::with_capacity(FRAME_HEADER_LEN + size);

        group.throughput(Throughput::Bytes((FRAME_HEADER_LEN + size) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            // Reuse one buffer, as a connection writer would. `clear` keeps the
            // allocation, so this measures framing, not the allocator.
            b.iter(|| {
                dst.clear();
                encode_frame(black_box(&frame), &mut dst).expect("encode frame");
                black_box(dst.len());
            });
        });
    }
    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode");
    for &size in &PAYLOAD_SIZES {
        let mut encoded = BytesMut::with_capacity(FRAME_HEADER_LEN + size);
        encode_frame(&data_frame(size), &mut encoded).expect("encode fixture");
        let encoded = encoded.freeze();

        group.throughput(Throughput::Bytes((FRAME_HEADER_LEN + size) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            // Setup copies the encoded frame into a fresh `BytesMut`, matching
            // a decoder that owns the read buffer. Setup is not measured.
            b.iter_batched(
                || BytesMut::from(&encoded[..]),
                |mut src| {
                    let frame = decode_frame(&mut src)
                        .expect("decode frame")
                        .expect("frame is complete");
                    black_box(frame);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn representative_request() -> HttpRequestHead {
    HttpRequestHead {
        method: "POST".to_owned(),
        target: "/session/ses_01J9Z6K8Y3V4W2X1/message?stream=true&limit=100".to_owned(),
        headers: vec![
            ("host".to_owned(), "127.0.0.1:4096".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".to_owned(), "text/event-stream".to_owned()),
            ("authorization".to_owned(), "Bearer test-token".to_owned()),
            (
                "user-agent".to_owned(),
                "opencode/1.0.0 (darwin; arm64)".to_owned(),
            ),
            ("content-length".to_owned(), "2048".to_owned()),
            ("accept-encoding".to_owned(), "gzip, br".to_owned()),
            ("x-request-id".to_owned(), "req_01J9Z6K8Y3V4W2X1".to_owned()),
        ],
    }
}

fn bench_http_request_head(c: &mut Criterion) {
    let head = representative_request();
    let encoded = encode_request_head(&head).expect("encode fixture");

    let mut group = c.benchmark_group("http_request_head");
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("encode", |b| {
        b.iter(|| {
            let bytes = encode_request_head(black_box(&head)).expect("encode request head");
            black_box(bytes);
        });
    });

    group.bench_function("decode", |b| {
        b.iter(|| {
            let head = decode_request_head(black_box(&encoded)).expect("decode request head");
            black_box(head);
        });
    });

    group.finish();
}

fn bench_hello(c: &mut Criterion) {
    let hello = Hello::new(
        Role::Host,
        &[
            Feature::Http,
            Feature::Sse,
            Feature::Ws,
            Feature::E2ee,
            Feature::Resync,
        ],
        Some("1.0.0".to_owned()),
    );
    let encoded = hello.encode().expect("encode fixture");

    let mut group = c.benchmark_group("hello");
    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("encode", |b| {
        b.iter(|| {
            let bytes = hello.encode().expect("encode hello");
            black_box(bytes);
        });
    });

    group.bench_function("decode", |b| {
        b.iter(|| {
            let hello = Hello::decode(black_box(&encoded)).expect("decode hello");
            black_box(hello);
        });
    });

    group.finish();
}

fn bench_frame_decode_rejections(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode_rejects");

    // A partial header is the normal state while a websocket message is being
    // accumulated. It must return `Ok(None)` without touching the buffer.
    let mut partial_header = BytesMut::with_capacity(FRAME_HEADER_LEN);
    partial_header.put_u8(PROTOCOL_MAJOR);
    partial_header.put_u8(Kind::Data.as_u8());
    partial_header.put_u16(0);
    partial_header.put_u64(1);
    group.bench_function("partial_header_returns_none", |b| {
        b.iter(|| {
            let frame = decode_frame(black_box(&mut partial_header)).expect("not an error");
            assert!(frame.is_none());
            black_box(frame);
        });
    });

    // A complete header whose declared payload has not fully arrived returns
    // `Truncated` (the library's bounded counterpart to `Ok(None)`), again
    // without allocating. The buffer is not advanced on this path.
    let mut truncated_payload = BytesMut::with_capacity(129);
    write_frame_header(&mut truncated_payload, Kind::Data, 64 * 1024);
    truncated_payload.extend_from_slice(&[0u8; 97]);
    group.bench_function("truncated_payload", |b| {
        b.iter(|| {
            let err = decode_frame(black_box(&mut truncated_payload)).unwrap_err();
            assert!(matches!(err, ProtocolError::Truncated { .. }));
            black_box(err);
        });
    });

    // A hostile declared length must be rejected from the 32-byte header
    // alone: no reservation, no advance, no payload copy.
    let mut oversized = BytesMut::with_capacity(FRAME_HEADER_LEN);
    write_frame_header(&mut oversized, Kind::Data, (MAX_FRAME_PAYLOAD + 1) as u32);
    group.bench_function("oversized_length", |b| {
        b.iter(|| {
            let err = decode_frame(black_box(&mut oversized)).unwrap_err();
            assert!(matches!(err, ProtocolError::PayloadTooLarge(_)));
            black_box(err);
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(400))
        .sample_size(20)
        .without_plots();
    targets =
        bench_frame_encode,
        bench_frame_decode,
        bench_http_request_head,
        bench_hello,
        bench_frame_decode_rejections
}

criterion_main!(benches);
