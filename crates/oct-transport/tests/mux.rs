use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::join_all;
use oct_protocol::{
    ErrorCode, Feature, HttpRequestHead, HttpResponseHead, OpenWs, Role, WsOpcode, MAX_WS_MESSAGE,
};
use oct_security::{client_handshake, host_handshake, Identity};
use oct_transport::{
    Inbound, Mux, MuxConfig, OpenHandler, Stream, TransportError, WsConnection, WsMessage,
};
use tokio::io::duplex;
use tokio_tungstenite::{accept_async, client_async};

struct EchoHandler;

#[async_trait]
impl OpenHandler for EchoHandler {
    async fn on_http(&self, stream: Stream, _head: HttpRequestHead) {
        if stream
            .send_response(HttpResponseHead {
                status: 200,
                headers: vec![("content-type".into(), "application/octet-stream".into())],
            })
            .await
            .is_err()
        {
            return;
        }

        loop {
            match stream.recv().await {
                Ok(Some(Inbound::Data(data))) => {
                    if stream.send_data(data).await.is_err() {
                        return;
                    }
                }
                Ok(Some(Inbound::End)) => {
                    let _ = stream.finish().await;
                    return;
                }
                Ok(Some(Inbound::Reset { .. })) | Ok(None) | Err(_) => return,
                Ok(Some(Inbound::HttpResponse(_)))
                | Ok(Some(Inbound::WsMessage { .. }))
                | Ok(Some(Inbound::WsClose { .. })) => return,
            }
        }
    }

    async fn on_ws(&self, stream: Stream, _head: OpenWs) {
        loop {
            match stream.recv().await {
                Ok(Some(Inbound::WsMessage { opcode, payload })) => {
                    if stream.send_ws_message(opcode, payload).await.is_err() {
                        return;
                    }
                }
                Ok(Some(Inbound::WsClose { code, reason })) => {
                    let _ = stream.send_ws_close(code, &reason).await;
                    return;
                }
                Ok(Some(Inbound::End | Inbound::Reset { .. })) | Ok(None) | Err(_) => return,
                Ok(Some(Inbound::HttpResponse(_) | Inbound::Data(_))) => return,
            }
        }
    }
}

async fn mux_pair(max_streams: usize) -> (Mux, Mux) {
    let (client_io, host_io) = duplex(4 * 1024 * 1024);
    let (client_ws, host_ws) = tokio::join!(
        client_async("ws://localhost/oct", client_io),
        accept_async(host_io)
    );
    let client_ws = client_ws.expect("client websocket handshake").0;
    let host_ws = host_ws.expect("host websocket handshake");
    let client_conn = WsConnection::from_stream(client_ws).await;
    let host_conn = WsConnection::from_stream(host_ws).await;

    let client = Mux::new(
        client_conn,
        MuxConfig {
            role: Role::Client,
            epoch: 101,
            max_streams,
            ping_interval: None,
            idle_timeout: Duration::from_secs(30),
        },
        Arc::new(EchoHandler),
    );
    let host = Mux::new(
        host_conn,
        MuxConfig {
            role: Role::Host,
            epoch: 202,
            max_streams,
            ping_interval: None,
            idle_timeout: Duration::from_secs(30),
        },
        Arc::new(EchoHandler),
    );
    let (client_ready, host_ready) = tokio::join!(
        client.wait_ready(Duration::from_secs(5)),
        host.wait_ready(Duration::from_secs(5))
    );
    client_ready.expect("client mux ready");
    host_ready.expect("host mux ready");
    (client, host)
}

fn request_head() -> HttpRequestHead {
    HttpRequestHead {
        method: "POST".into(),
        target: "/echo".into(),
        headers: vec![("content-type".into(), "application/octet-stream".into())],
    }
}

fn ws_head() -> OpenWs {
    OpenWs {
        target: "/pty".into(),
        subprotocols: vec![],
        headers: vec![],
    }
}

async fn next_inbound(stream: &Stream) -> Inbound {
    match tokio::time::timeout(Duration::from_secs(5), stream.recv())
        .await
        .expect("stream recv timed out")
        .expect("stream recv failed")
    {
        Some(inbound) => inbound,
        None => panic!("stream ended without an inbound event"),
    }
}

async fn expect_ws_message(stream: &Stream, opcode: WsOpcode, expected: &[u8]) {
    match next_inbound(stream).await {
        Inbound::WsMessage {
            opcode: actual_opcode,
            payload,
        } => {
            assert_eq!(actual_opcode, opcode);
            assert_eq!(payload.as_ref(), expected);
        }
        other => panic!("expected a websocket message, got {other:?}"),
    }
}

async fn secure_mux_pair() -> (Mux, Mux) {
    let (client_io, host_io) = duplex(4 * 1024 * 1024);
    let (client_ws, host_ws) = tokio::join!(
        client_async("ws://localhost/oct", client_io),
        accept_async(host_io)
    );
    let client_conn =
        WsConnection::from_stream(client_ws.expect("client websocket handshake").0).await;
    let host_conn = WsConnection::from_stream(host_ws.expect("host websocket handshake")).await;

    let host_identity = Identity::generate();
    let client_identity = Identity::generate();
    let pinned_host = host_identity.public_key();
    let (client_session, host_session) = tokio::join!(
        client_handshake(&client_conn, &client_identity, &pinned_host),
        host_handshake(&host_conn, &host_identity)
    );
    client_conn.install_noise(Arc::new(client_session.expect("client noise")));
    host_conn.install_noise(Arc::new(host_session.expect("host noise")));

    let client = Mux::new(
        client_conn,
        MuxConfig {
            role: Role::Client,
            epoch: 301,
            max_streams: 8,
            ping_interval: None,
            idle_timeout: Duration::from_secs(30),
        },
        Arc::new(EchoHandler),
    );
    let host = Mux::new(
        host_conn,
        MuxConfig {
            role: Role::Host,
            epoch: 302,
            max_streams: 8,
            ping_interval: None,
            idle_timeout: Duration::from_secs(30),
        },
        Arc::new(EchoHandler),
    );
    let (client_ready, host_ready) = tokio::join!(
        client.wait_ready(Duration::from_secs(5)),
        host.wait_ready(Duration::from_secs(5))
    );
    let client_ready = client_ready.expect("secure client mux ready");
    let host_ready = host_ready.expect("secure host mux ready");
    assert!(client_ready.supports(Feature::E2ee));
    assert!(host_ready.supports(Feature::E2ee));
    (client, host)
}

#[tokio::test]
async fn secure_mux_roundtrips_http_and_ws_after_noise_handshake() {
    let (client, _host) = secure_mux_pair().await;

    let http = client.open_http(request_head()).await.unwrap();
    http.send_data(Bytes::from_static(b"encrypted body"))
        .await
        .unwrap();
    http.finish().await.unwrap();
    let mut body = Vec::new();
    loop {
        match next_inbound(&http).await {
            Inbound::HttpResponse(head) => assert_eq!(head.status, 200),
            Inbound::Data(bytes) => body.extend_from_slice(&bytes),
            Inbound::End => break,
            other => panic!("unexpected secure HTTP event: {other:?}"),
        }
    }
    assert_eq!(body, b"encrypted body");

    let ws = client.open_ws(ws_head()).await.unwrap();
    ws.send_ws_message(WsOpcode::Binary, Bytes::from_static(b"\x00pty"))
        .await
        .unwrap();
    expect_ws_message(&ws, WsOpcode::Binary, b"\x00pty").await;

    let large: Vec<u8> = (0..100 * 1024).map(|index| (index % 251) as u8).collect();
    ws.send_ws_message(WsOpcode::Binary, Bytes::from(large.clone()))
        .await
        .unwrap();
    expect_ws_message(&ws, WsOpcode::Binary, &large).await;
}

async fn secure_ws_pair() -> (WsConnection, WsConnection) {
    let (client_io, host_io) = duplex(4 * 1024 * 1024);
    let (client_ws, host_ws) = tokio::join!(
        client_async("ws://localhost/oct", client_io),
        accept_async(host_io)
    );
    let client_conn = WsConnection::from_stream(client_ws.expect("client handshake").0).await;
    let host_conn = WsConnection::from_stream(host_ws.expect("host handshake")).await;
    let host_identity = Identity::generate();
    let client_identity = Identity::generate();
    let pinned = host_identity.public_key();
    let (client_session, host_session) = tokio::join!(
        client_handshake(&client_conn, &client_identity, &pinned),
        host_handshake(&host_conn, &host_identity)
    );
    client_conn.install_noise(Arc::new(client_session.unwrap()));
    host_conn.install_noise(Arc::new(host_session.unwrap()));
    (client_conn, host_conn)
}

#[tokio::test]
async fn secure_transport_rekeys_bidirectionally() {
    let (client, host) = secure_ws_pair().await;
    client.set_rekey_threshold(64);
    host.set_rekey_threshold(64);

    for index in 0..16usize {
        let outbound = Bytes::from(format!("rekey-client-{index}-{}", "x".repeat(40)));
        client.send_binary(outbound.clone()).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), host.recv())
            .await
            .expect("client rekey receive timed out")
            .expect("client rekey receive failed")
        {
            Some(WsMessage::Binary(bytes)) => assert_eq!(bytes, outbound),
            other => panic!("unexpected client rekey frame: {other:?}"),
        }
    }

    for index in 0..16usize {
        let outbound = Bytes::from(format!("rekey-host-{index}-{}", "y".repeat(40)));
        host.send_binary(outbound.clone()).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("host rekey receive timed out")
            .expect("host rekey receive failed")
        {
            Some(WsMessage::Binary(bytes)) => assert_eq!(bytes, outbound),
            other => panic!("unexpected host rekey frame: {other:?}"),
        }
    }
}

#[tokio::test]
async fn concurrent_encrypted_sends_keep_noise_nonce_order() {
    let (client, host) = secure_ws_pair().await;
    let payloads: Vec<Bytes> = (0..128)
        .map(|index| Bytes::from(format!("secure-message-{index}")))
        .collect();

    let sender_payloads = payloads.clone();
    let sender = tokio::spawn(async move {
        let sends = sender_payloads
            .into_iter()
            .map(|payload| {
                let client = client.clone();
                async move { client.send_binary(payload).await.unwrap() }
            })
            .collect::<Vec<_>>();
        join_all(sends).await;
    });

    let mut received = Vec::new();
    for _ in 0..payloads.len() {
        match tokio::time::timeout(Duration::from_secs(5), host.recv())
            .await
            .expect("encrypted receive timed out")
            .expect("encrypted receive failed")
        {
            Some(WsMessage::Binary(bytes)) => received.push(bytes),
            other => panic!("unexpected encrypted frame: {other:?}"),
        }
    }
    sender.await.unwrap();

    let mut expected: Vec<Vec<u8>> = payloads.iter().map(|bytes| bytes.to_vec()).collect();
    let mut actual: Vec<Vec<u8>> = received.iter().map(|bytes| bytes.to_vec()).collect();
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn http_stream_exchanges_head_data_and_half_close() {
    let (client, _host) = mux_pair(8).await;
    let stream = client.open_http(request_head()).await.unwrap();
    assert_eq!(stream.id() & 1, 1, "client allocates odd stream ids");
    stream
        .send_data(Bytes::from_static(b"oct-payload"))
        .await
        .unwrap();
    stream.finish().await.unwrap();

    let mut saw_response = false;
    let mut body = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), stream.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Some(Inbound::HttpResponse(head)) => {
                assert_eq!(head.status, 200);
                saw_response = true;
            }
            Some(Inbound::Data(data)) => body.extend_from_slice(&data),
            Some(Inbound::End) => break,
            Some(Inbound::Reset { code, reason }) => panic!("unexpected reset {code:?}: {reason}"),
            Some(Inbound::WsMessage { .. } | Inbound::WsClose { .. }) => {
                panic!("unexpected websocket event on an http stream")
            }
            None => panic!("stream ended without END"),
        }
    }
    assert!(saw_response);
    assert_eq!(body, b"oct-payload");
}

#[tokio::test]
async fn supports_many_concurrent_streams() {
    let (client, _host) = mux_pair(256).await;
    let mut tasks = Vec::new();
    for index in 0..128u32 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let payload = Bytes::copy_from_slice(&index.to_be_bytes());
            let stream = client.open_http(request_head()).await.unwrap();
            stream.send_data(payload.clone()).await.unwrap();
            stream.finish().await.unwrap();
            let mut received = Vec::new();
            let mut response_seen = false;
            loop {
                match tokio::time::timeout(Duration::from_secs(10), stream.recv())
                    .await
                    .unwrap()
                    .unwrap()
                {
                    Some(Inbound::HttpResponse(head)) => {
                        assert_eq!(head.status, 200);
                        response_seen = true;
                    }
                    Some(Inbound::Data(bytes)) => received.extend_from_slice(&bytes),
                    Some(Inbound::End) => break,
                    Some(Inbound::Reset { code, reason }) => {
                        panic!("stream reset {code:?}: {reason}")
                    }
                    Some(Inbound::WsMessage { .. } | Inbound::WsClose { .. }) => {
                        panic!("unexpected websocket event on an http stream")
                    }
                    None => panic!("stream ended without END"),
                }
            }
            assert!(response_seen);
            assert_eq!(received, payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn large_stream_flow_control_does_not_deadlock() {
    let (client, _host) = mux_pair(8).await;
    let stream = client.open_http(request_head()).await.unwrap();
    let payload: Vec<u8> = (0..10 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();

    let sender = async {
        stream
            .send_data(Bytes::from(payload.clone()))
            .await
            .unwrap();
        stream.finish().await.unwrap();
    };
    let receiver = async {
        let mut received = Vec::new();
        loop {
            match next_inbound(&stream).await {
                Inbound::Data(bytes) => received.extend_from_slice(&bytes),
                Inbound::End => break,
                Inbound::HttpResponse(head) => assert_eq!(head.status, 200),
                Inbound::Reset { code, reason } => {
                    panic!("flow-control stream reset {code:?}: {reason}")
                }
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        received
    };
    let (_, received) = tokio::join!(sender, receiver);
    assert_eq!(received, payload);
}

#[tokio::test]
async fn flow_control_fairly_progresses_multiple_streams() {
    let (client, _host) = mux_pair(64).await;
    let mut tasks = Vec::new();
    for stream_index in 0..8u8 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let stream = client.open_http(request_head()).await.unwrap();
            let payload: Vec<u8> = (0..512 * 1024)
                .map(|index| (index as u8).wrapping_add(stream_index))
                .collect();
            let sender = async {
                stream
                    .send_data(Bytes::from(payload.clone()))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            };
            let receiver = async {
                let mut received = Vec::new();
                loop {
                    match next_inbound(&stream).await {
                        Inbound::Data(bytes) => received.extend_from_slice(&bytes),
                        Inbound::End => break,
                        Inbound::HttpResponse(head) => assert_eq!(head.status, 200),
                        Inbound::Reset { code, reason } => {
                            panic!("stream reset {code:?}: {reason}")
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                received
            };
            let (_, received) = tokio::join!(sender, receiver);
            assert_eq!(received, payload);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn websocket_messages_and_close_roundtrip() {
    let (client, _host) = mux_pair(8).await;
    let stream = client.open_ws(ws_head()).await.unwrap();
    assert_eq!(stream.id() & 1, 1, "client allocates odd stream ids");

    stream
        .send_ws_message(WsOpcode::Text, Bytes::from_static(b"hello"))
        .await
        .unwrap();
    expect_ws_message(&stream, WsOpcode::Text, b"hello").await;

    let binary = Bytes::from_static(b"\x00\x01\x02\x00\xff binary");
    stream
        .send_ws_message(WsOpcode::Binary, binary.clone())
        .await
        .unwrap();
    expect_ws_message(&stream, WsOpcode::Binary, &binary).await;

    stream
        .send_ws_message(WsOpcode::Text, Bytes::new())
        .await
        .unwrap();
    expect_ws_message(&stream, WsOpcode::Text, b"").await;

    // More than one 64 KiB frame, so the receiver must reassemble fragments.
    let large: Vec<u8> = (0..100 * 1024).map(|i| (i % 251) as u8).collect();
    stream
        .send_ws_message(WsOpcode::Binary, Bytes::from(large.clone()))
        .await
        .unwrap();
    expect_ws_message(&stream, WsOpcode::Binary, &large).await;

    stream
        .send_ws_close(Some(4000), "normal closure")
        .await
        .unwrap();
    match next_inbound(&stream).await {
        Inbound::WsClose { code, reason } => {
            assert_eq!(code, Some(4000));
            assert_eq!(reason, "normal closure");
        }
        other => panic!("expected a websocket close, got {other:?}"),
    }
}

#[tokio::test]
async fn websocket_send_apis_are_kind_scoped() {
    let (client, _host) = mux_pair(8).await;

    let http = client.open_http(request_head()).await.unwrap();
    assert!(matches!(
        http.send_ws_message(WsOpcode::Text, Bytes::from_static(b"x"))
            .await,
        Err(TransportError::Internal(_))
    ));
    assert!(matches!(
        http.send_ws_close(Some(1000), "not ws").await,
        Err(TransportError::Internal(_))
    ));

    let ws = client.open_ws(ws_head()).await.unwrap();
    assert!(matches!(
        ws.send_data(Bytes::from_static(b"x")).await,
        Err(TransportError::Internal(_))
    ));
    assert!(matches!(
        ws.send_response(HttpResponseHead {
            status: 200,
            headers: vec![],
        })
        .await,
        Err(TransportError::Internal(_))
    ));
    assert!(matches!(
        ws.finish().await,
        Err(TransportError::Internal(_))
    ));
    assert!(matches!(
        ws.send_ws_message(WsOpcode::Continuation, Bytes::new())
            .await,
        Err(TransportError::Internal(_))
    ));

    let oversized = Bytes::from(vec![0u8; MAX_WS_MESSAGE + 1]);
    assert!(matches!(
        ws.send_ws_message(WsOpcode::Binary, oversized).await,
        Err(TransportError::MessageTooLarge)
    ));
}

#[tokio::test]
async fn local_close_resets_active_stream_state() {
    let (client, _host) = mux_pair(8).await;
    let stream = client.open_http(request_head()).await.unwrap();
    client.close().await;
    assert!(client.is_closed());
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), stream.recv())
            .await
            .unwrap()
            .unwrap(),
        Some(Inbound::Reset {
            code: ErrorCode::Cancelled,
            ..
        })
    ));
}
