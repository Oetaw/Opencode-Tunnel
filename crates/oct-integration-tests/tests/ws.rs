use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::generate_room_credentials;
use oct_relay::{Relay, RelayConfig};
use oct_testkit::spawn_fake_backend;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HOST, ORIGIN};
use tokio_tungstenite::tungstenite::http::{HeaderValue, Request};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(5);

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Harness {
    backend: oct_testkit::FakeBackend,
    gateway_url: String,
    password: String,
    client_shutdown: CancellationToken,
    host_shutdown: CancellationToken,
    relay_shutdown: CancellationToken,
    client_task: tokio::task::JoinHandle<()>,
    host_task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn spawn() -> Self {
        let backend = spawn_fake_backend().await;
        let relay = Relay::bind(RelayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..RelayConfig::default()
        })
        .await
        .unwrap();
        let relay_addr = relay.local_addr();
        let relay_url = format!("ws://{relay_addr}/oct/v1");
        let relay_shutdown = CancellationToken::new();
        let relay_task_shutdown = relay_shutdown.clone();
        tokio::spawn(async move {
            let _ = relay.serve(relay_task_shutdown).await;
        });

        let (room, token) = generate_room_credentials();
        let host_shutdown = CancellationToken::new();
        let host = HostAgent::new(HostConfig {
            relay_url: relay_url.clone(),
            room: room.clone(),
            token: token.clone(),
            upstream_url: backend.base_url.clone(),
            backend_password: None,
            ping_interval: Duration::from_secs(20),
            reconnect_max: Duration::from_secs(2),
            security: None,
        })
        .unwrap();
        let host_shutdown_task = host_shutdown.clone();
        let host_task = tokio::spawn(async move {
            let _ = host.run(host_shutdown_task).await;
        });

        let client = TunnelClient::new(ClientConfig {
            relay_url,
            room,
            token,
            gateway_bind: "127.0.0.1:0".parse().unwrap(),
            connect_timeout: Duration::from_secs(2),
            security: None,
        })
        .unwrap();
        let client_shutdown = CancellationToken::new();
        let handle = client.start(client_shutdown.clone()).await.unwrap();
        let gateway_url = handle.local_url.clone();
        let password = handle.password.clone();
        let client_task = tokio::spawn(async move {
            let _ = handle;
        });

        let harness = Self {
            backend,
            gateway_url,
            password,
            client_shutdown,
            host_shutdown,
            relay_shutdown,
            client_task,
            host_task,
        };
        harness.wait_online().await;
        harness
    }

    async fn wait_online(&self) {
        let http = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let response = http
                .get(format!("{}/api/info", self.gateway_url))
                .basic_auth("opencode", Some(&self.password))
                .timeout(Duration::from_secs(1))
                .send()
                .await;
            if response.as_ref().is_ok_and(|r| r.status().is_success()) {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("tunnel did not become ready: {response:?}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn ws_url(&self) -> String {
        format!(
            "{}/ws/echo",
            self.gateway_url.replacen("http://", "ws://", 1)
        )
    }

    fn gateway_addr(&self) -> std::net::SocketAddr {
        self.gateway_url
            .trim_start_matches("http://")
            .parse()
            .expect("gateway URL should contain a socket address")
    }

    fn request(&self, password: Option<&str>) -> Request<()> {
        let mut request = self.ws_url().into_client_request().unwrap();
        if let Some(password) = password {
            request
                .headers_mut()
                .insert(AUTHORIZATION, basic_auth_header(password));
        }
        request
    }

    async fn connect(&self) -> Ws {
        let (socket, response) = tokio::time::timeout(
            TIMEOUT,
            tokio_tungstenite::connect_async(self.request(Some(&self.password))),
        )
        .await
        .expect("websocket connect timed out")
        .expect("websocket connect failed");
        assert_eq!(response.status(), 101);
        socket
    }

    async fn handshake_error(&self, request: Request<()>) -> WsError {
        let tcp =
            tokio::time::timeout(TIMEOUT, tokio::net::TcpStream::connect(self.gateway_addr()))
                .await
                .expect("tcp connect timed out")
                .expect("tcp connect failed");
        tokio::time::timeout(TIMEOUT, tokio_tungstenite::client_async(request, tcp))
            .await
            .expect("websocket handshake timed out")
            .expect_err("gateway should reject the websocket handshake")
    }

    async fn shutdown(self) {
        self.client_shutdown.cancel();
        self.host_shutdown.cancel();
        self.relay_shutdown.cancel();
        self.client_task.abort();
        let _ = self.host_task.await;
    }
}

fn basic_auth_header(password: &str) -> HeaderValue {
    let credentials = format!("opencode:{password}");
    HeaderValue::from_str(&format!("Basic {}", base64_encode(credentials.as_bytes()))).unwrap()
}

/// Minimal standard-alphabet base64 so the test does not need an extra crate.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        let value = (u32::from(chunk[0]) << 16) | (u32::from(second) << 8) | u32::from(third);
        encoded.push(ALPHABET[((value >> 18) & 0x3f) as usize] as char);
        encoded.push(ALPHABET[((value >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[((value >> 6) & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(value & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
    }
    encoded
}

async fn recv(ws: &mut Ws) -> Message {
    loop {
        let message = tokio::time::timeout(TIMEOUT, ws.next())
            .await
            .expect("timed out waiting for a websocket frame")
            .expect("websocket closed before echoing")
            .expect("websocket receive failed");
        match message {
            Message::Ping(_) | Message::Pong(_) => continue,
            message => return message,
        }
    }
}

fn assert_http_status(error: WsError, expected: u16) {
    match error {
        WsError::Http(response) => {
            assert_eq!(
                response.status().as_u16(),
                expected,
                "unexpected handshake rejection status"
            );
        }
        other => panic!("expected an HTTP handshake rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn websocket_text_binary_and_large_messages_roundtrip_through_tunnel() {
    let harness = Harness::spawn().await;
    let mut ws = harness.connect().await;

    ws.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(recv(&mut ws).await, Message::Text("hello".into()));

    let mut binary = vec![0x00, 0xff, 0x7f, 0x80];
    binary.extend_from_slice(b"\x00{\"cursor\":0}");
    ws.send(Message::Binary(binary.clone().into()))
        .await
        .unwrap();
    assert_eq!(recv(&mut ws).await, Message::Binary(binary.into()));

    let large = (0..100 * 1024).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    ws.send(Message::Binary(large.clone().into()))
        .await
        .unwrap();
    assert_eq!(recv(&mut ws).await, Message::Binary(large.into()));

    ws.send(Message::Text(String::new().into())).await.unwrap();
    assert_eq!(recv(&mut ws).await, Message::Text(String::new().into()));

    ws.send(Message::Binary(Vec::new().into())).await.unwrap();
    assert_eq!(recv(&mut ws).await, Message::Binary(Vec::new().into()));

    assert!(
        harness
            .backend
            .requests()
            .iter()
            .any(|record| record.path == "/ws/echo"),
        "fake backend never saw the websocket upgrade"
    );

    ws.send(Message::Close(None)).await.unwrap();
    let closed = tokio::time::timeout(TIMEOUT, async {
        loop {
            match ws.next().await {
                None | Some(Ok(Message::Close(_))) => break,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(other)) => panic!("unexpected frame after close: {other:?}"),
                Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => break,
                Some(Err(error)) => panic!("websocket close failed: {error}"),
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "gateway did not close the websocket within the timeout"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn websocket_upgrade_requires_gateway_auth_and_host() {
    let harness = Harness::spawn().await;

    let missing_auth = harness.handshake_error(harness.request(None)).await;
    assert_http_status(missing_auth, 401);

    let wrong_password = harness.request(Some("wrong-password"));
    let wrong_auth = harness.handshake_error(wrong_password).await;
    assert_http_status(wrong_auth, 401);

    let mut bad_host = harness.request(Some(&harness.password));
    bad_host
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("attacker.example"));
    let bad_host = harness.handshake_error(bad_host).await;
    assert_http_status(bad_host, 403);

    let mut bad_origin = harness.request(Some(&harness.password));
    bad_origin
        .headers_mut()
        .insert(ORIGIN, HeaderValue::from_static("http://attacker.example"));
    let bad_origin = harness.handshake_error(bad_origin).await;
    assert_http_status(bad_origin, 403);

    harness.shutdown().await;
}
