use std::time::Duration;

use futures_util::StreamExt;
use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::generate_room_credentials;
use oct_relay::{Relay, RelayConfig};
use oct_testkit::spawn_fake_backend;
use serde_json::json;
use tokio_util::sync::CancellationToken;

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

    fn http(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http()
            .request(method, format!("{}{}", self.gateway_url, path))
            .basic_auth("opencode", Some(&self.password))
    }

    async fn shutdown(self) {
        self.client_shutdown.cancel();
        self.host_shutdown.cancel();
        self.relay_shutdown.cancel();
        self.client_task.abort();
        let _ = self.host_task.await;
    }
}

#[tokio::test]
async fn proxies_http_bodies_queries_and_headers() {
    let harness = Harness::spawn().await;
    let response = harness
        .request(reqwest::Method::POST, "/echo?raw=a%2Fb&x=1")
        .header("x-test", "value")
        .body("payload-\u{1F980}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/echo");
    assert_eq!(body["query"], "raw=a%2Fb&x=1");
    assert_eq!(body["body"], "payload-\u{1F980}");
    assert_eq!(body["headers"]["x-test"], json!(["value"]));
    // The local gateway password must never reach the backend.
    assert!(body["headers"]["authorization"].is_null());
    harness.shutdown().await;
}

#[tokio::test]
async fn forwarding_live_sse_events() {
    let harness = Harness::spawn().await;
    let response = harness
        .request(reqwest::Method::GET, "/api/event")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        harness
            .backend
            .wait_for_subscribers(1, Duration::from_secs(3))
            .await
    );

    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    harness.backend.broadcast_json(&json!({
        "type": "server.connected",
        "properties": {"seq": 7}
    }));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let chunk = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
        if let Ok(Some(Ok(bytes))) = chunk {
            buffer.extend_from_slice(&bytes);
            let text = String::from_utf8_lossy(&buffer);
            if text.contains("\"seq\":7") {
                harness.shutdown().await;
                return;
            }
        }
    }
    panic!(
        "SSE event was not forwarded: {}",
        String::from_utf8_lossy(&buffer)
    );
}

#[tokio::test]
async fn dropping_sse_response_cancels_the_upstream_subscription() {
    let harness = Harness::spawn().await;
    harness
        .backend
        .state
        .set_keepalive(Duration::from_millis(100));
    let response = harness
        .request(reqwest::Method::GET, "/api/event")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        harness
            .backend
            .wait_for_subscribers(1, Duration::from_secs(3))
            .await
    );
    drop(response);
    assert!(
        harness
            .backend
            .state
            .wait_for_no_subscribers(Duration::from_secs(5))
            .await,
        "host kept the upstream SSE subscription after the client disconnected"
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn gateway_rejects_wrong_password_and_bad_host() {
    let harness = Harness::spawn().await;
    let wrong = harness
        .http()
        .get(format!("{}/api/info", harness.gateway_url))
        .basic_auth("opencode", Some("wrong"))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(wrong.headers().get("www-authenticate").is_some());

    let bad_host = harness
        .request(reqwest::Method::GET, "/api/info")
        .header("host", "attacker.example")
        .send()
        .await
        .unwrap();
    assert_eq!(bad_host.status(), reqwest::StatusCode::FORBIDDEN);
    harness.shutdown().await;
}

#[tokio::test]
async fn host_offline_is_explicit_not_synthetic_success() {
    let harness = Harness::spawn().await;
    harness.host_shutdown.cancel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let response = harness
            .request(reqwest::Method::GET, "/api/info")
            .send()
            .await
            .unwrap();
        if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(
                response.headers().get("x-oct-error").unwrap(),
                "HOST_OFFLINE"
            );
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("gateway still reported success after host shutdown");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    harness.shutdown().await;
}
