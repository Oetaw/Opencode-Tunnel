use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::generate_room_credentials;
use oct_relay::{Relay, RelayConfig};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

const TIMEOUT: Duration = Duration::from_secs(8);

/// Env-gated real-PTY test. It creates a shell PTY on the isolated OpenCode
/// server, mints a one-use ticket through the tunnel, and verifies that the
/// first binary PTY frame crosses the full gateway -> relay -> host path.
///
/// `OCT_REAL_UPSTREAM` and `OPENCODE_PASSWORD` are supplied by
/// `scripts/e2e-real-opencode.sh`.
#[tokio::test]
async fn real_opencode_pty_websocket_through_tunnel() {
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        assert_ne!(
            std::env::var("OCT_REQUIRE_REAL_PTY").ok().as_deref(),
            Some("1"),
            "OCT_REAL_UPSTREAM is required for the real PTY test"
        );
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").expect("OPENCODE_PASSWORD");

    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let relay_url = format!("ws://{}/oct/v1", relay.local_addr());
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
        upstream_url: upstream.clone(),
        backend_password: Some(password.clone()),
        ping_interval: Duration::from_secs(20),
        reconnect_max: Duration::from_secs(2),
        security: None,
    })
    .unwrap();
    let host_task_shutdown = host_shutdown.clone();
    tokio::spawn(async move {
        let _ = host.run(host_task_shutdown).await;
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
    wait_ready(&handle.local_url, &handle.password).await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let created: serde_json::Value = http
        .post(format!("{}/api/pty", handle.local_url))
        .basic_auth("opencode", Some(&handle.password))
        .json(&serde_json::json!({
            "command": "/bin/sh",
            "args": [],
            "cwd": workspace.path(),
            "title": "oct-pty-e2e",
        }))
        .timeout(TIMEOUT)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let pty_id = created["data"]["id"].as_str().unwrap().to_owned();

    let minted: serde_json::Value = http
        .post(format!(
            "{}/api/pty/{pty_id}/connect-token",
            handle.local_url
        ))
        .basic_auth("opencode", Some(&handle.password))
        .header("x-opencode-ticket", "1")
        .timeout(TIMEOUT)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let ticket = minted["data"]["ticket"].as_str().unwrap().to_owned();

    let ws_url = format!(
        "{}/api/pty/{pty_id}/connect?ticket={ticket}",
        handle.local_url.replacen("http://", "ws://", 1)
    );
    let mut request = ws_url.into_client_request().unwrap();
    let credentials = STANDARD.encode(format!("opencode:{}", handle.password));
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {credentials}")).unwrap(),
    );
    let (mut socket, response) =
        tokio::time::timeout(TIMEOUT, tokio_tungstenite::connect_async(request))
            .await
            .expect("PTY websocket handshake timed out")
            .expect("PTY websocket handshake failed");
    assert_eq!(response.status(), 101);

    let first = tokio::time::timeout(TIMEOUT, async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(bytes))) => break bytes,
                Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Frame(_))) => continue,
                Some(Ok(Message::Close(frame))) => {
                    panic!("PTY websocket closed before first frame: {frame:?}")
                }
                Some(Err(error)) => panic!("PTY websocket failed: {error}"),
                None => panic!("PTY websocket ended before first frame"),
            }
        }
    })
    .await
    .expect("timed out waiting for the PTY cursor frame");
    assert_eq!(
        first.first(),
        Some(&0u8),
        "first PTY frame must be the binary cursor tag"
    );

    let _ = socket.send(Message::Close(None)).await;
    let _ = http
        .delete(format!("{}/api/pty/{pty_id}", handle.local_url))
        .basic_auth("opencode", Some(&handle.password))
        .timeout(TIMEOUT)
        .send()
        .await;

    client_shutdown.cancel();
    host_shutdown.cancel();
    relay_shutdown.cancel();
}

async fn wait_ready(gateway: &str, password: &str) {
    let http = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let response = http
            .get(format!("{gateway}/api/info"))
            .basic_auth("opencode", Some(password))
            .timeout(Duration::from_secs(1))
            .send()
            .await;
        if response.as_ref().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "tunnel not ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
