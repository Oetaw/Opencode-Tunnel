use std::time::Duration;

use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::generate_room_credentials;
use oct_relay::{Relay, RelayConfig};
use tokio_util::sync::CancellationToken;

/// Env-gated real-upstream smoke test.
///
/// `OCT_REAL_UPSTREAM` is the loopback origin of an already-running OpenCode
/// server (for example `http://127.0.0.1:54123`); `OPENCODE_PASSWORD` supplies
/// its Basic auth password. The test never reads or copies OpenCode state.
#[tokio::test]
async fn real_opencode_api_info_through_tunnel() {
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").ok();

    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let relay_url = format!("ws://{}/oct/v1", relay.local_addr());
    let relay_shutdown = CancellationToken::new();
    let relay_task_shutdown = relay_shutdown.clone();
    let relay_task = tokio::spawn(async move {
        let _ = relay.serve(relay_task_shutdown).await;
    });

    let (room, token) = generate_room_credentials();
    let host_shutdown = CancellationToken::new();
    let host = HostAgent::new(HostConfig {
        relay_url: relay_url.clone(),
        room: room.clone(),
        token: token.clone(),
        upstream_url: upstream,
        backend_password: password,
        ping_interval: Duration::from_secs(20),
        reconnect_max: Duration::from_secs(2),
        security: None,
    })
    .unwrap();
    let host_task_shutdown = host_shutdown.clone();
    let host_task = tokio::spawn(async move {
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

    let http = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let body: serde_json::Value = loop {
        let response = http
            .get(format!("{}/api/info", handle.local_url))
            .basic_auth("opencode", Some(&handle.password))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        if let Ok(response) = response {
            if response.status().is_success() {
                break response.json().await.unwrap();
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "real OpenCode did not answer through the tunnel"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    };
    assert_eq!(body["version"], "2.0.22");

    client_shutdown.cancel();
    host_shutdown.cancel();
    relay_shutdown.cancel();
    let _ = host_task.await;
    let _ = relay_task.await;
}
