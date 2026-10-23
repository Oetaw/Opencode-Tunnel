use std::time::Duration;

use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_relay::{Relay, RelayConfig};
use oct_testkit::spawn_fake_backend;
use tokio_util::sync::CancellationToken;

mod support;

async fn bind_relay(addr: std::net::SocketAddr) -> Relay {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match Relay::bind(RelayConfig {
            listen: addr,
            admission_token: Some(support::ADMISSION.into()),
            ..RelayConfig::default()
        })
        .await
        {
            Ok(relay) => return relay,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("could not rebind relay on {addr}: {error}"),
        }
    }
}

#[tokio::test]
async fn reconnects_after_relay_restart() {
    let backend = spawn_fake_backend().await;
    let relay = bind_relay("127.0.0.1:0".parse().unwrap()).await;
    let relay_addr = relay.local_addr();
    let relay_url = format!("ws://{relay_addr}/oct/v1");

    let relay_shutdown = CancellationToken::new();
    let relay_task_shutdown = relay_shutdown.clone();
    let mut relay_task = tokio::spawn(async move {
        let _ = relay.serve(relay_task_shutdown).await;
    });

    let (room, token) = support::plaintext_credentials();
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
    let url = format!("{}/api/info", handle.local_url);
    let password = handle.password.clone();

    wait_online(&http, &url, &password, Duration::from_secs(8)).await;

    relay_shutdown.cancel();
    let _ = (&mut relay_task).await;

    let relay = bind_relay(relay_addr).await;
    let second_shutdown = CancellationToken::new();
    let second_task_shutdown = second_shutdown.clone();
    let second_task = tokio::spawn(async move {
        let _ = relay.serve(second_task_shutdown).await;
    });

    wait_online(&http, &url, &password, Duration::from_secs(20)).await;

    client_shutdown.cancel();
    host_shutdown.cancel();
    second_shutdown.cancel();
    let _ = host_task.await;
    let _ = second_task.await;
}

async fn wait_online(http: &reqwest::Client, url: &str, password: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let response = http
            .get(url)
            .basic_auth("opencode", Some(password))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        if response.as_ref().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("tunnel did not recover: {response:?}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
