use std::sync::Arc;
use std::time::Duration;

use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_relay::{Relay, RelayConfig};
use oct_security::{ClientSecurity, HostSecurity, Identity, Invite};
use oct_testkit::spawn_fake_backend;
use tokio_util::sync::CancellationToken;

mod support;

#[tokio::test]
async fn invite_enrollment_encrypts_the_tunnel_and_revocation_closes_it() {
    let backend = spawn_fake_backend().await;
    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        admission_token: Some(support::ADMISSION.into()),
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

    let state = tempfile::tempdir().unwrap();
    let host_security = Arc::new(HostSecurity::load_or_create(state.path()).unwrap());
    let (room, host_token, client_token) = support::e2ee_credentials();
    let invite = Invite::new(
        relay_url.clone(),
        room.clone(),
        client_token.clone(),
        host_security.identity.public_key(),
        300,
        Some("e2ee-test".into()),
    )
    .unwrap();
    host_security.invites.create(&invite).unwrap();

    let host_shutdown = CancellationToken::new();
    let host = HostAgent::new(HostConfig {
        relay_url: relay_url.clone(),
        room: room.clone(),
        token: host_token.clone(),
        upstream_url: backend.base_url.clone(),
        backend_password: None,
        ping_interval: Duration::from_secs(20),
        reconnect_max: Duration::from_secs(2),
        security: Some(Arc::clone(&host_security)),
    })
    .unwrap();
    let host_stop = host_shutdown.clone();
    let host_task = tokio::spawn(async move { host.run(host_stop).await });

    let client_security = Arc::new(ClientSecurity::new(
        Identity::generate(),
        host_security.identity.public_key(),
        "test-device",
        Some(invite.secret.clone()),
    ));
    let client = TunnelClient::new(ClientConfig {
        relay_url,
        room,
        token: client_token,
        gateway_bind: "127.0.0.1:0".parse().unwrap(),
        connect_timeout: Duration::from_secs(2),
        security: Some(Arc::clone(&client_security)),
    })
    .unwrap();
    let client_shutdown = CancellationToken::new();
    let handle = client.start(client_shutdown.clone()).await.unwrap();
    wait_online(&handle.local_url, &handle.password, Duration::from_secs(10)).await;

    let http = reqwest::Client::new();
    let info: serde_json::Value = http
        .get(format!("{}/api/info", handle.local_url))
        .basic_auth("opencode", Some(&handle.password))
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["version"], "2.0.22");

    let device = host_security
        .devices
        .find(&client_security.identity.public_key())
        .unwrap()
        .expect("client should be enrolled");
    host_security.devices.revoke(&device.id).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let status = http
            .get(format!("{}/api/info", handle.local_url))
            .basic_auth("opencode", Some(&handle.password))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .map(|response| response.status());
        if !status.is_ok_and(|status| status == reqwest::StatusCode::OK) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "revocation did not close the active tunnel"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    client_shutdown.cancel();
    host_shutdown.cancel();
    relay_shutdown.cancel();
    let _ = host_task.await;
}

async fn wait_online(gateway: &str, password: &str, timeout: Duration) {
    let http = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let ok = http
            .get(format!("{gateway}/api/info"))
            .basic_auth("opencode", Some(password))
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success());
        if ok {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "E2EE tunnel did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn unpaired_client_cannot_open_the_tunnel() {
    let backend = spawn_fake_backend().await;
    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        admission_token: Some(support::ADMISSION.into()),
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

    let state = tempfile::tempdir().unwrap();
    let host_security = Arc::new(HostSecurity::load_or_create(state.path()).unwrap());
    let (room, host_token, client_token) = support::e2ee_credentials();
    let host_shutdown = CancellationToken::new();
    let host = HostAgent::new(HostConfig {
        relay_url: relay_url.clone(),
        room: room.clone(),
        token: host_token.clone(),
        upstream_url: backend.base_url.clone(),
        backend_password: None,
        ping_interval: Duration::from_secs(20),
        reconnect_max: Duration::from_secs(2),
        security: Some(Arc::clone(&host_security)),
    })
    .unwrap();
    let host_stop = host_shutdown.clone();
    tokio::spawn(async move { host.run(host_stop).await });

    let client_security = Arc::new(ClientSecurity::new(
        Identity::generate(),
        host_security.identity.public_key(),
        "unpaired",
        None,
    ));
    let client = TunnelClient::new(ClientConfig {
        relay_url,
        room,
        token: client_token,
        gateway_bind: "127.0.0.1:0".parse().unwrap(),
        connect_timeout: Duration::from_secs(2),
        security: Some(client_security),
    })
    .unwrap();
    let client_shutdown = CancellationToken::new();
    let handle = client.start(client_shutdown.clone()).await.unwrap();
    let http = reqwest::Client::new();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let status = http
        .get(format!("{}/api/info", handle.local_url))
        .basic_auth("opencode", Some(&handle.password))
        .timeout(Duration::from_secs(1))
        .send()
        .await
        .map(|response| response.status());
    assert_ne!(
        status.ok(),
        Some(reqwest::StatusCode::OK),
        "an unpaired client must not receive a successful response"
    );

    client_shutdown.cancel();
    host_shutdown.cancel();
    relay_shutdown.cancel();
}
