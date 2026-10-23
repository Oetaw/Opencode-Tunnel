use std::process::Stdio;
use std::time::Duration;

use futures_util::StreamExt;
use oct_client::{ClientConfig, TunnelClient};
use oct_host::{HostAgent, HostConfig};
use oct_protocol::relay::generate_room_credentials;
use oct_relay::{Relay, RelayConfig};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Tunnel {
    gateway_url: String,
    gateway_password: String,
    client_shutdown: CancellationToken,
    host_shutdown: CancellationToken,
    relay_shutdown: CancellationToken,
}

impl Tunnel {
    async fn start(upstream: &str, backend_password: Option<String>) -> Self {
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
            upstream_url: upstream.to_owned(),
            backend_password,
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
        let gateway_url = handle.local_url.clone();
        let gateway_password = handle.password.clone();
        wait_ready(&gateway_url, &gateway_password).await;
        Self {
            gateway_url,
            gateway_password,
            client_shutdown,
            host_shutdown,
            relay_shutdown,
        }
    }

    fn stop(&self) {
        self.client_shutdown.cancel();
        self.host_shutdown.cancel();
        self.relay_shutdown.cancel();
    }
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

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn direct_get(upstream: &str, password: &str, path: &str) -> reqwest::Response {
    client()
        .get(format!("{upstream}{path}"))
        .basic_auth("opencode", Some(password))
        .send()
        .await
        .unwrap()
}

async fn gateway_get(tunnel: &Tunnel, path: &str) -> reqwest::Response {
    client()
        .get(format!("{}{path}", tunnel.gateway_url))
        .basic_auth("opencode", Some(&tunnel.gateway_password))
        .send()
        .await
        .unwrap()
}

async fn assert_same_get(upstream: &str, password: &str, tunnel: &Tunnel, path: &str) {
    let direct = direct_get(upstream, password, path).await;
    let tunneled = gateway_get(tunnel, path).await;
    assert_eq!(direct.status(), tunneled.status(), "status for {path}");
    assert_eq!(
        direct.headers().get("content-type"),
        tunneled.headers().get("content-type"),
        "content-type for {path}"
    );
    let direct_body = direct.bytes().await.unwrap();
    let tunneled_body = tunneled.bytes().await.unwrap();
    assert!(
        direct_body == tunneled_body,
        "body differs for {path} (direct {} bytes, tunnel {} bytes)",
        direct_body.len(),
        tunneled_body.len()
    );
}

#[tokio::test]
async fn read_only_api_is_byte_identical_through_the_tunnel() {
    let _guard = TEST_LOCK.lock().await;
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").unwrap_or_default();
    let tunnel = Tunnel::start(&upstream, Some(password.clone())).await;

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
    std::fs::write(dir.path().join("b.txt"), b"b").unwrap();
    let fs_list = format!("/api/fs/list?path={}", dir.path().display());

    let paths = [
        "/api/info",
        "/api/config",
        "/api/location",
        "/api/agent",
        "/api/model",
        "/api/provider",
        "/api/project",
        "/api/session",
        "/api/command",
        "/api/skill",
        "/api/vcs",
        "/api/vcs/status",
        "/api/vcs/branch",
        fs_list.as_str(),
        "/openapi.json",
        "/api/does-not-exist",
    ];
    for path in &paths {
        // Warm lazy upstream caches (notably /api/vcs computes git metadata on
        // first access) so the comparison measures the tunnel, not first-call
        // initialization order.
        let _ = direct_get(&upstream, &password, path).await;
        let _ = gateway_get(&tunnel, path).await;
    }
    for path in paths {
        assert_same_get(&upstream, &password, &tunnel, path).await;
    }

    let direct_head = client()
        .head(format!("{upstream}/api/info"))
        .basic_auth("opencode", Some(&password))
        .send()
        .await
        .unwrap();
    let tunneled_head = client()
        .head(format!("{}/api/info", tunnel.gateway_url))
        .basic_auth("opencode", Some(&tunnel.gateway_password))
        .send()
        .await
        .unwrap();
    assert_eq!(direct_head.status(), tunneled_head.status());
    assert_eq!(
        direct_head.headers().get("content-type"),
        tunneled_head.headers().get("content-type")
    );
    assert!(direct_head.bytes().await.unwrap().is_empty());
    assert!(tunneled_head.bytes().await.unwrap().is_empty());

    let direct = client()
        .put(format!("{upstream}/api/info"))
        .basic_auth("opencode", Some(&password))
        .send()
        .await
        .unwrap();
    let tunneled = client()
        .put(format!("{}/api/info", tunnel.gateway_url))
        .basic_auth("opencode", Some(&tunnel.gateway_password))
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), tunneled.status());
    assert_eq!(
        direct.bytes().await.unwrap(),
        tunneled.bytes().await.unwrap()
    );

    tunnel.stop();
}

#[tokio::test]
async fn mutations_and_session_reads_match_direct_opencode() {
    let _guard = TEST_LOCK.lock().await;
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").unwrap_or_default();
    let tunnel = Tunnel::start(&upstream, Some(password.clone())).await;
    let http = client();

    let create_direct = http
        .post(format!("{upstream}/api/session"))
        .basic_auth("opencode", Some(&password))
        .json(&json!({"title": "oct parity direct"}))
        .send()
        .await
        .unwrap();
    let create_tunnel = http
        .post(format!("{}/api/session", tunnel.gateway_url))
        .basic_auth("opencode", Some(&tunnel.gateway_password))
        .json(&json!({"title": "oct parity tunnel"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_direct.status(), create_tunnel.status());
    let direct: Value = create_direct.json().await.unwrap();
    let tunneled: Value = create_tunnel.json().await.unwrap();

    let direct_data = &direct["data"];
    let tunnel_data = &tunneled["data"];
    let direct_project = direct_data["projectID"].as_str().unwrap().to_owned();
    let tunnel_project = tunnel_data["projectID"].as_str().unwrap().to_owned();
    assert_eq!(direct_project, tunnel_project);
    for (label, session) in [("direct", direct_data), ("tunnel", tunnel_data)] {
        assert!(
            session["id"].as_str().unwrap().starts_with("ses_"),
            "{label} id"
        );
        assert!(
            !session["projectID"].as_str().unwrap().is_empty(),
            "{label} project"
        );
        assert_eq!(session["cost"], 0, "{label} cost");
        assert_eq!(session["tokens"]["input"], 0, "{label} tokens");
    }
    let direct_id = direct_data["id"].as_str().unwrap().to_owned();
    let tunnel_id = tunnel_data["id"].as_str().unwrap().to_owned();
    assert_ne!(direct_id, tunnel_id);

    for (base, password, id, project, label) in [
        (
            upstream.as_str(),
            password.as_str(),
            direct_id.as_str(),
            direct_project.as_str(),
            "direct",
        ),
        (
            tunnel.gateway_url.as_str(),
            tunnel.gateway_password.as_str(),
            tunnel_id.as_str(),
            tunnel_project.as_str(),
            "tunnel",
        ),
    ] {
        let response = client()
            .get(format!("{base}/api/session/{id}"))
            .basic_auth("opencode", Some(password))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{label} get session");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["data"]["id"], id, "{label} session id");
        assert_eq!(body["data"]["projectID"], project, "{label} project");
    }

    // Compare the two sessions structurally after removing per-instance ids,
    // timestamps, and titles.
    let normalize = |mut value: Value| {
        let data = &mut value["data"];
        data["id"] = Value::Null;
        data["title"] = Value::Null;
        data["time"] = Value::Null;
        value
    };
    assert_eq!(normalize(direct), normalize(tunneled));

    for (base, password, id) in [
        (upstream.as_str(), password.as_str(), direct_id.as_str()),
        (
            tunnel.gateway_url.as_str(),
            tunnel.gateway_password.as_str(),
            tunnel_id.as_str(),
        ),
    ] {
        let response = client()
            .delete(format!("{base}/api/session/{id}"))
            .basic_auth("opencode", Some(password))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
        let missing = client()
            .get(format!("{base}/api/session/{id}"))
            .basic_auth("opencode", Some(password))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), 404);
    }

    tunnel.stop();
}

#[tokio::test]
async fn sse_initial_events_match_direct_opencode() {
    let _guard = TEST_LOCK.lock().await;
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").unwrap_or_default();
    let tunnel = Tunnel::start(&upstream, Some(password.clone())).await;

    let direct = client()
        .get(format!("{upstream}/api/event"))
        .basic_auth("opencode", Some(&password))
        .send()
        .await
        .unwrap();
    let tunneled = client()
        .get(format!("{}/api/event", tunnel.gateway_url))
        .basic_auth("opencode", Some(&tunnel.gateway_password))
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), 200);
    assert_eq!(tunneled.status(), 200);
    assert_eq!(
        direct.headers().get("content-type"),
        tunneled.headers().get("content-type")
    );

    let (direct_event, tunnel_event) =
        tokio::join!(first_sse_event(direct), first_sse_event(tunneled));
    assert_eq!(direct_event, "server.connected");
    assert_eq!(tunnel_event, "server.connected");

    tunnel.stop();
}

async fn first_sse_event(response: reqwest::Response) -> String {
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let chunk = tokio::time::timeout(Duration::from_secs(2), stream.next()).await;
        if let Ok(Some(Ok(bytes))) = chunk {
            buffer.extend_from_slice(&bytes);
            if let Some(text) = String::from_utf8_lossy(&buffer)
                .split("\n\n")
                .next()
                .filter(|block| block.contains("data:"))
            {
                for line in text.lines() {
                    if let Some(data) = line.strip_prefix("data:") {
                        let value: Value = serde_json::from_str(data.trim()).unwrap();
                        return value["type"].as_str().unwrap_or_default().to_owned();
                    }
                }
            }
        }
    }
    panic!("no SSE event received");
}

#[tokio::test]
async fn unmodified_opencode_cli_can_use_the_gateway() {
    let _guard = TEST_LOCK.lock().await;
    let Ok(upstream) = std::env::var("OCT_REAL_UPSTREAM") else {
        eprintln!("skipping: OCT_REAL_UPSTREAM is not set");
        return;
    };
    let password = std::env::var("OPENCODE_PASSWORD").unwrap_or_default();
    let tunnel = Tunnel::start(&upstream, Some(password.clone())).await;

    let direct = opencode_api(&upstream, &password).await;
    let tunneled = opencode_api(&tunnel.gateway_url, &tunnel.gateway_password).await;
    assert_eq!(direct, tunneled);

    tunnel.stop();
}

async fn opencode_api(server: &str, password: &str) -> Value {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("opencode")
            .args(["api", "--server", server, "GET", "/api/info"])
            .env("OPENCODE_PASSWORD", password)
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .expect("opencode api timed out")
    .expect("failed to run opencode api");
    assert!(
        output.status.success(),
        "opencode api failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("opencode api output is JSON")
}
