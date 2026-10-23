use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oct_protocol::relay::{generate_room_credentials, RelayControl, RelayRole, RELAY_PROTOCOL};
use oct_relay::{Relay, RelayConfig};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

async fn connect(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    tokio_tungstenite::connect_async(format!("ws://{addr}/oct/v1"))
        .await
        .expect("websocket connect")
        .0
}

async fn send_control(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    control: RelayControl,
) {
    ws.send(Message::Text(control.encode().unwrap().into()))
        .await
        .unwrap();
}

async fn recv_control(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> RelayControl {
    let message = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("relay response timeout")
        .expect("relay closed")
        .expect("relay websocket error");
    let Message::Text(text) = message else {
        panic!("expected text control message");
    };
    RelayControl::decode(text.as_str()).unwrap()
}

#[tokio::test]
async fn routes_opaque_binary_between_host_and_client() {
    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let addr = relay.local_addr();
    let shutdown = CancellationToken::new();
    let serve_shutdown = shutdown.clone();
    let server = tokio::spawn(async move { relay.serve(serve_shutdown).await });

    let (room, token) = generate_room_credentials();
    let mut host = connect(addr).await;
    let mut client = connect(addr).await;

    send_control(
        &mut host,
        RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: room.clone(),
            role: RelayRole::Host,
            token: token.clone(),
            client_version: Some("test".into()),
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut host).await,
        RelayControl::Ready {
            role: RelayRole::Host,
            ..
        }
    ));

    send_control(
        &mut client,
        RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room,
            role: RelayRole::Client,
            token,
            client_version: Some("test".into()),
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut client).await,
        RelayControl::Ready {
            role: RelayRole::Client,
            ..
        }
    ));
    assert!(matches!(
        recv_control(&mut host).await,
        RelayControl::PeerJoined {
            role: RelayRole::Client
        }
    ));
    assert!(matches!(
        recv_control(&mut client).await,
        RelayControl::PeerJoined {
            role: RelayRole::Host
        }
    ));

    host.send(Message::Binary(vec![0xde, 0xad, 0xbe, 0xef].into()))
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        message,
        Message::Binary(vec![0xde, 0xad, 0xbe, 0xef].into())
    );

    client.close(None).await.unwrap();
    assert!(matches!(
        recv_control(&mut host).await,
        RelayControl::Error { ref code, .. } if code == "PEER_LEFT"
    ));

    shutdown.cancel();
    let _ = server.await;
}

#[tokio::test]
async fn rejects_duplicate_role_and_bad_token() {
    let relay = Relay::bind(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..RelayConfig::default()
    })
    .await
    .unwrap();
    let addr = relay.local_addr();
    let shutdown = CancellationToken::new();
    let serve_shutdown = shutdown.clone();
    let server = tokio::spawn(async move { relay.serve(serve_shutdown).await });

    let (room, token) = generate_room_credentials();
    let mut host = connect(addr).await;
    send_control(
        &mut host,
        RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: room.clone(),
            role: RelayRole::Host,
            token: token.clone(),
            client_version: None,
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut host).await,
        RelayControl::Ready { .. }
    ));

    let mut duplicate = connect(addr).await;
    send_control(
        &mut duplicate,
        RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room: room.clone(),
            role: RelayRole::Host,
            token: token.clone(),
            client_version: None,
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut duplicate).await,
        RelayControl::Error { ref code, .. } if code == "ROLE_OCCUPIED"
    ));

    let mut bad = connect(addr).await;
    send_control(
        &mut bad,
        RelayControl::Hello {
            protocol: RELAY_PROTOCOL,
            room,
            role: RelayRole::Client,
            token: "x".repeat(64),
            client_version: None,
        },
    )
    .await;
    assert!(matches!(
        recv_control(&mut bad).await,
        RelayControl::Error { ref code, .. } if code == "UNAUTHORIZED"
    ));

    shutdown.cancel();
    let _ = server.await;
}
