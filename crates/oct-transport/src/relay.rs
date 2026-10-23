use std::time::Duration;

use oct_protocol::relay::RelayControl;

use crate::{TransportError, WsConnection, WsMessage};

/// Send the relay hello and wait for `Ready`. Any `PeerJoined` that arrives
/// immediately after `Ready` stays queued for [`wait_for_peer`].
pub async fn register(
    conn: &WsConnection,
    hello: RelayControl,
    timeout: Duration,
) -> Result<RelayControl, TransportError> {
    if !matches!(hello, RelayControl::Hello { .. }) {
        return Err(TransportError::Internal(
            "register requires RelayControl::Hello".into(),
        ));
    }
    hello.validate_hello()?;
    let (expected_room, expected_role) = match &hello {
        RelayControl::Hello { room, role, .. } => (room.clone(), *role),
        _ => unreachable!("hello variant checked above"),
    };
    let text = hello.encode()?;
    conn.send_text(text).await?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Timeout("relay ready"));
        }
        let message = tokio::time::timeout(remaining, conn.recv())
            .await
            .map_err(|_| TransportError::Timeout("relay ready"))??;
        let Some(message) = message else {
            return Err(TransportError::Closed);
        };
        let WsMessage::Text(text) = message else {
            // Binary frames before Ready are a protocol violation.
            return Err(TransportError::Internal(
                "relay sent binary before ready".into(),
            ));
        };
        let control = RelayControl::decode(&text)?;
        match control {
            ready @ RelayControl::Ready { .. } => {
                ready.validate_ready(&expected_room, expected_role)?;
                conn.set_relay_role(expected_role).await;
                return Ok(ready);
            }
            RelayControl::Error { code, message } => {
                return Err(TransportError::RelayRejected { code, message })
            }
            RelayControl::PeerLeft { .. } => return Err(TransportError::PeerLeft),
            RelayControl::Ping => {
                let _ = conn.send_text(RelayControl::Pong.encode()?).await;
            }
            RelayControl::Pong | RelayControl::PeerJoined { .. } => {
                // PeerJoined before Ready is ignored; the relay should not do
                // this, but it is not attacker-controlled state.
            }
            RelayControl::Hello { .. } => {
                return Err(TransportError::Internal("relay echoed a hello".into()));
            }
            RelayControl::Evict { .. } => {
                return Err(TransportError::Internal(
                    "relay sent an evict control before ready".into(),
                ));
            }
        }
    }
}

/// Wait until the relay reports that the opposite role has joined.
pub async fn wait_for_peer(conn: &WsConnection, timeout: Duration) -> Result<(), TransportError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(TransportError::Timeout("relay peer"));
        }
        let message = tokio::time::timeout(remaining, conn.recv())
            .await
            .map_err(|_| TransportError::Timeout("relay peer"))??;
        let Some(message) = message else {
            return Err(TransportError::Closed);
        };
        let WsMessage::Text(text) = message else {
            // Binary is only legal after both peers and HELLO are ready.
            return Err(TransportError::Internal(
                "relay sent binary before peer joined".into(),
            ));
        };
        match RelayControl::decode(&text)? {
            RelayControl::PeerJoined { role } => {
                if let Some(own) = conn.relay_role().await {
                    if role != own.peer() {
                        return Err(TransportError::Internal(
                            "relay announced an unexpected peer role".into(),
                        ));
                    }
                }
                return Ok(());
            }
            RelayControl::Error { code, message } => {
                return Err(TransportError::RelayRejected { code, message })
            }
            RelayControl::PeerLeft { .. } => return Err(TransportError::PeerLeft),
            RelayControl::Ping => {
                let _ = conn.send_text(RelayControl::Pong.encode()?).await;
            }
            RelayControl::Pong | RelayControl::Ready { .. } => {}
            RelayControl::Hello { .. } => {
                return Err(TransportError::Internal("relay echoed a hello".into()));
            }
            RelayControl::Evict { .. } => {
                return Err(TransportError::Internal(
                    "relay sent an evict control to an endpoint".into(),
                ));
            }
        }
    }
}
