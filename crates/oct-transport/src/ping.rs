use std::time::Duration;

use bytes::Bytes;
use tokio_util::sync::CancellationToken;

use crate::{TransportError, WsConnection};

/// Send one websocket-level ping. The peer's websocket stack answers with a
/// pong automatically; this is distinct from the end-to-end OCT PING frame.
pub async fn send_ws_ping(conn: &WsConnection, payload: Bytes) -> Result<(), TransportError> {
    conn.send_ping(payload).await
}

/// Periodically ping the carrier until shutdown. The task exits on shutdown or
/// when the connection closes.
pub async fn run_periodic_ping(
    conn: WsConnection,
    interval: Duration,
    shutdown: CancellationToken,
) {
    if interval.is_zero() {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                if conn.is_closed() {
                    return;
                }
                if send_ws_ping(&conn, Bytes::from_static(b"oct")).await.is_err() {
                    return;
                }
            }
        }
    }
}
