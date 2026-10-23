use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use oct_protocol::relay::{token_matches, RelayRole};
use tokio::sync::{mpsc, Mutex};

use crate::RelayError;

pub const OUTBOUND_QUEUE: usize = 64;

pub type ConnectionId = u64;

/// Messages sent from the routing layer to one connection writer.
#[derive(Debug)]
pub enum Outbound {
    Text(String),
    Binary(Bytes),
    Close,
}

#[derive(Debug, Clone)]
pub struct PeerSlot {
    pub conn_id: ConnectionId,
    pub tx: mpsc::Sender<Outbound>,
}

#[derive(Debug, Default)]
struct Room {
    token: String,
    host: Option<PeerSlot>,
    client: Option<PeerSlot>,
    idle_since: Option<Instant>,
}

impl Room {
    fn slot(&self, role: RelayRole) -> Option<&PeerSlot> {
        match role {
            RelayRole::Host => self.host.as_ref(),
            RelayRole::Client => self.client.as_ref(),
        }
    }

    fn slot_mut(&mut self, role: RelayRole) -> &mut Option<PeerSlot> {
        match role {
            RelayRole::Host => &mut self.host,
            RelayRole::Client => &mut self.client,
        }
    }

    fn peer_slot(&self, role: RelayRole) -> Option<&PeerSlot> {
        match role {
            RelayRole::Host => self.client.as_ref(),
            RelayRole::Client => self.host.as_ref(),
        }
    }

    fn is_empty(&self) -> bool {
        self.host.is_none() && self.client.is_none()
    }

    fn is_full(&self) -> bool {
        self.host.is_some() && self.client.is_some()
    }
}

pub struct JoinResult {
    /// The joining connection must send `Ready` before reading this queue.
    pub peer_joined: Option<RelayRole>,
    /// Present when the room is now paired.
    pub peer_tx: Option<mpsc::Sender<Outbound>>,
}

/// In-memory room registry. The relay deliberately keeps only routing state:
/// a room id, a token pinned on first use, role slots, and one idle timestamp.
pub struct Rooms {
    inner: Mutex<HashMap<String, Room>>,
    pub(crate) max_connections_per_room: usize,
    pub(crate) idle_timeout: Duration,
}

impl Rooms {
    pub fn new(max_connections_per_room: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_connections_per_room,
            idle_timeout,
        }
    }

    /// Join a room. Returns the peer role if a peer is now present and the
    /// peer's outbound sender for bidirectional forwarding.
    pub async fn join(
        &self,
        room_id: &str,
        role: RelayRole,
        token: &str,
        conn_id: ConnectionId,
        tx: mpsc::Sender<Outbound>,
    ) -> Result<JoinResult, RelayError> {
        let mut rooms = self.inner.lock().await;
        let room = rooms.entry(room_id.to_owned()).or_default();

        if room.token.is_empty() {
            room.token = token.to_owned();
        } else if !token_matches(&room.token, token) {
            return Err(RelayError::InvalidToken);
        }

        if room.slot(role).is_some() {
            return Err(RelayError::RoleOccupied);
        }
        if room.is_full() {
            return Err(RelayError::RoomFull);
        }
        if room.host.is_some() as usize + room.client.is_some() as usize
            >= self.max_connections_per_room
        {
            return Err(RelayError::RoomFull);
        }

        *room.slot_mut(role) = Some(PeerSlot { conn_id, tx });
        room.idle_since = None;

        if let Some(peer) = room.peer_slot(role) {
            let peer_role = match role {
                RelayRole::Host => RelayRole::Client,
                RelayRole::Client => RelayRole::Host,
            };
            let peer_message = oct_protocol::relay::RelayControl::PeerJoined { role };
            let text = peer_message
                .encode()
                .map_err(|e| RelayError::Internal(e.to_string()))?;
            // Enqueue under the registry lock so PeerJoined cannot be
            // overtaken by a forwarded binary frame.
            if peer.tx.try_send(Outbound::Text(text)).is_err() {
                room.host = None;
                room.client = None;
                return Err(RelayError::PeerOffline);
            }
            Ok(JoinResult {
                peer_joined: Some(peer_role),
                peer_tx: Some(peer.tx.clone()),
            })
        } else {
            Ok(JoinResult {
                peer_joined: None,
                peer_tx: None,
            })
        }
    }

    /// Return the peer's outbound sender for opaque binary forwarding.
    pub async fn peer_tx(&self, room_id: &str, role: RelayRole) -> Option<mpsc::Sender<Outbound>> {
        let rooms = self.inner.lock().await;
        rooms.get(room_id)?.peer_slot(role).map(|p| p.tx.clone())
    }

    /// Remove a connection. Returns the surviving peer, if any, so the caller
    /// can notify it that the tunnel peer left.
    pub async fn leave(
        &self,
        room_id: &str,
        role: RelayRole,
        conn_id: ConnectionId,
    ) -> Option<PeerSlot> {
        let mut rooms = self.inner.lock().await;
        let room = rooms.get_mut(room_id)?;
        let was_ours = room
            .slot(role)
            .map(|s| s.conn_id == conn_id)
            .unwrap_or(false);
        if !was_ours {
            return None;
        }
        *room.slot_mut(role) = None;
        let survivor = match role {
            RelayRole::Host => room.client.clone(),
            RelayRole::Client => room.host.clone(),
        };
        if room.is_empty() {
            rooms.remove(room_id);
        } else {
            room.idle_since = Some(Instant::now());
        }
        survivor
    }

    /// Mark rooms whose sole peer has been waiting too long for eviction.
    /// Returns the senders to close. Paired rooms are never evicted.
    pub async fn evict_idle(&self, now: Instant) -> Vec<mpsc::Sender<Outbound>> {
        let mut rooms = self.inner.lock().await;
        let mut evicted = Vec::new();
        let mut remove = Vec::new();
        for (room_id, room) in rooms.iter_mut() {
            if room.is_full() {
                continue;
            }
            let idle_since = match room.idle_since {
                Some(t) => t,
                None => {
                    room.idle_since = Some(now);
                    continue;
                }
            };
            if now.duration_since(idle_since) >= self.idle_timeout {
                if let Some(slot) = room.host.as_ref().or(room.client.as_ref()) {
                    evicted.push(slot.tx.clone());
                }
                remove.push(room_id.clone());
            }
        }
        for room_id in remove {
            rooms.remove(&room_id);
        }
        evicted
    }

    pub async fn room_count(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// A snapshot for tests and health output. Contains no tokens.
    pub async fn occupied_roles(&self, room_id: &str) -> Option<(bool, bool)> {
        let rooms = self.inner.lock().await;
        let room = rooms.get(room_id)?;
        Some((room.host.is_some(), room.client.is_some()))
    }
}

/// Arc alias used by the server state.
pub type SharedRooms = Arc<Rooms>;
