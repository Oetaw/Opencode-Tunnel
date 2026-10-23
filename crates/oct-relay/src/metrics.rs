use std::sync::atomic::{AtomicU64, Ordering};

/// Metadata-only relay counters. Never includes room ids, tokens, paths or
/// payload bytes.
#[derive(Debug, Default)]
pub struct Metrics {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub joins_total: AtomicU64,
    pub rejects_total: AtomicU64,
    pub bytes_forwarded_total: AtomicU64,
    pub frames_forwarded_total: AtomicU64,
    pub peer_left_total: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub joins_total: u64,
    pub rejects_total: u64,
    pub bytes_forwarded_total: u64,
    pub frames_forwarded_total: u64,
    pub peer_left_total: u64,
}

impl Metrics {
    pub fn connection_opened(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn join(&self) {
        self.joins_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reject(&self) {
        self.rejects_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn forwarded(&self, bytes: usize) {
        self.frames_forwarded_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded_total
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn peer_left(&self) {
        self.peer_left_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            connections_active: self.connections_active.load(Ordering::Relaxed),
            joins_total: self.joins_total.load(Ordering::Relaxed),
            rejects_total: self.rejects_total.load(Ordering::Relaxed),
            bytes_forwarded_total: self.bytes_forwarded_total.load(Ordering::Relaxed),
            frames_forwarded_total: self.frames_forwarded_total.load(Ordering::Relaxed),
            peer_left_total: self.peer_left_total.load(Ordering::Relaxed),
        }
    }
}
