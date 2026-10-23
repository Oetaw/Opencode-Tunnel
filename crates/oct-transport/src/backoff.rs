use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::TransportError;

/// Cancellable, jittered exponential backoff. Equal jitter avoids a
/// thundering herd when a relay restarts and many endpoints reconnect.
#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        let max = max.max(initial);
        Self {
            initial,
            max,
            next: initial,
        }
    }

    pub fn reset(&mut self) {
        self.next = self.initial;
    }

    pub fn next_delay(&mut self) -> Duration {
        let base = self.next;
        let jittered = base + base.mul_f64(rand::random::<f64>() * 0.5);
        self.next = (base * 2).min(self.max);
        jittered.min(self.max)
    }

    pub async fn sleep(&mut self, shutdown: &CancellationToken) -> Result<(), TransportError> {
        let delay = self.next_delay();
        tokio::select! {
            _ = shutdown.cancelled() => Err(TransportError::Cancelled),
            _ = tokio::time::sleep(delay) => Ok(()),
        }
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_reset() {
        let mut backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(50));
        for _ in 0..20 {
            let delay = backoff.next_delay();
            assert!(delay >= Duration::from_millis(10));
            assert!(delay <= Duration::from_millis(50));
        }
        backoff.reset();
        assert!(backoff.next_delay() <= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn cancellation_is_observed() {
        let token = CancellationToken::new();
        token.cancel();
        let mut backoff = Backoff::default();
        assert!(matches!(
            backoff.sleep(&token).await,
            Err(TransportError::Cancelled)
        ));
    }
}
