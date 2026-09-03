use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct RateLimiter {
    rps: u32,
    last_request: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    pub fn new(rps: u32) -> Self {
        let rps = rps.max(1);
        Self {
            rps,
            last_request: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(1))),
        }
    }

    pub async fn acquire(&self) {
        let interval = Duration::from_micros(1_000_000 / self.rps as u64);
        let mut last = self.last_request.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed < interval {
            let delay = interval - elapsed;
            tokio::time::sleep(delay).await;
            *last = Instant::now();
        } else {
            *last = now;
        }
    }
}
