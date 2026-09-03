use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct KillSwitch {
    is_active: Arc<AtomicBool>,
    token: CancellationToken,
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            is_active: Arc::new(AtomicBool::new(false)),
            token: CancellationToken::new(),
        }
    }

    pub fn trigger(&self) {
        self.is_active.store(true, Ordering::SeqCst);
        self.token.cancel();
    }

    pub fn is_triggered(&self) -> bool {
        self.is_active.load(Ordering::SeqCst) || self.token.is_cancelled()
    }

    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}
