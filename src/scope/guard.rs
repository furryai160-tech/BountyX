use crate::scope::policy::ScopePolicy;
use crate::scope::validator::{ScopeValidator, ScopeViolation};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{error, warn};

#[derive(Clone)]
pub struct ScopeGuard {
    policy: Arc<ScopePolicy>,
    request_counter: Arc<AtomicUsize>,
}

impl ScopeGuard {
    pub fn new(policy: ScopePolicy) -> Self {
        Self {
            policy: Arc::new(policy),
            request_counter: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn policy(&self) -> &ScopePolicy {
        &self.policy
    }

    pub fn total_requests_executed(&self) -> usize {
        self.request_counter.load(Ordering::SeqCst)
    }

    pub fn remaining_budget(&self) -> usize {
        let current = self.total_requests_executed();
        if current >= self.policy.max_requests {
            0
        } else {
            self.policy.max_requests - current
        }
    }

    /// Primary safety checkpoint for all outgoing network probes
    pub fn validate_and_record_request(&self, url: &str, method: &str) -> Result<(), ScopeViolation> {
        // 1. Check global budget
        let current = self.request_counter.load(Ordering::SeqCst);
        if current >= self.policy.max_requests {
            warn!(
                "🛑 ScopeGuard BLOCKED request to '{}': Budget cap reached ({}/{})",
                url, current, self.policy.max_requests
            );
            return Err(ScopeViolation::BudgetExceeded {
                current,
                max: self.policy.max_requests,
            });
        }

        // 2. Validate URL against Policy rules
        if let Err(violation) = ScopeValidator::validate_url(url, method, &self.policy) {
            warn!("🛑 ScopeGuard BLOCKED violation on '{}': {}", url, violation);
            return Err(violation);
        }

        // 3. Atomically increment budget counter upon approved validation
        self.request_counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Fast non-mutating check for passive inspection
    pub fn is_target_allowed(&self, target: &str) -> bool {
        ScopeValidator::is_host_allowed(target, &self.policy)
    }
}
