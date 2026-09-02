use crate::errors::Result;
use crate::recon::ProcessExecutor;
use crate::validation::{Deduplicator, ScopeGuard};
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct GauRunner {
    binary_path: String,
    timeout_secs: u64,
}

impl GauRunner {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
        }
    }

    pub async fn fetch_urls(
        &self,
        domain: &str,
        scope_guard: &ScopeGuard,
    ) -> Result<Vec<String>> {
        let normalized = scope_guard.validate_target(domain)?;

        info!("Fetching historical URLs with GAU for domain: '{}'", normalized);

        let args = ["--threads", "5", "--subs", &normalized];
        let timeout = Duration::from_secs(self.timeout_secs);

        let (stdout, stderr) = match ProcessExecutor::execute(&self.binary_path, &args, None, timeout).await {
            Ok(res) => res,
            Err(e) => {
                warn!("GAU execution failed or binary not found ({}): {}", self.binary_path, e);
                return Ok(Vec::new());
            }
        };

        if !stderr.is_empty() {
            debug!("GAU stderr: {}", stderr);
        }

        let raw_lines: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        let deduped = Deduplicator::deduplicate_strings(&raw_lines);
        let in_scope_urls = scope_guard.filter_in_scope(&deduped);

        info!("GAU retrieved {} in-scope historical URLs", in_scope_urls.len());
        Ok(in_scope_urls)
    }
}
