use crate::errors::Result;
use crate::recon::ProcessExecutor;
use crate::validation::{Deduplicator, ScopeGuard};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub parent_asset: String,
    pub source: String,
}

pub struct SubfinderRunner {
    binary_path: String,
    timeout_secs: u64,
}

impl SubfinderRunner {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
        }
    }

    pub async fn enumerate(
        &self,
        target: &str,
        scope_guard: &ScopeGuard,
    ) -> Result<Vec<SubdomainResult>> {
        // Strict Gate: Must be in-scope before launching tool
        let normalized_target = scope_guard.validate_target(target)?;

        info!(
            "Starting Subfinder enumeration on authorized target: '{}'",
            normalized_target
        );

        let args = ["-d", &normalized_target, "-silent", "-all"];
        let timeout = Duration::from_secs(self.timeout_secs);

        let (stdout, stderr) = match ProcessExecutor::execute(&self.binary_path, &args, None, timeout).await {
            Ok(res) => res,
            Err(e) => {
                warn!("Subfinder execution failed or binary not found ({}): {}", self.binary_path, e);
                // Return empty list on tool failure without crashing entire pipeline
                return Ok(Vec::new());
            }
        };

        if !stderr.is_empty() {
            tracing::debug!("Subfinder stderr: {}", stderr);
        }

        let raw_lines: Vec<String> = stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        // 1. Deduplicate
        let deduped = Deduplicator::deduplicate_strings(&raw_lines);

        // 2. Strict Scope Gate: Re-verify all discovered subdomains
        let in_scope_subdomains = scope_guard.filter_in_scope(&deduped);

        let results: Vec<SubdomainResult> = in_scope_subdomains
            .into_iter()
            .map(|sub| SubdomainResult {
                subdomain: sub,
                parent_asset: normalized_target.clone(),
                source: "subfinder".to_string(),
            })
            .collect();

        info!(
            "Subfinder discovered {} verified in-scope subdomains for '{}'",
            results.len(),
            normalized_target
        );

        Ok(results)
    }
}
