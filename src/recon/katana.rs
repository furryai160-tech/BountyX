use crate::errors::Result;
use crate::recon::ProcessExecutor;
use crate::validation::{Deduplicator, ScopeGuard};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Deserialize)]
struct KatanaJsonOutput {
    pub request: Option<KatanaRequest>,
}

#[derive(Debug, Deserialize)]
struct KatanaRequest {
    pub endpoint: Option<String>,
}

pub struct KatanaRunner {
    binary_path: String,
    timeout_secs: u64,
}

impl KatanaRunner {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
        }
    }

    pub async fn crawl(
        &self,
        urls: &[String],
        scope_guard: &ScopeGuard,
    ) -> Result<Vec<String>> {
        let authorized_urls = scope_guard.filter_in_scope(urls);
        if authorized_urls.is_empty() {
            return Ok(Vec::new());
        }

        info!(
            "Starting Katana endpoint discovery on {} target URLs",
            authorized_urls.len()
        );

        let input_data = authorized_urls.join("\n");
        let args = [
            "-silent",
            "-jsonl",
            "-depth",
            "2",
            "-crawl-duration",
            "30",
            "-concurrency",
            "5",
        ];
        let timeout = Duration::from_secs(self.timeout_secs);

        let (stdout, stderr) = match ProcessExecutor::execute(&self.binary_path, &args, Some(&input_data), timeout).await {
            Ok(res) => res,
            Err(e) => {
                warn!("Katana execution failed or binary not found ({}): {}", self.binary_path, e);
                return Ok(Vec::new());
            }
        };

        if !stderr.is_empty() {
            debug!("Katana stderr: {}", stderr);
        }

        let mut discovered_urls = Vec::new();
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<KatanaJsonOutput>(line) {
                if let Some(req) = entry.request {
                    if let Some(endpoint) = req.endpoint {
                        if scope_guard.is_in_scope(&endpoint) {
                            discovered_urls.push(endpoint);
                        }
                    }
                }
            } else if line.starts_with("http://") || line.starts_with("https://") {
                if scope_guard.is_in_scope(line) {
                    discovered_urls.push(line.to_string());
                }
            }
        }

        let deduped = Deduplicator::deduplicate_strings(&discovered_urls);
        info!("Katana discovered {} unique verified in-scope URLs", deduped.len());
        Ok(deduped)
    }
}
