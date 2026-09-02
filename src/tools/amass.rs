use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A subdomain discovered or enriched by amass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmassResult {
    pub subdomain: String,
    pub source: String,
    pub ip: Option<String>,
}

/// Adapter for `amass` — OWASP's most comprehensive subdomain enumeration tool.
///
/// Amass uses 50+ data sources including:
/// - Certificate Transparency (crt.sh, Censys)
/// - DNS bruteforce with smart wordlists
/// - Scraping (VirusTotal, Shodan, SecurityTrails)
/// - Web archive mining
/// - Google, Bing, Yahoo dorking
///
/// It's significantly more comprehensive than subfinder alone.
/// Used as a complementary stage to subfinder for maximum coverage.
///
/// Run mode: passive (no active DNS bruteforce to stay stealthy)
#[derive(Clone)]
pub struct AmassAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl AmassAdapter {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
            repository: None,
        }
    }

    pub fn with_repository(mut self, repo: Repository) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn parse_results(&self, output: &ToolOutput, parent: &str) -> Vec<AmassResult> {
        let mut results = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('[') {
                continue;
            }

            // amass outputs: subdomain.example.com
            // or with -json: {"name":"sub.example.com","addresses":[{"ip":"1.2.3.4"}]}
            if trimmed.starts_with('{') {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    let subdomain = val.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let ip = val.get("addresses")
                        .and_then(|a| a.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|obj| obj.get("ip"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let source = val.get("sources")
                        .and_then(|s| s.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .unwrap_or("amass")
                        .to_string();

                    if !subdomain.is_empty() && subdomain.contains(parent) {
                        info!("🌍 amass: {} ({:?})", subdomain, ip);
                        results.push(AmassResult { subdomain, source, ip });
                    }
                }
            } else if trimmed.contains('.') && trimmed.contains(parent) {
                results.push(AmassResult {
                    subdomain: trimmed.to_string(),
                    source: "amass".to_string(),
                    ip: None,
                });
            }
        }

        info!("amass found {} subdomain(s) for '{}'.", results.len(), parent);
        results
    }
}

#[async_trait]
impl SecurityTool for AmassAdapter {
    fn name(&self) -> &'static str {
        "amass"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Strip protocol/path — amass needs the domain only
        let domain = input.target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(&input.target);

        let args: Vec<&str> = vec![
            "enum",
            "-passive",         // Passive mode — stealthy, no DNS bruteforce
            "-nocolor",
            "-json",
            "-d", domain,
        ];

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            None,
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
