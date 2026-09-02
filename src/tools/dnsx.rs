use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A subdomain discovered by dnsx DNS bruteforce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsxRecord {
    /// The discovered subdomain
    pub host: String,
    /// The resolved IP address(es)
    pub ips: Vec<String>,
    /// Record type (A, AAAA, CNAME, MX, TXT)
    pub record_type: String,
}

/// Adapter for `dnsx` — a fast and multi-purpose DNS toolkit.
///
/// Used for two key purposes in bug bounty:
/// 1. **DNS Bruteforce**: Combined with a wordlist to discover hidden subdomains
///    that passive recon tools miss (internal apps, staging servers, dev environments).
/// 2. **DNS Resolution**: Validates and resolves a list of subdomains from subfinder
///    to weed out dead/unresolvable domains before scanning.
///
/// Hidden subdomains found via DNS bruteforce are often:
/// - Old dev/staging servers with weaker security
/// - Internal tools accidentally exposed to the internet
/// - Services not covered by bug bounty scope's CDN/WAF
#[derive(Clone)]
pub struct DnsxAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl DnsxAdapter {
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

    /// Parse dnsx JSON output into DnsxRecord structs.
    ///
    /// dnsx JSON format:
    /// {"host":"api.example.com","a":["1.2.3.4"],"status_code":"NOERROR"}
    pub fn parse_records(&self, output: &ToolOutput) -> Vec<DnsxRecord> {
        let mut records = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let host = val.get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if host.is_empty() {
                    continue;
                }

                // Extract IPs — try 'a', 'aaaa', 'cname'
                let mut ips = Vec::new();
                let mut record_type = "A".to_string();

                if let Some(a_records) = val.get("a").and_then(|v| v.as_array()) {
                    for r in a_records {
                        if let Some(ip) = r.as_str() {
                            ips.push(ip.to_string());
                        }
                    }
                    record_type = "A".to_string();
                } else if let Some(cname) = val.get("cname").and_then(|v| v.as_array()) {
                    for r in cname {
                        if let Some(c) = r.as_str() {
                            ips.push(c.to_string());
                        }
                    }
                    record_type = "CNAME".to_string();
                }

                info!("🌐 DNS resolved: {} → {:?} ({})", host, ips, record_type);

                records.push(DnsxRecord {
                    host,
                    ips,
                    record_type,
                });
            }
        }

        info!("dnsx resolved {} DNS record(s).", records.len());
        records
    }
}

#[async_trait]
impl SecurityTool for DnsxAdapter {
    fn name(&self) -> &'static str {
        "dnsx"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Resolve/validate a list of subdomains from stdin.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        let args: Vec<&str> = vec![
            "-json",
            "-silent",
            "-a",           // Query A records
            "-cname",       // Query CNAME records
            "-resp",        // Include response
            "-r", "8.8.8.8,1.1.1.1", // Use reliable public resolvers
            "-t", "50",     // 50 concurrent threads
            "-retry", "2",
        ];

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            Some(&input.target), // pipe subdomains via stdin
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
