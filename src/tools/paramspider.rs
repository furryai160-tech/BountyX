use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// URL with parameters discovered by paramspider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamspiderResult {
    pub url: String,
}

/// Adapter for `paramspider` — mine URL parameters from web archives.
///
/// Paramspider fetches all historical URLs for a domain from the Wayback
/// Machine (web.archive.org), Common Crawl, and AlienVault OTX, then
/// extracts all unique query parameters.
///
/// Why is this valuable for bug bounty?
/// - Old endpoints that were removed but still work in backend
/// - Parameters that were never properly sanitized
/// - Hidden API endpoints from old versions
/// - Debug parameters left over from development
///
/// Example output: https://example.com/search?q=FUZZ&filter=FUZZ
///
/// These URLs feed directly into:
/// - dalfox (XSS)
/// - sqlmap (SQLi)
/// - gf patterns (SSRF, LFI, etc.)
#[derive(Clone)]
pub struct ParamspiderAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl ParamspiderAdapter {
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

    /// Parse paramspider output — it outputs URLs with FUZZ placeholders.
    pub fn parse_results(&self, output: &ToolOutput) -> Vec<ParamspiderResult> {
        let results: Vec<ParamspiderResult> = output.raw_lines
            .iter()
            .map(|l| l.trim().to_string())
            .filter(|l| l.starts_with("http") && l.contains('='))
            .map(|url| ParamspiderResult { url })
            .collect();

        info!("paramspider found {} parameterized URL(s) from archives.", results.len());
        results
    }
}

#[async_trait]
impl SecurityTool for ParamspiderAdapter {
    fn name(&self) -> &'static str {
        "paramspider"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("--help");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(!out.stderr.is_empty() || !out.stdout.is_empty()),
            _ => Ok(false),
        }
    }

    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Strip protocol for paramspider
        let domain = input.target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(&input.target);

        let args: Vec<&str> = vec![
            "-d", domain,
            "--quiet",
            "--exclude", "png,jpg,gif,jpeg,svg,ico,css,woff,ttf",
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
