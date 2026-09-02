use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::warn;

/// A single XSS finding discovered by dalfox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssFinding {
    /// The full URL where the XSS was confirmed
    pub url: String,
    /// The injected payload that triggered the sink
    pub payload: String,
    /// The parameter name that was vulnerable
    pub param: Option<String>,
    /// Dalfox-assigned severity or type (e.g. "R", "G", "V")
    pub vuln_type: String,
    /// Severity classification mapped from type
    pub severity: String,
    /// Raw output line from dalfox
    pub raw: String,
}

/// Adapter wrapping the `dalfox` XSS scanner.
///
/// Dalfox is one of the best open-source XSS scanners. It does parameter
/// detection, blind XSS injection, DOM-based analysis, and has a fast
/// scanning engine. This adapter integrates it into the BountyScope pipeline.
#[derive(Clone)]
pub struct DalfoxAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl DalfoxAdapter {
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

    /// Parse dalfox output lines into XssFinding structs.
    ///
    /// Dalfox output formats:
    ///   [V] Verified XSS    URL | PARAM | PAYLOAD
    ///   [R] Reflected       URL
    ///   [G] Grep / pattern  URL
    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<XssFinding> {
        let mut findings = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();

            // Detect dalfox prefixed result lines
            let (vuln_type, severity) = if trimmed.starts_with("[V]") {
                ("V", "HIGH")
            } else if trimmed.starts_with("[R]") {
                ("R", "MEDIUM")
            } else if trimmed.starts_with("[G]") {
                ("G", "LOW")
            } else {
                continue;
            };

            // Try to extract URL and param/payload
            // Format example: [V] Verified XSS [param=q] https://example.com/search?q=...
            let url = trimmed
                .split_whitespace()
                .find(|p| p.starts_with("http://") || p.starts_with("https://"))
                .unwrap_or("")
                .to_string();

            if url.is_empty() {
                continue;
            }

            // Extract param from brackets like [param=q]
            let param = trimmed
                .split('[')
                .find(|s| s.contains("param=") || s.contains("=") && s.contains(']'))
                .and_then(|s| s.split(']').next())
                .and_then(|s| s.split('=').nth(1).or_else(|| s.split('=').next()))
                .map(|s| s.trim().to_string());

            // Use the URL's query string parameters as payload evidence
            let payload = url
                .split('?')
                .nth(1)
                .unwrap_or("N/A")
                .to_string();

            findings.push(XssFinding {
                url,
                payload,
                param,
                vuln_type: vuln_type.to_string(),
                severity: severity.to_string(),
                raw: trimmed.to_string(),
            });
        }

        findings
    }
}

#[async_trait]
impl SecurityTool for DalfoxAdapter {
    fn name(&self) -> &'static str {
        "dalfox"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Run dalfox XSS scan.
    ///
    /// Dalfox accepts URLs via stdin (pipe mode) or directly as arguments.
    /// We use `pipe` mode: `dalfox pipe` reads URLs from stdin line by line
    /// and runs XSS probing concurrently on all of them.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // dalfox pipe mode: reads URLs from stdin
        let args: Vec<&str> = vec![
            "pipe",
            "--silence",          // suppress banner/progress
            "--no-color",         // clean output for parsing
            "--only-poc",         // only output confirmed/reflected findings
            "--skip-mining-dom",  // skip slow DOM analysis for speed
            "--timeout",
            "10",
            "--worker",
            "20",
            "--delay",
            "0",
        ];

        let stdin_content = input.targets.join("\n");

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            Some(&stdin_content),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
