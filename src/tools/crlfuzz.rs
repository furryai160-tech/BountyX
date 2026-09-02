use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A CRLF injection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlfFinding {
    /// The URL that was vulnerable
    pub url: String,
    /// The payload that confirmed the injection
    pub payload: String,
    /// Severity is always HIGH — CRLF allows header injection, redirect, XSS via response splitting
    pub severity: String,
    /// Human-readable description for the bug report
    pub description: String,
}

/// Adapter for `crlfuzz` — CRLF injection scanner.
///
/// CRLF (Carriage Return Line Feed) injection allows attackers to inject
/// arbitrary HTTP response headers. Impact ranges from:
/// - **Header Injection** → Session fixation, cache poisoning (P3/P4)
/// - **HTTP Response Splitting** → XSS via injected headers (P2/P3)
/// - **Open Redirect** via Location header injection (P3)
/// - **Cookie Injection** → Privilege escalation (P2)
///
/// crlfuzz works by injecting `%0d%0a` sequences and checking whether
/// the injected headers appear in the HTTP response.
#[derive(Clone)]
pub struct CrlfuzzAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl CrlfuzzAdapter {
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

    /// Parse crlfuzz output — it outputs vulnerable URLs directly.
    ///
    /// crlfuzz prints the vulnerable URL with the payload already injected
    /// when a CRLF injection is confirmed:
    /// `[VLN] https://example.com/path?x=%0d%0aHeader:injected`
    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<CrlfFinding> {
        let mut findings = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();

            // crlfuzz prefix for confirmed vulnerability
            if trimmed.contains("[VLN]") || (trimmed.starts_with("http") && trimmed.contains("%0d%0a")) {
                let url = trimmed.trim_start_matches("[VLN] ").trim().to_string();

                if url.is_empty() {
                    continue;
                }

                // Extract the payload from the URL
                let payload = if let Some(pos) = url.find("%0d%0a") {
                    url[pos..].to_string()
                } else {
                    "%0d%0a".to_string()
                };

                info!("🔀 CRLF Injection CONFIRMED: {}", url);

                findings.push(CrlfFinding {
                    url: url.clone(),
                    payload: payload.clone(),
                    severity: "HIGH".to_string(),
                    description: format!(
                        "CRLF Injection confirmed at '{}'. \
                        Payload '{}' was reflected in the HTTP response headers. \
                        Impact: HTTP Response Splitting, Header Injection, potential XSS or Open Redirect. \
                        Recommended fix: Sanitize all user input before using it in HTTP response headers.",
                        url, payload
                    ),
                });
            }
        }

        info!("crlfuzz found {} CRLF injection point(s).", findings.len());
        findings
    }
}

#[async_trait]
impl SecurityTool for CrlfuzzAdapter {
    fn name(&self) -> &'static str {
        "crlfuzz"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-h");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Run CRLF fuzzing against a target URL.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        let args: Vec<&str> = vec![
            "-u", &input.target,
            "-s",       // Silent — no banner
            "-c", "20", // 20 concurrent requests
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
