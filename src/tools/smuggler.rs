use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// HTTP Request Smuggling vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmugglerFinding {
    /// Target URL
    pub url: String,
    /// Smuggling technique that worked (CL.TE, TE.CL, TE.TE)
    pub technique: String,
    /// Severity is always CRITICAL — desync attacks have massive impact
    pub severity: String,
    /// Detailed description for bug report
    pub description: String,
}

/// Adapter for `smuggler` — HTTP Request Smuggling detector.
///
/// HTTP Request Smuggling (HRS) is one of the most impactful vulnerabilities
/// in modern web security. It exploits disagreement between front-end proxies
/// (Nginx, CloudFlare, HAProxy) and back-end servers about HTTP/1.1 boundaries.
///
/// Impact (almost always P1 - Critical):
/// - **Session Hijacking**: Steal other users' requests/cookies
/// - **Cache Poisoning**: Poison CDN cache with malicious responses
/// - **Request Queue Desyncing**: Forward-smuggle requests to restricted endpoints
/// - **Bypass Security Controls**: Skip WAF, authentication, rate limiting
///
/// Techniques detected:
/// - **CL.TE**: Front-end uses Content-Length, back-end uses Transfer-Encoding
/// - **TE.CL**: Front-end uses Transfer-Encoding, back-end uses Content-Length
/// - **TE.TE**: Both use Transfer-Encoding but one can be confused
///
/// bounty range: $3,000 — $50,000+ (P1 at most programs)
#[derive(Clone)]
pub struct SmugglerAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl SmugglerAdapter {
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

    /// Parse smuggler output for confirmed vulnerabilities.
    ///
    /// smuggler outputs lines like:
    /// `[*] Possible CLTE Issue Found on: https://example.com/`
    /// `[*] Possible TECL Issue Found on: https://example.com/`
    pub fn parse_findings(&self, output: &ToolOutput, target: &str) -> Vec<SmugglerFinding> {
        let mut findings = Vec::new();

        for line in &output.raw_lines {
            let lower = line.to_lowercase();

            if lower.contains("issue found") || lower.contains("vulnerable") ||
               lower.contains("possible clte") || lower.contains("possible tecl") ||
               lower.contains("possible tete") {

                let technique = if lower.contains("clte") || lower.contains("cl.te") {
                    "CL.TE"
                } else if lower.contains("tecl") || lower.contains("te.cl") {
                    "TE.CL"
                } else if lower.contains("tete") || lower.contains("te.te") {
                    "TE.TE"
                } else {
                    "HTTP Request Smuggling"
                };

                info!("🚨💀 HTTP REQUEST SMUGGLING [{}] at '{}'", technique, target);

                findings.push(SmugglerFinding {
                    url: target.to_string(),
                    technique: technique.to_string(),
                    severity: "CRITICAL".to_string(),
                    description: format!(
                        "HTTP Request Smuggling ({}) confirmed at '{}'. \
                        Front-end and back-end servers disagree on HTTP message boundaries. \
                        Impact: Session hijacking, cache poisoning, WAF bypass, \
                        request queue desynchronization. \
                        Immediate remediation required: Normalize all HTTP parsing \
                        and disable Transfer-Encoding on front-end proxies.",
                        technique, target
                    ),
                });
            }
        }

        info!("smuggler found {} request smuggling issue(s).", findings.len());
        findings
    }
}

#[async_trait]
impl SecurityTool for SmugglerAdapter {
    fn name(&self) -> &'static str {
        "smuggler"
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

    /// Run smuggler against a target URL.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        let args: Vec<&str> = vec![
            "-u", &input.target,
            "-q",           // Quiet mode
            "--no-color",
            "-t", "clte",   // Test CL.TE (most common)
            "-t", "tecl",   // Test TE.CL
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
