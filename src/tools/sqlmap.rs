use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// Severity mapping for SQLi findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqliSeverity {
    Critical,
    High,
    Medium,
}

impl SqliSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
        }
    }
}

/// A confirmed SQL Injection finding from sqlmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqliFinding {
    /// The vulnerable URL
    pub url: String,
    /// The parameter that was found vulnerable
    pub parameter: String,
    /// The injection type (e.g. "Boolean-based blind", "Error-based", "UNION query")
    pub injection_type: String,
    /// The database backend detected
    pub dbms: String,
    /// Severity classification
    pub severity: String,
    /// Proof/evidence string
    pub payload: String,
}

/// Adapter for `sqlmap` — the most powerful SQL Injection detection tool.
///
/// IMPORTANT: This adapter is configured in **DETECTION ONLY** mode.
/// It NEVER performs:
/// - Data extraction/dumping
/// - OS command execution
/// - File read/write
/// - Privilege escalation
///
/// It ONLY detects whether a parameter is injectable and reports the
/// injection type and database backend for the bug bounty report.
///
/// Safety flags used:
/// - `--level=2`: Moderate test coverage (avoids excessive noise)
/// - `--risk=1`: Lowest risk level (no destructive tests)
/// - `--batch`: Non-interactive, no user prompts
/// - `--no-cast`: Faster, skip output casting
/// - `--technique=BEUST`: All techniques but limited to detection
/// - NO `--dump`, `--dbs`, `--tables`, `--os-shell` or similar
#[derive(Clone)]
pub struct SqlmapAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl SqlmapAdapter {
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

    /// Parse sqlmap output lines for confirmed injection findings.
    ///
    /// sqlmap outputs lines like:
    /// `[INFO] GET parameter 'id' is 'Boolean-based blind' injectable`
    /// `[INFO] the back-end DBMS is MySQL`
    pub fn parse_findings(&self, output: &ToolOutput, target_url: &str) -> Vec<SqliFinding> {
        let mut findings = Vec::new();
        let mut current_param = String::new();
        let mut current_type = String::new();
        let mut current_dbms = String::new();
        let mut current_payload = String::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();

            // Detect injectable parameter confirmation
            if (trimmed.contains("is '") && trimmed.contains("injectable"))
                || trimmed.contains("appears to be")
                || trimmed.contains("might be injectable")
            {
                // Extract parameter name
                if let Some(param) = Self::extract_param(trimmed) {
                    current_param = param;
                }
                // Extract injection type
                if let Some(itype) = Self::extract_between(trimmed, "'", "' injectable") {
                    current_type = itype;
                }
                // Extract payload if present
                if trimmed.contains("Payload:") {
                    if let Some(payload) = trimmed.split("Payload:").nth(1) {
                        current_payload = payload.trim().to_string();
                    }
                }
            }

            // Detect DBMS
            if trimmed.contains("back-end DBMS is") || trimmed.contains("DBMS:") {
                if let Some(db) = trimmed.split("DBMS is ").nth(1).or_else(|| trimmed.split("DBMS: ").nth(1)) {
                    current_dbms = db.trim().trim_end_matches('.').to_string();
                }
            }

            // "sqlmap identified the following injection point" — confirms finding
            if trimmed.contains("sqlmap identified the following injection point")
                || (trimmed.contains("is vulnerable") && !current_param.is_empty())
            {
                if !current_param.is_empty() && !current_type.is_empty() {
                    let severity = if current_type.to_lowercase().contains("union")
                        || current_type.to_lowercase().contains("error")
                    {
                        SqliSeverity::Critical.as_str().to_string()
                    } else {
                        SqliSeverity::High.as_str().to_string()
                    };

                    info!("💉 SQLi CONFIRMED [{}] at '{}' — param: '{}', type: '{}'",
                        severity, target_url, current_param, current_type);

                    findings.push(SqliFinding {
                        url: target_url.to_string(),
                        parameter: current_param.clone(),
                        injection_type: current_type.clone(),
                        dbms: if current_dbms.is_empty() { "Unknown".to_string() } else { current_dbms.clone() },
                        severity,
                        payload: current_payload.clone(),
                    });

                    // Reset for next finding
                    current_param.clear();
                    current_type.clear();
                    current_payload.clear();
                }
            }
        }

        info!("sqlmap detected {} SQL injection point(s) at '{}'", findings.len(), target_url);
        findings
    }

    fn extract_param(line: &str) -> Option<String> {
        // Patterns: "GET parameter 'id'", "POST parameter 'username'", "Cookie parameter 'sess'"
        for prefix in &["GET parameter '", "POST parameter '", "Cookie parameter '", "parameter '"] {
            if let Some(start) = line.find(prefix) {
                let rest = &line[start + prefix.len()..];
                if let Some(end) = rest.find('\'') {
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    }

    fn extract_between(s: &str, start_pat: &str, end_pat: &str) -> Option<String> {
        let start = s.find(start_pat)? + start_pat.len();
        let rest = &s[start..];
        let end = rest.find(end_pat)?;
        Some(rest[..end].to_string())
    }
}

#[async_trait]
impl SecurityTool for SqlmapAdapter {
    fn name(&self) -> &'static str {
        "sqlmap"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("--version");
        match tokio::time::timeout(Duration::from_secs(8), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty()),
            _ => Ok(false),
        }
    }

    /// Run sqlmap in DETECTION-ONLY mode on a target URL.
    ///
    /// Uses the most conservative flags to maximize detection without
    /// any risk of data destruction, extraction, or unauthorized access.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        let args: Vec<&str> = vec![
            "-u", &input.target,
            "--batch",              // Non-interactive
            "--level=2",            // Moderate test depth
            "--risk=1",             // Safest risk level
            "--technique=BEUST",    // All detection techniques
            "--no-cast",            // Faster
            "--random-agent",       // Bypass simple WAF signatures
            "--output-dir=/tmp/sqlmap_bountyscope",
            "--forms",              // Also test form parameters
            "--crawl=1",            // Minimal crawl for linked forms
            "--smart",              // Only test promising parameters
            "--timeout=15",
            "--retries=1",
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
