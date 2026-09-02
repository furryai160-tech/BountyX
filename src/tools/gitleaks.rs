use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A secret found by gitleaks in a git repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitleaksFinding {
    /// Type of secret (AWS Key, GitHub Token, etc.)
    pub rule_id: String,
    /// The matched secret value (partially redacted)
    pub secret: String,
    /// The file where the secret was found
    pub file: String,
    /// The commit SHA
    pub commit: String,
    /// Severity
    pub severity: String,
    /// Human-readable description
    pub description: String,
}

/// Adapter for `gitleaks` — detect secrets in git repositories.
///
/// Gitleaks scans git history for accidentally committed secrets:
/// - AWS Access Keys / Secret Keys → P1 ($$$)
/// - GitHub Personal Access Tokens → P1
/// - Stripe/Twilio/SendGrid API Keys → P1-P2
/// - Database credentials in config files → P1
/// - Private SSH/TLS keys → P1
/// - Slack Webhooks, Discord tokens → P2-P3
/// - Generic API keys and passwords → P2-P3
///
/// This is a goldmine for bug bounty because developers often commit
/// secrets accidentally and then "delete" them (but git history remains).
#[derive(Clone)]
pub struct GitleaksAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl GitleaksAdapter {
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

    /// Parse gitleaks JSON output.
    ///
    /// gitleaks --report-format json outputs an array of findings.
    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<GitleaksFinding> {
        let mut findings = Vec::new();

        // gitleaks outputs a JSON array
        let full_output = output.raw_lines.join("\n");
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&full_output) {
            for item in arr {
                let rule_id = item.get("RuleID")
                    .or_else(|| item.get("ruleID"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown-secret")
                    .to_string();

                let secret = item.get("Secret")
                    .or_else(|| item.get("secret"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let file = item.get("File")
                    .or_else(|| item.get("file"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let commit = item.get("Commit")
                    .or_else(|| item.get("commit"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                if secret.is_empty() && rule_id == "unknown-secret" {
                    continue;
                }

                // Classify severity by rule type
                let severity = Self::classify_severity(&rule_id);
                let redacted = Self::redact_secret(&secret);

                info!("🔑 gitleaks: {} [{}] in '{}' @ commit '{}'",
                    rule_id, severity, file, &commit[..commit.len().min(8)]);

                findings.push(GitleaksFinding {
                    rule_id: rule_id.clone(),
                    secret: redacted.clone(),
                    file: file.clone(),
                    commit: commit[..commit.len().min(8)].to_string(),
                    severity: severity.clone(),
                    description: format!(
                        "Secret type '{}' found in file '{}' (commit: {}). \
                        Value: '{}'. Immediate revocation required.",
                        rule_id, file, &commit[..commit.len().min(8)], redacted
                    ),
                });
            }
        }

        info!("gitleaks found {} secret(s).", findings.len());
        findings
    }

    fn classify_severity(rule_id: &str) -> String {
        let lower = rule_id.to_lowercase();
        if lower.contains("aws") || lower.contains("private-key") ||
           lower.contains("github-token") || lower.contains("gcp") {
            "CRITICAL".to_string()
        } else if lower.contains("stripe") || lower.contains("twilio") ||
                  lower.contains("sendgrid") || lower.contains("database") {
            "HIGH".to_string()
        } else {
            "MEDIUM".to_string()
        }
    }

    fn redact_secret(secret: &str) -> String {
        if secret.len() <= 8 {
            return secret.to_string();
        }
        let visible = &secret[..4];
        let end = &secret[secret.len()-4..];
        format!("{}...{}", visible, end)
    }
}

#[async_trait]
impl SecurityTool for GitleaksAdapter {
    fn name(&self) -> &'static str {
        "gitleaks"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty()),
            _ => Ok(false),
        }
    }

    /// Scan a git repo URL or local path for secrets.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Determine if target is a remote URL or local path
        let (subcommand, location_arg) = if input.target.starts_with("http") {
            ("detect", input.target.as_str())
        } else {
            ("detect", input.target.as_str())
        };

        let args: Vec<&str> = vec![
            subcommand,
            "--source", location_arg,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-banner",
            "--redact",     // Partially redact found secrets in output
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
