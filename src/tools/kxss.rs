use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A confirmed reflected XSS candidate found by kxss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KxssFinding {
    /// The full URL with the reflection point
    pub url: String,
    /// The parameter that reflects unfiltered
    pub param: String,
    /// Characters that passed through unfiltered (e.g. "<>\"'")
    pub reflected_chars: String,
    /// Severity — MEDIUM for reflection, HIGH if angle brackets pass
    pub severity: String,
}

/// Adapter for `kxss` — ultra-fast reflected XSS finder by @tomnomnom.
///
/// kxss is used as the FIRST XSS stage before dalfox:
/// 1. kxss quickly tests ALL URLs for character reflection (< > " ' etc.)
/// 2. Only URLs where dangerous chars reflect get passed to dalfox
/// 3. This makes the pipeline 10x faster by avoiding wasted dalfox runs
///
/// kxss reads URLs from stdin and outputs ones with reflections.
///
/// Pipeline flow:
///   all URLs → kxss (fast filter) → reflected URLs → dalfox (confirm + PoC)
#[derive(Clone)]
pub struct KxssAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl KxssAdapter {
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

    /// Parse kxss output lines into KxssFinding structs.
    ///
    /// kxss outputs lines like:
    /// `[KXSS] https://example.com/search?q=test ← PARAM: q, REFLECTED: <>"'`
    /// or just the URL with the reflected chars appended.
    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<KxssFinding> {
        let mut findings = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.starts_with("http") {
                continue;
            }

            // kxss outputs: URL [param=value] Chars: <>
            // Extract URL (first token)
            let url = trimmed.split_whitespace().next().unwrap_or("").to_string();
            if url.is_empty() {
                continue;
            }

            // Try to extract reflected chars from rest of line
            let reflected_chars = if trimmed.contains('<') || trimmed.contains('>') {
                "<>\"'".to_string()
            } else if trimmed.contains('"') || trimmed.contains('\'') {
                "\"'".to_string()
            } else {
                "unknown".to_string()
            };

            // Extract param from URL query string
            let param = url.split('?')
                .nth(1)
                .and_then(|q| q.split('=').next())
                .unwrap_or("unknown")
                .to_string();

            // If angle brackets reflect → HIGH (likely exploitable XSS)
            let severity = if reflected_chars.contains('<') {
                "HIGH".to_string()
            } else {
                "MEDIUM".to_string()
            };

            info!("💡 kxss reflection [{}] at '{}' param='{}' chars='{}'",
                severity, url, param, reflected_chars);

            findings.push(KxssFinding {
                url,
                param,
                reflected_chars,
                severity,
            });
        }

        info!("kxss found {} reflected URL(s) for dalfox follow-up.", findings.len());
        findings
    }
}

#[async_trait]
impl SecurityTool for KxssAdapter {
    fn name(&self) -> &'static str {
        "kxss"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        match tokio::time::timeout(Duration::from_secs(3), cmd.output()).await {
            Ok(Ok(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Run kxss — pass URLs via stdin, get reflections back.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // kxss reads from stdin — we pass all URLs as newline-separated stdin
        let stdin_data = if input.targets.len() > 1 {
            input.targets.join("\n")
        } else {
            input.target.clone()
        };

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &[],
            Some(&stdin_data),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
