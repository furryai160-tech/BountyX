use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// Result from gospider crawler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GospiderResult {
    /// Discovered URL
    pub url: String,
    /// Source (form, linkfinder, robots, etc.)
    pub source: String,
}

/// Adapter for `gospider` — fast web spider for endpoint discovery.
///
/// Gospider is more aggressive than katana and discovers endpoints via:
/// - HTML link extraction (a href, src, action)
/// - JavaScript analysis (fetch(), XMLHttpRequest, axios)
/// - Form action URLs
/// - robots.txt and sitemap.xml
/// - External JS files analysis
/// - Inline JS parsing
///
/// Used as a complementary crawler alongside katana for maximum
/// endpoint coverage. Different parsers catch different endpoints.
#[derive(Clone)]
pub struct GospiderAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl GospiderAdapter {
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

    /// Parse gospider output lines into discovered URLs.
    ///
    /// gospider outputs lines like:
    /// `[url] - [code-200] - https://example.com/api/v1/users`
    /// `[form] - https://example.com/login`
    /// `[javascript] - https://cdn.example.com/app.js`
    pub fn parse_results(&self, output: &ToolOutput) -> Vec<GospiderResult> {
        let mut results = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();
            if !trimmed.contains("http") {
                continue;
            }

            // Extract source type and URL
            let (source, url) = if trimmed.starts_with('[') {
                // Format: [type] - [code-N] - URL or [type] - URL
                let parts: Vec<&str> = trimmed.splitn(3, " - ").collect();
                let src = parts.first()
                    .map(|s| s.trim_matches(|c| c == '[' || c == ']'))
                    .unwrap_or("unknown")
                    .to_string();
                let url_part = parts.last()
                    .map(|s| s.trim())
                    .unwrap_or("")
                    .to_string();
                (src, url_part)
            } else {
                // Raw URL
                ("gospider".to_string(), trimmed.to_string())
            };

            if url.starts_with("http") && !url.is_empty() {
                results.push(GospiderResult { url, source });
            }
        }

        info!("gospider discovered {} endpoint(s).", results.len());
        results
    }
}

#[async_trait]
impl SecurityTool for GospiderAdapter {
    fn name(&self) -> &'static str {
        "gospider"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("--version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        let args: Vec<&str> = vec![
            "-s", &input.target,
            "--depth", "3",         // 3 levels deep
            "--concurrent", "5",    // 5 concurrent requests
            "--threads", "5",
            "--timeout", "10",
            "--quiet",
            "--robots",             // Respect robots.txt paths (still crawls them)
            "--sitemap",            // Parse sitemap.xml
            "--other-source",       // Crawl JS files found
            "--include-subs",       // Include subdomains
            "-o", "/dev/null",      // Don't write to file, use stdout
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
