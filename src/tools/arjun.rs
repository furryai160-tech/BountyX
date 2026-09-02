use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

/// A single parameter discovered by arjun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArjunParam {
    /// The URL where the parameter was discovered
    pub url: String,
    /// Discovered parameter names
    pub params: Vec<String>,
    /// HTTP method (GET or POST)
    pub method: String,
}

/// Adapter wrapping the `arjun` Hidden Parameter Discovery tool.
///
/// Arjun finds hidden HTTP parameters using wordlists and difference-based
/// detection. Discovering hidden parameters is critical for finding SSRF,
/// Open Redirect, SQLi, and XSS through parameters that normal crawlers miss.
#[derive(Clone)]
pub struct ArjunAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl ArjunAdapter {
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

    /// Parse arjun JSON output (arjun -oJ mode produces JSON arrays).
    ///
    /// Arjun JSON output per URL:
    /// [{"url": "https://example.com/api", "params": ["id", "user", "token"]}]
    pub fn parse_results(&self, output: &ToolOutput) -> Vec<ArjunParam> {
        let mut results = Vec::new();

        // Try parsing as a JSON array first
        let full_stdout = output.raw_lines.join("\n");
        if let Ok(parsed) = serde_json::from_str::<Vec<RawArjunResult>>(&full_stdout) {
            for r in parsed {
                if !r.params.is_empty() {
                    results.push(ArjunParam {
                        url: r.url,
                        params: r.params,
                        method: "GET".to_string(),
                    });
                }
            }
        } else {
            // Fallback: parse line-by-line for text output format
            // Format: [+] Parameters found: id, user, token
            let mut current_url = String::new();
            for line in &output.raw_lines {
                let trimmed = line.trim();
                if trimmed.starts_with("http") {
                    current_url = trimmed.to_string();
                } else if trimmed.starts_with("[+] Parameters found:") || trimmed.contains("Parameters:") {
                    if let Some(params_str) = trimmed.split(':').nth(1) {
                        let params: Vec<String> = params_str
                            .split(',')
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect();

                        if !params.is_empty() && !current_url.is_empty() {
                            results.push(ArjunParam {
                                url: current_url.clone(),
                                params,
                                method: "GET".to_string(),
                            });
                        }
                    }
                }
            }
        }

        results
    }
}

#[derive(Deserialize)]
struct RawArjunResult {
    pub url: String,
    #[serde(default)]
    pub params: Vec<String>,
}

#[async_trait]
impl SecurityTool for ArjunAdapter {
    fn name(&self) -> &'static str {
        "arjun"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("--help");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(!out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Run arjun parameter discovery.
    ///
    /// We run arjun in stdin/file mode using `-i` with a temp URL list,
    /// and capture structured JSON output via `-oJ /dev/stdout`.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // arjun reads a URL list from a file (-i) and outputs JSON (-oJ)
        // We pass urls via stdin_data and use -i /dev/stdin
        let args: Vec<&str> = vec![
            "-i",
            "/dev/stdin",
            "--stable",      // stable mode: less noise, more reliable results
            "-t",
            "5",             // 5 threads per URL
            "-oJ",
            "/dev/stdout",   // JSON output to stdout
            "--quiet",       // suppress banner
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
