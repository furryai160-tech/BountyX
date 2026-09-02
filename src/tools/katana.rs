use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::Deserialize;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct KatanaJsonOutput {
    pub request: Option<KatanaRequest>,
}

#[derive(Debug, Deserialize)]
struct KatanaRequest {
    pub endpoint: Option<String>,
}

pub struct KatanaAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl KatanaAdapter {
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

    pub fn parse_urls(&self, output: &ToolOutput) -> Vec<String> {
        let mut urls = Vec::new();
        for line in &output.raw_lines {
            if let Ok(entry) = serde_json::from_str::<KatanaJsonOutput>(line) {
                if let Some(req) = entry.request {
                    if let Some(ep) = req.endpoint {
                        if !ep.is_empty() {
                            urls.push(ep);
                        }
                    }
                }
            } else if line.starts_with("http://") || line.starts_with("https://") {
                urls.push(line.clone());
            }
        }
        urls
    }
}

#[async_trait]
impl SecurityTool for KatanaAdapter {
    fn name(&self) -> &'static str {
        "katana"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);
        let stdin_content = if let Some(ref s) = input.stdin_data {
            s.clone()
        } else {
            input.targets.join("\n")
        };

        let args = [
            "-silent",
            "-jsonl",
            "-depth",
            "2",
            "-crawl-duration",
            "30",
            "-concurrency",
            "5",
        ];

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
