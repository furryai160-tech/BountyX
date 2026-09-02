use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub parent_asset: String,
    pub source: String,
}

pub struct SubfinderAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl SubfinderAdapter {
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

    pub fn parse_subdomains(&self, output: &ToolOutput, parent_asset: &str) -> Vec<SubdomainResult> {
        output
            .raw_lines
            .iter()
            .map(|line| SubdomainResult {
                subdomain: line.clone(),
                parent_asset: parent_asset.to_string(),
                source: "subfinder".to_string(),
            })
            .collect()
    }
}

#[async_trait]
impl SecurityTool for SubfinderAdapter {
    fn name(&self) -> &'static str {
        "subfinder"
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
        let args = ["-d", &input.target, "-silent", "-all"];

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            input.stdin_data.as_deref(),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
