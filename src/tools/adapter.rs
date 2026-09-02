use crate::errors::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInput {
    pub target: String,
    pub targets: Vec<String>,
    pub extra_args: Vec<String>,
    pub stdin_data: Option<String>,
    pub job_id: Option<String>,
}

impl ToolInput {
    pub fn single(target: &str) -> Self {
        Self {
            target: target.to_string(),
            targets: vec![target.to_string()],
            extra_args: Vec::new(),
            stdin_data: None,
            job_id: None,
        }
    }

    pub fn multiple(targets: &[String]) -> Self {
        Self {
            target: targets.first().cloned().unwrap_or_default(),
            targets: targets.to_vec(),
            extra_args: Vec::new(),
            stdin_data: Some(targets.join("\n")),
            job_id: None,
        }
    }

    pub fn with_job_id(mut self, job_id: Option<&str>) -> Self {
        self.job_id = job_id.map(|s| s.to_string());
        self
    }

    pub fn with_extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args = args;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub tool_name: String,
    pub target: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub raw_lines: Vec<String>,
}

#[async_trait]
pub trait SecurityTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn binary_path(&self) -> &str;
    async fn check_available(&self) -> Result<bool>;
    async fn run(&self, input: ToolInput) -> Result<ToolOutput>;
}
