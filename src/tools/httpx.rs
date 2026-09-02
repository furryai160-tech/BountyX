use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResult {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub content_length: Option<usize>,
    pub response_time_ms: Option<u64>,
    pub technologies: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HttpxJsonOutput {
    pub url: Option<String>,
    pub input: Option<String>,
    pub host: Option<String>,
    pub port: Option<serde_json::Value>,
    pub scheme: Option<String>,
    #[serde(rename = "status-code", alias = "status_code")]
    pub status_code: Option<u16>,
    pub title: Option<String>,
    #[serde(rename = "content-length", alias = "content_length")]
    pub content_length: Option<usize>,
    #[serde(rename = "time", alias = "response_time")]
    pub response_time: Option<String>,
    pub techs: Option<Vec<String>>,
    pub technologies: Option<Vec<String>>,
}

pub struct HttpxAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
    custom_header: Option<String>,
}

impl HttpxAdapter {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
            repository: None,
            custom_header: None,
        }
    }

    pub fn with_repository(mut self, repo: Repository) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn with_custom_header(mut self, header: Option<String>) -> Self {
        self.custom_header = header;
        self
    }


    pub fn parse_results(&self, output: &ToolOutput) -> Vec<HttpProbeResult> {
        let mut results = Vec::new();

        for line in &output.raw_lines {
            if let Ok(entry) = serde_json::from_str::<HttpxJsonOutput>(line) {
                let target_url = entry.url.or(entry.input).unwrap_or_default();
                if target_url.is_empty() {
                    continue;
                }

                let parsed_url = Url::parse(&target_url).ok();
                let host = entry.host.unwrap_or_else(|| {
                    parsed_url
                        .as_ref()
                        .and_then(|u| u.host_str())
                        .unwrap_or("")
                        .to_string()
                });

                let scheme = entry.scheme.unwrap_or_else(|| {
                    parsed_url
                        .as_ref()
                        .map(|u| u.scheme().to_string())
                        .unwrap_or_else(|| "https".to_string())
                });

                let port = match entry.port {
                    Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(443) as u16,
                    Some(serde_json::Value::String(s)) => s.parse::<u16>().unwrap_or(443),
                    _ => parsed_url
                        .as_ref()
                        .and_then(|u| u.port())
                        .unwrap_or(if scheme == "http" { 80 } else { 443 }),
                };

                let techs = entry.techs.or(entry.technologies).unwrap_or_default();

                results.push(HttpProbeResult {
                    url: target_url,
                    host,
                    port,
                    scheme,
                    status_code: entry.status_code,
                    title: entry.title,
                    content_length: entry.content_length,
                    response_time_ms: None,
                    technologies: techs,
                });
            }
        }

        results
    }
}

#[async_trait]
impl SecurityTool for HttpxAdapter {
    fn name(&self) -> &'static str {
        "httpx"
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

        let mut args = vec![
            "-json".to_string(),
            "-silent".to_string(),
            "-title".to_string(),
            "-tech-detect".to_string(),
            "-status-code".to_string(),
            "-content-length".to_string(),
            "-threads".to_string(),
            "10".to_string(),
        ];

        if let Some(ref hdr) = self.custom_header {
            args.push("-H".to_string());
            args.push(hdr.clone());
        }

        let args_str_slices: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args_str_slices,
            Some(&stdin_content),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }

}
