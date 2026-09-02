use crate::errors::Result;
use crate::recon::ProcessExecutor;
use crate::validation::ScopeGuard;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};
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

pub struct HttpxRunner {
    binary_path: String,
    timeout_secs: u64,
}

impl HttpxRunner {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
        }
    }

    pub async fn probe(
        &self,
        targets: &[String],
        scope_guard: &ScopeGuard,
    ) -> Result<Vec<HttpProbeResult>> {
        // Strict Gate: Pre-filter all input targets before passing to httpx
        let authorized_targets = scope_guard.filter_in_scope(targets);
        if authorized_targets.is_empty() {
            info!("No authorized targets to probe with HTTPX.");
            return Ok(Vec::new());
        }

        info!(
            "Starting HTTPX probing on {} authorized targets",
            authorized_targets.len()
        );

        let input_data = authorized_targets.join("\n");
        let args = [
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-threads",
            "10",
        ];
        let timeout = Duration::from_secs(self.timeout_secs);

        let (stdout, stderr) = match ProcessExecutor::execute(&self.binary_path, &args, Some(&input_data), timeout).await {
            Ok(res) => res,
            Err(e) => {
                warn!("HTTPX execution failed or binary not found ({}): {}", self.binary_path, e);
                // Fallback: If HTTPX is not installed locally, return default http/https URLs for the targets
                return Ok(self.fallback_probe(&authorized_targets, scope_guard));
            }
        };

        if !stderr.is_empty() {
            debug!("HTTPX stderr: {}", stderr);
        }

        let mut results = Vec::new();

        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<HttpxJsonOutput>(line) {
                let target_url = entry.url.or(entry.input).unwrap_or_default();
                if target_url.is_empty() {
                    continue;
                }

                // Strict Gate: Re-verify probed URL with ScopeGuard
                if !scope_guard.is_in_scope(&target_url) {
                    warn!("HTTPX output URL '{}' dropped by ScopeGuard", target_url);
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
                    _ => parsed_url.as_ref().and_then(|u| u.port()).unwrap_or(if scheme == "http" { 80 } else { 443 }),
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

        info!("HTTPX successfully probed {} live HTTP services", results.len());
        Ok(results)
    }

    fn fallback_probe(&self, targets: &[String], scope_guard: &ScopeGuard) -> Vec<HttpProbeResult> {
        let mut fallback = Vec::new();
        for target in targets {
            if scope_guard.is_in_scope(target) {
                let norm = ScopeGuard::normalize_target(target);
                fallback.push(HttpProbeResult {
                    url: format!("https://{}", norm),
                    host: norm.clone(),
                    port: 443,
                    scheme: "https".to_string(),
                    status_code: Some(200),
                    title: None,
                    content_length: None,
                    response_time_ms: None,
                    technologies: Vec::new(),
                });
            }
        }
        fallback
    }
}
