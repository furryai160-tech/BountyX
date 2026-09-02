use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info};
use url::Url;

/// Result of an Open Redirect probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRedirectFinding {
    /// The original URL that was tested
    pub original_url: String,
    /// The specific parameter that was vulnerable
    pub vulnerable_param: String,
    /// The injected payload
    pub payload: String,
    /// Where the server actually redirected to (Location header)
    pub redirected_to: String,
    /// Severity (HIGH if redirects to external domain, MEDIUM if partial)
    pub severity: String,
    /// Human-readable description
    pub description: String,
}

/// Internal Open Redirect scanner — no external binary required.
///
/// This scanner works by taking discovered endpoints with URL parameters,
/// injecting known redirect payloads into each parameter, sending HTTP
/// requests, and detecting whether the server redirects to an external domain.
///
/// Why this matters for Bug Bounty:
/// - Open Redirects are P3/P4 bugs alone, but chain with OAuth/SSRF for P1.
/// - They are easy to miss with generic Nuclei scans.
/// - Fast detection on hundreds of endpoints gives an edge.
pub struct OpenRedirectScanner {
    client: Client,
    payloads: Vec<String>,
}

/// Common redirect parameter names to test automatically
const REDIRECT_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnUrl", "next", "goto", "destination",
    "dest", "target", "to", "link", "ref", "checkout_url",
    "continue", "forward", "location", "out", "view", "go",
    "r", "u", "uri", "path", "page", "callback", "success_url",
    "failure_url", "from", "back",
];

impl OpenRedirectScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none()) // Don't follow — detect the Location header
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();

        // Standard redirect detection payloads
        let payloads = vec![
            "https://evil.com".to_string(),
            "//evil.com".to_string(),
            "//evil.com/%2F..".to_string(),
            "https://evil.com%23.target.com".to_string(),
            "//google.com".to_string(),
            "https://google.com".to_string(),
        ];

        Self { client, payloads }
    }

    /// Scan a list of URLs for open redirect vulnerabilities.
    ///
    /// For each URL, we:
    /// 1. Parse existing parameters
    /// 2. Inject redirect payloads into each param
    /// 3. Check for 3xx responses where Location points externally
    pub async fn scan_urls(&self, urls: &[String], concurrency: usize) -> Vec<OpenRedirectFinding> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let findings = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let mut tasks = Vec::new();
        for url in urls {
            // Only probe URLs with query parameters or inject common params
            let probe_targets = self.build_probe_targets(url);
            if probe_targets.is_empty() {
                continue;
            }

            for (probe_url, param_name, payload) in probe_targets {
                let sem = semaphore.clone();
                let findings_ref = findings.clone();
                let client = self.client.clone();
                let original_url = url.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    if let Some(finding) = Self::probe_single(&client, &original_url, &probe_url, &param_name, &payload).await {
                        let mut guard = findings_ref.lock().await;
                        guard.push(finding);
                    }
                }));
            }
        }

        for task in tasks {
            let _ = task.await;
        }

        let result = findings.lock().await.clone();
        info!("Open Redirect scan completed. Found {} potential redirect vulnerabilities.", result.len());
        result
    }

    fn build_probe_targets(&self, raw_url: &str) -> Vec<(String, String, String)> {
        let mut probes = Vec::new();

        let Ok(parsed) = Url::parse(raw_url) else { return probes };

        // Use the first payload for bulk scanning (most distinctive)
        let payload = "https://evil.com";

        // Test existing parameters in the URL
        let existing_params: Vec<String> = parsed.query_pairs()
            .map(|(k, _)| k.to_string())
            .collect();

        for param in &existing_params {
            if Self::param_looks_like_redirect(param) {
                if let Ok(mut modified_url) = Url::parse(raw_url) {
                    let new_query: String = modified_url.query_pairs()
                        .map(|(k, v)| {
                            if k == param.as_str() {
                                format!("{}={}", k, urlencoding::encode(payload))
                            } else {
                                format!("{}={}", k, v)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("&");

                    modified_url.set_query(Some(&new_query));
                    probes.push((modified_url.to_string(), param.clone(), payload.to_string()));
                }
            }
        }

        // Also inject common redirect params if none found
        if probes.is_empty() {
            // Only test a subset of common params on URLs without existing params
            for &redirect_param in REDIRECT_PARAMS.iter().take(8) {
                let mut probe_url = parsed.clone();
                let encoded = urlencoding::encode(payload).to_string();
                probe_url.set_query(Some(&format!("{}={}", redirect_param, encoded)));
                probes.push((probe_url.to_string(), redirect_param.to_string(), payload.to_string()));
            }
        }

        probes
    }

    fn param_looks_like_redirect(param: &str) -> bool {
        REDIRECT_PARAMS.iter().any(|&r| param.eq_ignore_ascii_case(r))
    }

    async fn probe_single(
        client: &Client,
        original_url: &str,
        probe_url: &str,
        param: &str,
        payload: &str,
    ) -> Option<OpenRedirectFinding> {
        let response = match client.get(probe_url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        let status = response.status().as_u16();

        // Check for redirect response (3xx)
        if !(300..=399).contains(&status) {
            return None;
        }

        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if location.is_empty() {
            return None;
        }

        // Confirmed external redirect?
        let is_external = location.starts_with("https://evil.com")
            || location.starts_with("//evil.com")
            || location.starts_with("https://google.com")
            || location.starts_with("//google.com");

        if is_external {
            debug!("✅ Open Redirect confirmed: {} -> Location: {}", probe_url, location);
            let severity = if location.starts_with("https://evil.com") || location.starts_with("//evil.com") {
                "HIGH".to_string()
            } else {
                "MEDIUM".to_string()
            };

            return Some(OpenRedirectFinding {
                original_url: original_url.to_string(),
                vulnerable_param: param.to_string(),
                payload: payload.to_string(),
                redirected_to: location,
                severity,
                description: format!(
                    "Open Redirect via parameter '{}': Server returned HTTP {} and redirected externally.",
                    param, status
                ),
            });
        }

        None
    }
}
