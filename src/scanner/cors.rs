use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info};
use url::Url;

/// Severity of a CORS misconfiguration finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorsSeverity {
    /// Origin reflected with Credentials: true — exploitable data theft
    Critical,
    /// Origin reflected without credentials — limited but real impact
    High,
    /// Null origin accepted — exploitable from sandboxed/data: URIs
    Medium,
    /// Wildcard but no credentials — informational
    Low,
}

impl CorsSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// A single CORS misconfiguration finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsFinding {
    /// The URL that was tested
    pub url: String,
    /// The Origin header we sent
    pub tested_origin: String,
    /// The ACAO header the server returned
    pub reflected_origin: String,
    /// Whether Access-Control-Allow-Credentials was true
    pub credentials_allowed: bool,
    /// Severity classification
    pub severity: String,
    /// Human-readable description
    pub description: String,
}

/// CORS Misconfiguration Scanner — pure Rust, no external binary.
///
/// Tests for the most common and impactful CORS misconfigurations:
///
/// 1. **Reflected Origin + Credentials** (CRITICAL): Server reflects back any
///    origin AND sets `Access-Control-Allow-Credentials: true`. Allows
///    cross-site requests to read authenticated data.
///
/// 2. **Reflected Origin** (HIGH): Server mirrors back arbitrary origins in
///    ACAO header. May allow reading unauthenticated data cross-origin.
///
/// 3. **Null Origin** (MEDIUM): Server accepts `Origin: null`. Exploitable
///    from sandboxed iframes and `data:` URI contexts.
///
/// 4. **Wildcard** (LOW): `Access-Control-Allow-Origin: *` without credentials.
///    Informational only — intended CORS policy but worth noting.
///
/// 5. **Subdomain Bypass**: Tests `evil.target.com` style origins to detect
///    overly permissive regex-based origin validation.
pub struct CorsScanner {
    client: Client,
}

impl CorsScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        Self { client }
    }

    /// Scan a list of URLs for CORS misconfigurations.
    pub async fn scan_urls(&self, urls: &[String], concurrency: usize) -> Vec<CorsFinding> {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
        let findings = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let mut tasks = Vec::new();

        for url in urls {
            // Build attacker-controlled origins to test for this target
            let test_origins = self.build_test_origins(url);

            for (origin_label, origin_value) in test_origins {
                let sem = semaphore.clone();
                let findings_ref = findings.clone();
                let client = self.client.clone();
                let url_clone = url.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await;

                    if let Some(finding) = Self::probe_cors(
                        &client,
                        &url_clone,
                        &origin_label,
                        &origin_value,
                    )
                    .await
                    {
                        let mut guard = findings_ref.lock().await;
                        // Deduplicate: skip if same URL+origin already added
                        let already = guard
                            .iter()
                            .any(|f: &CorsFinding| f.url == finding.url && f.tested_origin == finding.tested_origin);
                        if !already {
                            guard.push(finding);
                        }
                    }
                }));
            }
        }

        for task in tasks {
            let _ = task.await;
        }

        let result = findings.lock().await.clone();
        info!(
            "CORS scan completed across {} URLs. Found {} misconfigurations.",
            urls.len(),
            result.len()
        );
        result
    }

    /// Build attacker-controlled origins to test for a given target URL.
    fn build_test_origins(&self, url: &str) -> Vec<(String, String)> {
        let mut origins = Vec::new();

        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return origins,
        };

        let host = match parsed.host_str() {
            Some(h) => h,
            None => return origins,
        };

        let scheme = parsed.scheme();

        // 1. Completely foreign origin (most basic test)
        origins.push(("foreign_origin".to_string(), "https://evil.com".to_string()));

        // 2. Null origin (sandboxed iframe bypass)
        origins.push(("null_origin".to_string(), "null".to_string()));

        // 3. Subdomain prefix bypass (evil.target.com style)
        origins.push((
            "subdomain_bypass".to_string(),
            format!("{}://evil.{}", scheme, host),
        ));

        // 4. Suffix bypass (target.com.evil.com style)
        origins.push((
            "suffix_bypass".to_string(),
            format!("{}://{}.evil.com", scheme, host),
        ));

        // 5. HTTP version of an HTTPS endpoint (protocol downgrade)
        if scheme == "https" {
            origins.push((
                "http_downgrade".to_string(),
                format!("http://{}", host),
            ));
        }

        origins
    }

    /// Send a single probe and return a CorsFinding if a misconfiguration is detected.
    async fn probe_cors(
        client: &Client,
        url: &str,
        origin_label: &str,
        test_origin: &str,
    ) -> Option<CorsFinding> {
        let response = match client
            .get(url)
            .header("Origin", test_origin)
            .header("Accept", "application/json, text/html, */*")
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return None,
        };

        let headers = response.headers().clone();

        // Extract CORS response headers
        let acao = headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let acac = headers
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("false")
            .to_string();

        let credentials_allowed = acac.trim().eq_ignore_ascii_case("true");

        // No CORS header at all — not misconfigured
        if acao.is_empty() {
            return None;
        }

        // Wildcard — lowest severity, informational
        if acao == "*" {
            if credentials_allowed {
                // Wildcard + credentials is technically invalid but some servers do it
                return Some(CorsFinding {
                    url: url.to_string(),
                    tested_origin: test_origin.to_string(),
                    reflected_origin: acao,
                    credentials_allowed: true,
                    severity: CorsSeverity::Critical.as_str().to_string(),
                    description: format!(
                        "CORS wildcard (*) with Access-Control-Allow-Credentials: true. \
                        Allows cross-origin authenticated requests from any domain. \
                        Origin tested: '{}'",
                        test_origin
                    ),
                });
            }

            debug!("CORS wildcard found at {} (LOW — informational)", url);
            return None; // Skip pure wildcards — too noisy, not exploitable without credentials
        }

        // Check if our attacker-controlled origin was reflected back
        let is_reflected = acao.trim() == test_origin
            || acao.contains("evil.com")
            || (test_origin == "null" && acao == "null");

        if !is_reflected {
            return None;
        }

        // Determine severity based on credentials flag
        let (severity, description) = if credentials_allowed {
            (
                CorsSeverity::Critical.as_str().to_string(),
                format!(
                    "CRITICAL CORS: Server reflects attacker-controlled origin '{}' \
                    AND sets Access-Control-Allow-Credentials: true. \
                    Full cross-origin authenticated data theft possible. \
                    Attack type: '{}'",
                    test_origin, origin_label
                ),
            )
        } else if test_origin == "null" {
            (
                CorsSeverity::Medium.as_str().to_string(),
                format!(
                    "CORS accepts null origin (sandboxed iframe/data URI bypass). \
                    Server returned ACAO: '{}'. Exploitable from sandboxed contexts.",
                    acao
                ),
            )
        } else {
            (
                CorsSeverity::High.as_str().to_string(),
                format!(
                    "CORS reflects attacker origin '{}' (no credentials). \
                    May allow cross-origin reading of unauthenticated responses. \
                    Attack type: '{}'",
                    test_origin, origin_label
                ),
            )
        };

        info!(
            "🌐 CORS misconfiguration found [{}]: {} — Origin: {} → ACAO: {} (credentials={})",
            severity, url, test_origin, acao, credentials_allowed
        );

        Some(CorsFinding {
            url: url.to_string(),
            tested_origin: test_origin.to_string(),
            reflected_origin: acao,
            credentials_allowed,
            severity,
            description,
        })
    }
}
