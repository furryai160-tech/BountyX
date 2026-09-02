use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct TakeoverFingerprint {
    pub service: &'static str,
    pub cname_patterns: &'static [&'static str],
    pub response_fingerprints: &'static [&'static str],
    pub severity: &'static str,
}


pub const TAKEOVER_SIGNATURES: &[TakeoverFingerprint] = &[
    TakeoverFingerprint {
        service: "GitHub Pages",
        cname_patterns: &["github.io"],
        response_fingerprints: &[
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "AWS S3 Bucket",
        cname_patterns: &["s3.amazonaws.com", "s3-website"],
        response_fingerprints: &[
            "The specified bucket does not exist",
            "NoSuchBucket",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Heroku",
        cname_patterns: &["herokuapp.com", "herokussl.com"],
        response_fingerprints: &[
            "There's nothing here, yet.",
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Zendesk",
        cname_patterns: &["zendesk.com"],
        response_fingerprints: &[
            "Help Center Closed",
            "this help center no longer exists",
        ],
        severity: "MEDIUM",
    },
    TakeoverFingerprint {
        service: "Shopify",
        cname_patterns: &["myshopify.com", "shops.myshopify.com"],
        response_fingerprints: &[
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Fastly",
        cname_patterns: &["fastly.net", "fastlylb.net"],
        response_fingerprints: &[
            "Fastly error: unknown domain",
            "The Fastly Varnish cache server",
        ],
        severity: "MEDIUM",
    },
    TakeoverFingerprint {
        service: "Vercel",
        cname_patterns: &["vercel-dns.com", "zeit.world"],
        response_fingerprints: &[
            "404: NOT_FOUND",
            "The deployment could not be found on Vercel",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Ghost",
        cname_patterns: &["ghost.io"],
        response_fingerprints: &[
            "The thing you were looking for is no longer here",
            "The site you are looking for is not found",
        ],
        severity: "MEDIUM",
    },
    TakeoverFingerprint {
        service: "Readme.io",
        cname_patterns: &["readme.io"],
        response_fingerprints: &[
            "Project doesnt exist",
            "Project doesn't exist",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Surge.sh",
        cname_patterns: &["surge.sh"],
        response_fingerprints: &[
            "project not found",
        ],
        severity: "HIGH",
    },
    TakeoverFingerprint {
        service: "Pantheon",
        cname_patterns: &["pantheonsite.io"],
        response_fingerprints: &[
            "404 error unknown site!",
            "The gods are wise, but do not know of the site which you seek.",
        ],
        severity: "HIGH",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverFinding {
    pub target: String,
    pub service: String,
    pub matched_fingerprint: String,
    pub severity: String,
    pub verified_url: String,
    pub description: String,
}

pub struct TakeoverScanner {
    client: Client,
}

impl TakeoverScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();

        Self { client }
    }

    /// Check if a given response body matches any known takeover signature
    pub fn inspect_response_body(
        target: &str,
        verified_url: &str,
        body: &str,
    ) -> Option<TakeoverFinding> {
        for sig in TAKEOVER_SIGNATURES {
            for &fp in sig.response_fingerprints {
                if body.contains(fp) {
                    return Some(TakeoverFinding {
                        target: target.to_string(),
                        service: sig.service.to_string(),
                        matched_fingerprint: fp.to_string(),
                        severity: sig.severity.to_string(),
                        verified_url: verified_url.to_string(),
                        description: format!(
                            "Potential Subdomain Takeover on '{}' pointing to unregistered service '{}'. Matched fingerprint: '{}'",
                            target, sig.service, fp
                        ),
                    });
                }
            }
        }
        None
    }

    /// Scan a single target over HTTPS and HTTP for takeover indicators
    pub async fn check_target(&self, target: &str) -> Option<TakeoverFinding> {
        let clean_host = target
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target);

        // 1. Try HTTPS first
        let https_url = format!("https://{}", clean_host);
        if let Ok(resp) = self.client.get(&https_url).send().await {
            if let Ok(body) = resp.text().await {
                if let Some(finding) = Self::inspect_response_body(clean_host, &https_url, &body) {
                    warn!(
                        "🚨 SUBDOMAIN TAKEOVER DETECTED on '{}' -> {}",
                        clean_host, finding.service
                    );
                    return Some(finding);
                }
            }
        }

        // 2. Fallback to HTTP
        let http_url = format!("http://{}", clean_host);
        if let Ok(resp) = self.client.get(&http_url).send().await {
            if let Ok(body) = resp.text().await {
                if let Some(finding) = Self::inspect_response_body(clean_host, &http_url, &body) {
                    warn!(
                        "🚨 SUBDOMAIN TAKEOVER DETECTED on '{}' -> {}",
                        clean_host, finding.service
                    );
                    return Some(finding);
                }
            }
        }

        None
    }

    /// Batch scan a list of subdomains with bounded concurrency
    pub async fn scan_subdomains(&self, targets: &[String]) -> Vec<TakeoverFinding> {
        if targets.is_empty() {
            return Vec::new();
        }

        debug!("Starting Subdomain Takeover scan on {} targets...", targets.len());
        let mut findings = Vec::new();

        // Check targets in small chunks of 10 to avoid overwhelming network
        for chunk in targets.chunks(10) {
            let mut tasks = Vec::new();
            for target in chunk {
                let t = target.clone();
                tasks.push(async move { self.check_target(&t).await });
            }

            let results = futures::future::join_all(tasks).await;
            for r in results.into_iter().flatten() {
                findings.push(r);
            }
        }

        if !findings.is_empty() {
            info!("Subdomain Takeover scan finished. Found {} vulnerable targets!", findings.len());
        }

        findings
    }
}

impl Default for TakeoverScanner {
    fn default() -> Self {
        Self::new()
    }
}
