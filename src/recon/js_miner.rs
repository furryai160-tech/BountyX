use crate::errors::Result;
use crate::mobile::models::ExtractedSecret;
use crate::validation::ScopeGuard;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsMinerResult {
    pub js_url: String,
    pub discovered_endpoints: Vec<String>,
    pub leaked_secrets: Vec<ExtractedSecret>,
}

pub struct JsMiner {
    client: Client,
    endpoint_regex: Regex,
    google_api_regex: Regex,
    aws_key_regex: Regex,
    stripe_key_regex: Regex,
    firebase_regex: Regex,
    slack_webhook_regex: Regex,
    github_pat_regex: Regex,
}

impl JsMiner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(2))
            .build()
            .unwrap_or_default();

        let endpoint_regex = Regex::new(
            r#"(?:"|')((?:/[a-zA-Z0-9_\-]+)+/(?:api|v[0-9]+|internal|admin|graphql|auth|user|v1|v2|v3|webhooks?|config)[a-zA-Z0-9_\-/]*)(?:"|')"#,
        )
        .expect("Valid endpoint regex");

        let google_api_regex = Regex::new(r"AIza[0-9A-Za-z\-_]{30,45}").expect("Valid Google regex");
        let aws_key_regex = Regex::new(r"AKIA[0-9A-Z]{16}").expect("Valid AWS regex");
        let stripe_key_regex = Regex::new(r"sk_live_[0-9a-zA-Z]{24,32}").expect("Valid Stripe regex");
        let firebase_regex = Regex::new(r"https?://[a-zA-Z0-9\-_]+\.firebaseio\.com").expect("Valid Firebase regex");
        let slack_webhook_regex = Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").expect("Valid Slack regex");
        let github_pat_regex = Regex::new(r"ghp_[0-9a-zA-Z]{30,40}").expect("Valid GitHub regex");


        Self {
            client,
            endpoint_regex,
            google_api_regex,
            aws_key_regex,
            stripe_key_regex,
            firebase_regex,
            slack_webhook_regex,
            github_pat_regex,
        }
    }

    /// Extract .js URLs from an endpoint list
    pub fn filter_js_urls(urls: &[String]) -> Vec<String> {
        let mut js_urls = Vec::new();
        for u in urls {
            let lower = u.to_lowercase();
            if lower.ends_with(".js")
                || lower.contains(".js?")
                || lower.contains(".js#")
                || lower.contains("/static/js/")
                || lower.contains("/_next/static/")
            {
                js_urls.push(u.clone());
            }
        }
        js_urls.sort();
        js_urls.dedup();
        js_urls
    }

    /// Analyze raw JavaScript content for endpoints and secrets
    pub fn analyze_js_content(&self, js_url: &str, content: &str) -> JsMinerResult {
        let mut discovered_endpoints = HashSet::new();
        let mut leaked_secrets = Vec::new();

        // 1. Extract API Endpoints
        for cap in self.endpoint_regex.captures_iter(content) {
            if let Some(matched) = cap.get(1) {
                let ep = matched.as_str().trim();
                // Filter out common false-positive extensions like .png, .css, .svg
                if !ep.ends_with(".png")
                    && !ep.ends_with(".jpg")
                    && !ep.ends_with(".css")
                    && !ep.ends_with(".svg")
                    && !ep.ends_with(".woff2")
                    && ep.len() > 3
                    && ep.len() < 120
                {
                    discovered_endpoints.insert(ep.to_string());
                }
            }
        }

        // 2. Extract Google API Keys
        for cap in self.google_api_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "Google Cloud API Key".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "HIGH".to_string(),
                description: format!("Google API key identified inside JS bundle '{}'", js_url),
            });
        }

        // 3. Extract AWS IAM Keys
        for cap in self.aws_key_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "AWS Access Key ID".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "CRITICAL".to_string(),
                description: format!("AWS IAM Access Key detected inside JS bundle '{}'", js_url),
            });
        }

        // 4. Extract Stripe Live Secret Keys
        for cap in self.stripe_key_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "Stripe Live Secret Key".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "CRITICAL".to_string(),
                description: format!("Stripe live secret key leaked inside JS bundle '{}'", js_url),
            });
        }

        // 5. Extract Firebase Databases
        for cap in self.firebase_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "Firebase Realtime DB".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "HIGH".to_string(),
                description: format!("Firebase database reference inside JS bundle '{}'", js_url),
            });
        }

        // 6. Extract Slack Webhooks
        for cap in self.slack_webhook_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "Slack Incoming Webhook".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "HIGH".to_string(),
                description: format!("Slack webhook exposed inside JS bundle '{}'", js_url),
            });
        }

        // 7. Extract GitHub Tokens
        for cap in self.github_pat_regex.find_iter(content) {
            leaked_secrets.push(ExtractedSecret {
                secret_type: "GitHub Personal Access Token".to_string(),
                matched_value: cap.as_str().to_string(),
                confidence: "CRITICAL".to_string(),
                description: format!("GitHub PAT discovered inside JS bundle '{}'", js_url),
            });
        }

        JsMinerResult {
            js_url: js_url.to_string(),
            discovered_endpoints: discovered_endpoints.into_iter().collect(),
            leaked_secrets,
        }
    }

    /// Asynchronously fetch and mine an in-scope JavaScript URL
    pub async fn fetch_and_mine(&self, js_url: &str) -> Option<JsMinerResult> {
        match self.client.get(js_url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return None;
                }

                // Check content length to avoid downloading huge files (> 3MB)
                if let Some(cl) = resp.content_length() {
                    if cl > 3 * 1024 * 1024 {
                        debug!("Skipping JS file '{}': size {} exceeds 3MB limit", js_url, cl);
                        return None;
                    }
                }

                if let Ok(text) = resp.text().await {
                    let result = self.analyze_js_content(js_url, &text);
                    return Some(result);
                }
            }
            Err(err) => {
                debug!("Failed to download JS file '{}': {}", js_url, err);
            }
        }
        None
    }

    /// Mine a collection of JS URLs concurrently (up to 10 at a time)
    pub async fn mine_all(&self, js_urls: &[String], max_files: usize) -> Vec<JsMinerResult> {
        let target_urls: Vec<String> = js_urls.iter().take(max_files).cloned().collect();
        let mut results = Vec::new();

        for chunk in target_urls.chunks(8) {
            let mut tasks = Vec::new();
            for url in chunk {
                let u = url.clone();
                tasks.push(async move { self.fetch_and_mine(&u).await });
            }

            let chunk_results = futures::future::join_all(tasks).await;
            for r in chunk_results.into_iter().flatten() {
                results.push(r);
            }
        }

        results
    }
}

impl Default for JsMiner {
    fn default() -> Self {
        Self::new()
    }
}
