use crate::errors::{BountyScopeError, Result};
use crate::sandbox::kill_switch::KillSwitch;
use crate::sandbox::limits::RateLimiter;
use crate::scope::guard::ScopeGuard;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxedResponse {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub elapsed_ms: u128,
    pub curl_command: String,
}

#[derive(Clone)]
pub struct SandboxedHttpClient {
    client: Client,
    scope_guard: ScopeGuard,
    rate_limiter: RateLimiter,
    kill_switch: KillSwitch,
}

impl SandboxedHttpClient {
    pub fn new(scope_guard: ScopeGuard, kill_switch: KillSwitch) -> Result<Self> {
        let timeout_secs = scope_guard.policy().request_timeout_seconds;
        let rps = scope_guard.policy().rate_limit_rps;

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(false)
            .build()?;

        let rate_limiter = RateLimiter::new(rps);

        Ok(Self {
            client,
            scope_guard,
            rate_limiter,
            kill_switch,
        })
    }

    pub fn scope_guard(&self) -> &ScopeGuard {
        &self.scope_guard
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill_switch
    }

    pub async fn request(
        &self,
        method: Method,
        url_str: &str,
        custom_headers: Option<HeaderMap>,
        body: Option<Vec<u8>>,
    ) -> Result<SandboxedResponse> {
        // 1. Kill switch check
        if self.kill_switch.is_triggered() {
            return Err(BountyScopeError::Config(
                "Execution aborted by emergency KillSwitch".to_string(),
            ));
        }

        // 2. Scope Guard check (Fail-closed)
        self.scope_guard
            .validate_and_record_request(url_str, method.as_str())
            .map_err(|violation| BountyScopeError::Scope(violation.to_string()))?;

        // 3. Rate limiter throttling
        self.rate_limiter.acquire().await;

        // 4. Construct request
        let mut req_builder = self.client.request(method.clone(), url_str);

        // Inject default user-agent
        req_builder = req_builder.header(
            USER_AGENT,
            "BountyX-Autonomous-Agent/3.0 (Authorized Security Research)",
        );

        // Inject policy custom headers (e.g., X-HackerOne-Research)
        for (k, v) in &self.scope_guard.policy().custom_headers {
            if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_str(k), HeaderValue::from_str(v)) {
                req_builder = req_builder.header(h_name, h_val);
            }
        }

        // Inject request custom headers
        if let Some(headers) = custom_headers {
            for (k, v) in headers {
                if let Some(k) = k {
                    req_builder = req_builder.header(k, v);
                }
            }
        }

        // Generate reproducible curl command
        let curl_cmd = format!(
            "curl -i -s -X {} \"{}\" -A \"BountyX-Autonomous-Agent/3.0\"",
            method.as_str(),
            url_str
        );

        if let Some(ref b) = body {
            req_builder = req_builder.body(b.clone());
        }

        // 5. Execute with elapsed timer
        let start = Instant::now();
        let resp = req_builder.send().await?;
        let elapsed_ms = start.elapsed().as_millis();

        let status = resp.status().as_u16();

        let mut headers_map = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            headers_map.insert(k.as_str().to_string(), v.to_str().unwrap_or("").to_string());
        }

        let body_text = resp.text().await.unwrap_or_default();

        Ok(SandboxedResponse {
            url: url_str.to_string(),
            method: method.as_str().to_string(),
            status,
            headers: headers_map,
            body: body_text,
            elapsed_ms,
            curl_command: curl_cmd,
        })
    }
}
