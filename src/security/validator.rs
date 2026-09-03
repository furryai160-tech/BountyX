use crate::ai::planner::SecurityHypothesis;
use crate::sandbox::client::{SandboxedHttpClient, SandboxedResponse};
use crate::security::evidence::{EvidenceBundle, SecretRedactor};
use crate::security::risk::{RiskAssessment, RiskEngine, Severity};
use chrono::Utc;
use reqwest::header::HeaderMap;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Confirmed,
    NeedsValidation,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedFinding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: FindingStatus,
    pub target_url: String,
    pub risk: RiskAssessment,
    pub evidence: EvidenceBundle,
    pub remediation: String,
}

pub struct FindingValidator;

impl FindingValidator {
    pub async fn validate_hypothesis(
        http_client: &SandboxedHttpClient,
        hypothesis: &SecurityHypothesis,
        initial_response: &SandboxedResponse,
        custom_headers: Option<HeaderMap>,
    ) -> Option<VerifiedFinding> {
        let method = Method::from_str(&hypothesis.method).unwrap_or(Method::GET);

        // 1. Evaluate Initial Anomaly
        let cat_lower = hypothesis.category.to_lowercase();
        let is_anomaly = if cat_lower.contains("bola") || cat_lower.contains("idor") {
            // An unauthenticated request returned 200 OK with JSON content containing IDs
            initial_response.status == 200
                && (initial_response.body.contains("\"id\"")
                    || initial_response.body.contains("\"email\"")
                    || initial_response.body.contains("\"user\""))
        } else if cat_lower.contains("cors") {
            // Reflected origin in Access-Control-Allow-Origin
            initial_response.headers.get("access-control-allow-origin").is_some()
        } else if cat_lower.contains("admin") || cat_lower.contains("authentication") {
            // 200 OK on admin path without credentials
            initial_response.status == 200
        } else if cat_lower.contains("sensitive") || cat_lower.contains("file") || cat_lower.contains("exposure") {
            // Check for exposed git repository, environment file, or openapi docs
            if hypothesis.target_url.ends_with("/.git/HEAD") {
                initial_response.status == 200 && initial_response.body.contains("ref: refs/")
            } else if hypothesis.target_url.ends_with("/.env") {
                initial_response.status == 200 && (initial_response.body.contains("DB_") || initial_response.body.contains("SECRET") || initial_response.body.contains("KEY="))
            } else if hypothesis.target_url.ends_with("/swagger.json") || hypothesis.target_url.ends_with("/openapi.json") {
                initial_response.status == 200 && (initial_response.body.contains("\"swagger\"") || initial_response.body.contains("\"openapi\""))
            } else {
                false
            }
        } else if cat_lower.contains("header") || cat_lower.contains("clickjacking") {
            // Missing X-Frame-Options and Frame-Ancestors CSP
            initial_response.status == 200 
                && initial_response.headers.get("x-frame-options").is_none()
                && !initial_response.headers.get("content-security-policy").map(|v| v.contains("frame-ancestors")).unwrap_or(false)
        } else {
            false
        };


        if !is_anomaly {
            return None;
        }

        // 2. Perform Reproduction Probe (Verify repeatability)
        let reproduction_res = http_client
            .request(method.clone(), &hypothesis.target_url, custom_headers.clone(), None)
            .await;

        let (is_reproduced, repro_resp) = match reproduction_res {
            Ok(resp) => {
                let consistent_status = resp.status == initial_response.status;
                let consistent_body = !resp.body.is_empty() && (resp.body.len() as i64 - initial_response.body.len() as i64).abs() < 100;
                (consistent_status && consistent_body, resp)
            }
            Err(_) => (false, initial_response.clone()),
        };

        // 3. Compute Status and Risk
        let status = if is_reproduced {
            FindingStatus::Confirmed
        } else {
            FindingStatus::NeedsValidation
        };

        let has_sensitive_data = repro_resp.body.contains("\"email\"")
            || repro_resp.body.contains("\"token\"")
            || repro_resp.body.contains("\"password\"");

        let risk = RiskEngine::calculate(&hypothesis.category, is_reproduced, has_sensitive_data);

        // 4. Bundle and Redact Evidence
        let evidence = EvidenceBundle {
            finding_id: format!("find-{}", uuid::Uuid::new_v4().simple()),
            timestamp: Utc::now(),
            target_url: hypothesis.target_url.clone(),
            method: hypothesis.method.clone(),
            request_headers: SecretRedactor::redact_headers(&initial_response.headers),
            request_body: None,
            response_status: repro_resp.status,
            response_headers: SecretRedactor::redact_headers(&repro_resp.headers),
            response_snippet: SecretRedactor::redact_snippet(&repro_resp.body),
            reproduction_curl: repro_resp.curl_command.clone(),
            differential_notes: format!(
                "Initial probe HTTP {} ({}ms). Reproduction probe HTTP {} ({}ms). Consistency verified: {}.",
                initial_response.status, initial_response.elapsed_ms, repro_resp.status, repro_resp.elapsed_ms, is_reproduced
            ),
        };

        let remediation = if cat_lower.contains("bola") || cat_lower.contains("idor") {
            "Implement server-side object authorization checks validating that the authenticated session owns the requested resource ID before returning data.".to_string()
        } else if cat_lower.contains("cors") {
            "Configure a strict whitelist of trusted domains for Access-Control-Allow-Origin. Avoid reflecting arbitrary Origin headers.".to_string()
        } else {
            "Restrict access to authenticated and authorized users only.".to_string()
        };

        Some(VerifiedFinding {
            id: evidence.finding_id.clone(),
            title: hypothesis.title.clone(),
            category: hypothesis.category.clone(),
            status,
            target_url: hypothesis.target_url.clone(),
            risk,
            evidence,
            remediation,
        })
    }
}
