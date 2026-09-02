use crate::errors::Result;
use crate::mobile::models::{ExtractedSecret, MobileAnalysisResult};
use crate::validation::{Deduplicator, ScopeGuard};
use regex::Regex;
use tracing::{debug, info};

pub struct MobileAnalyzer;

impl MobileAnalyzer {
    pub fn analyze_app_metadata(
        app_identifier: &str,
        platform: &str,
        raw_text_content: &str,
        scope_guard: &ScopeGuard,
    ) -> Result<MobileAnalysisResult> {
        info!(
            "Running Mobile Static Analysis on {} application: '{}'",
            platform, app_identifier
        );

        let mut leaked_secrets = Vec::new();
        let mut extracted_endpoints = Vec::new();
        let mut insecure_configurations = Vec::new();

        // 1. Google API Key Pattern
        if let Ok(re_google) = Regex::new(r"AIza[0-9A-Za-z\-_]{30,45}") {
            for cap in re_google.find_iter(raw_text_content) {
                leaked_secrets.push(ExtractedSecret {
                    secret_type: "Google API Key".to_string(),
                    matched_value: cap.as_str().to_string(),
                    confidence: "HIGH".to_string(),
                    description: "Hardcoded Google Cloud API Key identified in application strings.".to_string(),
                });
            }
        }

        // 2. Firebase Database URLs
        if let Ok(re_firebase) = Regex::new(r"https?://[a-zA-Z0-9\-_]+\.firebaseio\.com") {
            for cap in re_firebase.find_iter(raw_text_content) {
                let url = cap.as_str().to_string();
                leaked_secrets.push(ExtractedSecret {
                    secret_type: "Firebase Realtime Database".to_string(),
                    matched_value: url.clone(),
                    confidence: "CRITICAL".to_string(),
                    description: "Firebase database reference. Potential for unauthenticated .json exposure.".to_string(),
                });
                extracted_endpoints.push(url);
            }
        }

        // 3. AWS Access Key ID
        if let Ok(re_aws) = Regex::new(r"AKIA[0-9A-Z]{16}") {
            for cap in re_aws.find_iter(raw_text_content) {
                leaked_secrets.push(ExtractedSecret {
                    secret_type: "AWS Access Key".to_string(),
                    matched_value: cap.as_str().to_string(),
                    confidence: "HIGH".to_string(),
                    description: "Hardcoded AWS IAM Access Key ID detected.".to_string(),
                });
            }
        }

        // 4. S3 Buckets
        if let Ok(re_s3) = Regex::new(r"https?://[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com") {
            for cap in re_s3.find_iter(raw_text_content) {
                let url = cap.as_str().to_string();
                extracted_endpoints.push(url);
            }
        }

        // 5. Backend APIs & Endpoints extraction
        if let Ok(re_api) = Regex::new(r"https?://[a-zA-Z0-9.\-_]+(:[0-9]+)?/[a-zA-Z0-9_\-/.?=&%]*") {
            for cap in re_api.find_iter(raw_text_content) {
                let url = cap.as_str().to_string();
                if !url.contains("schemas.android.com") && !url.contains("w3.org") {
                    extracted_endpoints.push(url);
                }
            }
        }

        // 6. Check Insecure Cleartext Traffic / Exported settings
        if raw_text_content.contains("android:usesCleartextTraffic=\"true\"") {
            insecure_configurations.push("Cleartext HTTP traffic explicitly enabled in manifest".to_string());
        }
        if raw_text_content.contains("android:exported=\"true\"") {
            insecure_configurations.push("Exported Android components detected in manifest".to_string());
        }

        // Deduplicate extracted endpoints and filter strictly via ScopeGuard
        let deduped_endpoints = Deduplicator::deduplicate_strings(&extracted_endpoints);
        let in_scope_endpoints = scope_guard.filter_in_scope(&deduped_endpoints);

        debug!(
            "Mobile analysis for '{}' found {} secrets and {} in-scope endpoints.",
            app_identifier,
            leaked_secrets.len(),
            in_scope_endpoints.len()
        );

        Ok(MobileAnalysisResult {
            app_identifier: app_identifier.to_string(),
            platform: platform.to_string(),
            extracted_endpoints: in_scope_endpoints,
            leaked_secrets,
            insecure_configurations,
            raw_telemetry: raw_text_content.chars().take(2000).collect(),
        })
    }
}
