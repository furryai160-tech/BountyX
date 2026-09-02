use crate::scanner::severity::Severity;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiFinding {
    pub template_id: String,
    pub template_name: String,
    pub severity: Severity,
    pub matched_at: String,
    pub host: String,
    pub matcher_name: Option<String>,
    pub description: Option<String>,
    pub extracted_results: Vec<String>,
    pub curl_command: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub raw_json: String,
}

#[derive(Debug, Deserialize)]
struct RawNucleiJson {
    #[serde(rename = "template-id", alias = "templateID", alias = "template_id")]
    pub template_id: Option<String>,
    pub info: Option<RawNucleiInfo>,
    #[serde(rename = "matched-at", alias = "matched", alias = "matched_at")]
    pub matched_at: Option<String>,
    pub host: Option<String>,
    #[serde(rename = "matcher-name", alias = "matcher_name")]
    pub matcher_name: Option<String>,
    #[serde(rename = "extracted-results", alias = "extracted_results")]
    pub extracted_results: Option<Vec<String>>,
    #[serde(rename = "curl-command", alias = "curl_command")]
    pub curl_command: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawNucleiInfo {
    pub name: Option<String>,
    pub severity: Option<String>,
    pub description: Option<String>,
}

pub struct NucleiParser;

impl NucleiParser {
    pub fn parse_line(line: &str) -> Option<NucleiFinding> {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            return None;
        }

        let raw: RawNucleiJson = serde_json::from_str(trimmed).ok()?;
        let template_id = raw.template_id.unwrap_or_else(|| "unknown-template".to_string());
        
        let info = raw.info.unwrap_or(RawNucleiInfo {
            name: None,
            severity: None,
            description: None,
        });

        let template_name = info.name.unwrap_or_else(|| template_id.clone());
        let severity_str = info.severity.unwrap_or_else(|| "medium".to_string());
        let severity = Severity::from_str(&severity_str).unwrap_or(Severity::Medium);

        let matched_at = raw.matched_at.unwrap_or_else(|| raw.host.clone().unwrap_or_default());
        let host = raw.host.unwrap_or_else(|| matched_at.clone());

        Some(NucleiFinding {
            template_id,
            template_name,
            severity,
            matched_at,
            host,
            matcher_name: raw.matcher_name,
            description: info.description,
            extracted_results: raw.extracted_results.unwrap_or_default(),
            curl_command: raw.curl_command,
            request: raw.request,
            response: raw.response,
            raw_json: trimmed.to_string(),
        })
    }
}
