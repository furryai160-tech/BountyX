use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub finding_id: String,
    pub timestamp: DateTime<Utc>,
    pub target_url: String,
    pub method: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_snippet: String,
    pub reproduction_curl: String,
    pub differential_notes: String,
}

pub struct SecretRedactor;

impl SecretRedactor {
    pub fn redact_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut redacted = HashMap::new();
        for (k, v) in headers {
            let k_lower = k.to_lowercase();
            if k_lower == "authorization"
                || k_lower == "cookie"
                || k_lower == "set-cookie"
                || k_lower == "x-api-key"
                || k_lower == "x-auth-token"
                || k_lower == "proxy-authorization"
            {
                redacted.insert(k.clone(), "[REDACTED_BY_BOUNTYX_SAFETY]".to_string());
            } else {
                redacted.insert(k.clone(), v.clone());
            }
        }
        redacted
    }

    pub fn redact_snippet(text: &str) -> String {
        // Redact potential Bearer tokens or secret keys in snippet
        let re_bearer = regex::Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}").unwrap();
        let s = re_bearer.replace_all(text, "Bearer [REDACTED_TOKEN]");

        // Cap length to 2048 chars for clean report readability
        if s.len() > 2048 {
            format!("{}... [Truncated for brevity]", &s[..2048])
        } else {
            s.to_string()
        }
    }
}
