use crate::errors::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SastFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub matched_secret: String,
    pub file_path: Option<String>,
    pub line_number: Option<usize>,
    pub remediation: String,
}

pub struct SastScanner;

impl SastScanner {
    pub fn scan_content(target_name: &str, content: &str) -> Result<Vec<SastFinding>> {
        info!("Running SAST & Secret Scanner on target: '{}'", target_name);
        let mut findings = Vec::new();

        // 1. Private RSA/EC Keys
        if let Ok(re_key) = Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----") {
            if re_key.is_match(content) {
                findings.push(SastFinding {
                    rule_id: "sec-leak-private-key".to_string(),
                    title: "Exposed Cryptographic Private Key".to_string(),
                    severity: "CRITICAL".to_string(),
                    matched_secret: "[REDACTED_PRIVATE_KEY_HEADER]".to_string(),
                    file_path: None,
                    line_number: None,
                    remediation: "Revoke the private key immediately and rotate all certificates and authentication tokens relying on it.".to_string(),
                });
            }
        }

        // 2. Slack Webhooks
        if let Ok(re_slack) = Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+") {
            for cap in re_slack.find_iter(content) {
                findings.push(SastFinding {
                    rule_id: "sec-leak-slack-webhook".to_string(),
                    title: "Exposed Slack Incoming Webhook".to_string(),
                    severity: "HIGH".to_string(),
                    matched_secret: cap.as_str().to_string(),
                    file_path: None,
                    line_number: None,
                    remediation: "Delete the exposed webhook URL in Slack settings and configure environment variable secrets.".to_string(),
                });
            }
        }

        // 3. GitHub Personal Access Tokens (PAT)
        if let Ok(re_ghp) = Regex::new(r"ghp_[0-9a-zA-Z]{36}") {
            for cap in re_ghp.find_iter(content) {
                findings.push(SastFinding {
                    rule_id: "sec-leak-github-pat".to_string(),
                    title: "Exposed GitHub Personal Access Token".to_string(),
                    severity: "CRITICAL".to_string(),
                    matched_secret: cap.as_str().to_string(),
                    file_path: None,
                    line_number: None,
                    remediation: "Revoke the GitHub Personal Access Token from GitHub developer settings immediately.".to_string(),
                });
            }
        }

        // 4. Database Connection Strings (PostgreSQL, MySQL, MongoDB)
        if let Ok(re_db) = Regex::new(r#"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_]+:[^"'\s<>]+@[a-zA-Z0-9.\-_]+(?::[0-9]+)?\/[a-zA-Z0-9_\-]+"#) {
            for cap in re_db.find_iter(content) {
                findings.push(SastFinding {
                    rule_id: "sec-leak-db-connection-string".to_string(),
                    title: "Hardcoded Database Connection String with Credentials".to_string(),
                    severity: "CRITICAL".to_string(),
                    matched_secret: cap.as_str().to_string(),
                    file_path: None,
                    line_number: None,
                    remediation: "Rotate database user password immediately and use secrets manager or secure environment variables.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}
