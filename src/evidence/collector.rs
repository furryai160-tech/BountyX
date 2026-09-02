use crate::scanner::NucleiFinding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedEvidence {
    pub target: String,
    pub matched_url: String,
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub curl_command: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub extracted_data: Vec<String>,
    pub raw_scanner_output: String,
}

pub struct EvidenceCollector;

impl EvidenceCollector {
    pub fn from_nuclei_finding(target: &str, finding: &NucleiFinding) -> CollectedEvidence {
        CollectedEvidence {
            target: target.to_string(),
            matched_url: finding.matched_at.clone(),
            template_id: finding.template_id.clone(),
            template_name: finding.template_name.clone(),
            severity: finding.severity.to_string(),
            curl_command: finding.curl_command.clone(),
            request: finding.request.clone(),
            response: finding.response.clone(),
            extracted_data: finding.extracted_results.clone(),
            raw_scanner_output: finding.raw_json.clone(),
        }
    }
}
