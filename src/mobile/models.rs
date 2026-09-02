use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedSecret {
    pub secret_type: String,
    pub matched_value: String,
    pub confidence: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileAnalysisResult {
    pub app_identifier: String,
    pub platform: String, // Android / iOS
    pub extracted_endpoints: Vec<String>,
    pub leaked_secrets: Vec<ExtractedSecret>,
    pub insecure_configurations: Vec<String>,
    pub raw_telemetry: String,
}
