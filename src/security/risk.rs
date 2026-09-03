use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Informational => write!(f, "INFORMATIONAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub severity: Severity,
    pub cvss_score: f32,
    pub impact_score: u8,        // 1 - 10
    pub confidence_score: u8,    // 0 - 100%
    pub reasoning: String,
}

pub struct RiskEngine;

impl RiskEngine {
    pub fn calculate(category: &str, is_reproduced: bool, body_reveals_sensitive_data: bool) -> RiskAssessment {
        let cat_lower = category.to_lowercase();

        if cat_lower.contains("bola") || cat_lower.contains("idor") {
            let (severity, cvss, impact, conf) = if is_reproduced && body_reveals_sensitive_data {
                (Severity::High, 8.5, 9, 95)
            } else if is_reproduced {
                (Severity::Medium, 6.5, 6, 85)
            } else {
                (Severity::Low, 4.0, 4, 60)
            };

            RiskAssessment {
                severity,
                cvss_score: cvss,
                impact_score: impact,
                confidence_score: conf,
                reasoning: "Object-level authorization boundary was probed. The response differential confirmed unauthorized resource retrieval under unauthenticated or cross-tenant context.".to_string(),
            }
        } else if cat_lower.contains("cors") {
            let (severity, cvss, impact, conf) = if is_reproduced {
                (Severity::Medium, 6.5, 7, 90)
            } else {
                (Severity::Low, 3.5, 3, 65)
            };

            RiskAssessment {
                severity,
                cvss_score: cvss,
                impact_score: impact,
                confidence_score: conf,
                reasoning: "CORS configuration reflected untrusted origins with credential support enabled, permitting cross-site data theft.".to_string(),
            }
        } else if cat_lower.contains("admin") || cat_lower.contains("authentication") {
            let (severity, cvss, impact, conf) = if is_reproduced {
                (Severity::High, 8.0, 8, 92)
            } else {
                (Severity::Medium, 5.5, 5, 70)
            };

            RiskAssessment {
                severity,
                cvss_score: cvss,
                impact_score: impact,
                confidence_score: conf,
                reasoning: "Privileged/Administrative path accessible without strict identity authentication verification.".to_string(),
            }
        } else {
            RiskAssessment {
                severity: Severity::Low,
                cvss_score: 3.5,
                impact_score: 3,
                confidence_score: if is_reproduced { 80 } else { 50 },
                reasoning: "Heuristic anomaly observed in application behavior under test conditions.".to_string(),
            }
        }
    }
}
