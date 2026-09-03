use crate::ai::memory::AgentMemory;
use crate::attack_surface::analyzer::AttackSurfaceAnalyzer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHypothesis {
    pub id: String,
    pub category: String,
    pub title: String,
    pub target_url: String,
    pub method: String,
    pub premise: String,
    pub test_action: String,
    pub expected_secure_behavior: String,
    pub potential_impact: String,
}

pub struct AgentPlanner;

impl AgentPlanner {
    pub fn formulate_hypotheses(base_url: &str, memory: &AgentMemory) -> Vec<SecurityHypothesis> {
        let mut hypotheses = Vec::new();
        let high_risk_candidates = AttackSurfaceAnalyzer::find_high_risk_candidates(&memory.assessment.graph);

        for (idx, candidate) in high_risk_candidates.iter().enumerate() {
            let full_url = format!("{}{}", base_url.trim_end_matches('/'), candidate.path);

            if candidate.risk_reason.contains("object identifier") {
                hypotheses.push(SecurityHypothesis {
                    id: format!("hyp-bola-{}", idx + 1),
                    category: "Broken Access Control (BOLA/IDOR)".to_string(),
                    title: format!("BOLA authorization test on {}", candidate.path),
                    target_url: full_url.clone(),
                    method: candidate.method.clone(),
                    premise: "Endpoint processes sensitive object IDs. If server relies solely on the ID without verifying caller tenancy, unauthorized data access occurs.".to_string(),
                    test_action: "Send request without credentials or with manipulated ID token and measure differential against authorized baseline.".to_string(),
                    expected_secure_behavior: "HTTP 401 Unauthorized or HTTP 403 Forbidden with zero sensitive record leakage.".to_string(),
                    potential_impact: "Unauthorized disclosure or modification of tenant records.".to_string(),
                });
            }

            if candidate.risk_reason.contains("Privileged") {
                hypotheses.push(SecurityHypothesis {
                    id: format!("hyp-priv-{}", idx + 1),
                    category: "Authentication Bypass".to_string(),
                    title: format!("Administrative route exposure on {}", candidate.path),
                    target_url: full_url.clone(),
                    method: candidate.method.clone(),
                    premise: "Administrative path discovered in attack surface may lack strict access control enforcement.".to_string(),
                    test_action: "Probe path without authentication headers and inspect response body for administrative data.".to_string(),
                    expected_secure_behavior: "HTTP 401/403 or immediate redirect to login portal.".to_string(),
                    potential_impact: "Direct access to internal management or telemetry systems.".to_string(),
                });
            }
        }

        // Also add CORS hypothesis for discovered API endpoints
        if let Some(first_ep) = memory.assessment.graph.get_endpoints().first() {
            if let crate::attack_surface::graph::NodeType::Endpoint { ref path, ref method } = first_ep.node_type {
                hypotheses.push(SecurityHypothesis {
                    id: "hyp-cors-1".to_string(),
                    category: "Security Misconfiguration (CORS)".to_string(),
                    title: format!("CORS Origin Reflection Test on {}", path),
                    target_url: format!("{}{}", base_url.trim_end_matches('/'), path),
                    method: method.clone(),
                    premise: "API endpoints may reflect arbitrary Origin headers with Access-Control-Allow-Credentials: true.".to_string(),
                    test_action: "Send request with Origin: https://bountyx-test.com and check CORS headers.".to_string(),
                    expected_secure_behavior: "No Access-Control-Allow-Origin header returned, or static trusted domain without wildcards.".to_string(),
                    potential_impact: "Cross-domain credentialed data exfiltration via attacker website.".to_string(),
                });
            }
        }

        hypotheses
    }
}
