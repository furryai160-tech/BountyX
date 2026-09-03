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

        // Sensitive Configuration / Source Code Exposure Probes
        let sensitive_probes = [
            ("/.git/HEAD", "Exposed Git Repository", "Potential leakage of source code and commits history via public .git folder."),
            ("/.env", "Exposed Environment Configuration", "Potential leakage of database credentials and API secrets in web root."),
            ("/swagger.json", "Exposed Swagger/OpenAPI Documentation", "Publicly accessible API schema detailing hidden endpoints and parameters."),
        ];

        for (idx, (probe_path, title, premise)) in sensitive_probes.iter().enumerate() {
            hypotheses.push(SecurityHypothesis {
                id: format!("hyp-sens-{}", idx + 1),
                category: "Sensitive Information Disclosure".to_string(),
                title: format!("{} on {}", title, probe_path),
                target_url: format!("{}{}", base_url.trim_end_matches('/'), probe_path),
                method: "GET".to_string(),
                premise: premise.to_string(),
                test_action: format!("Send GET request to {} and inspect status code and body for signature keywords.", probe_path),
                expected_secure_behavior: "HTTP 404 Not Found or HTTP 403 Forbidden.".to_string(),
                potential_impact: "Critical exposure of internal credentials or system architecture.".to_string(),
            });
        }

        // Clickjacking / Frame Protection Audit on main URL
        hypotheses.push(SecurityHypothesis {
            id: "hyp-clickjack-1".to_string(),
            category: "Missing Security Headers (Clickjacking)".to_string(),
            title: "Missing X-Frame-Options Header Verification".to_string(),
            target_url: base_url.trim_end_matches('/').to_string(),
            method: "GET".to_string(),
            premise: "Web application interfaces rendered without X-Frame-Options or Content-Security-Policy frame-ancestors can be embedded in malicious iframes.".to_string(),
            test_action: "Inspect HTTP response headers of root landing page for framing restrictions.".to_string(),
            expected_secure_behavior: "X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors 'self' header present.".to_string(),
            potential_impact: "UI redressing / clickjacking leading to unauthorized user actions.".to_string(),
        });

        hypotheses
    }
}

