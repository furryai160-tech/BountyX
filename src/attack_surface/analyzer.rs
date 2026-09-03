use crate::attack_surface::graph::{AttackSurfaceGraph, AttackSurfaceNode, NodeType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighRiskCandidate {
    pub endpoint_id: String,
    pub path: String,
    pub method: String,
    pub risk_reason: String,
    pub suggested_test: String,
}

pub struct AttackSurfaceAnalyzer;

impl AttackSurfaceAnalyzer {
    pub fn find_high_risk_candidates(graph: &AttackSurfaceGraph) -> Vec<HighRiskCandidate> {
        let mut candidates = Vec::new();
        let endpoints = graph.get_endpoints();

        for ep in endpoints {
            if let NodeType::Endpoint { ref path, ref method } = ep.node_type {
                let params = graph.get_parameters_for_endpoint(&ep.id);
                let p_lower = path.to_lowercase();

                // 1. Check for IDOR / BOLA candidates (endpoints taking ID parameters)
                let id_params: Vec<_> = params
                    .iter()
                    .filter(|p| {
                        if let NodeType::Parameter { ref name, .. } = p.node_type {
                            let n = name.to_lowercase();
                            n == "id" || n.ends_with("_id") || n == "uuid" || n == "account" || n == "order"
                        } else {
                            false
                        }
                    })
                    .collect();

                if !id_params.is_empty() {
                    candidates.push(HighRiskCandidate {
                        endpoint_id: ep.id.clone(),
                        path: path.clone(),
                        method: method.clone(),
                        risk_reason: format!("Endpoint consumes object identifier(s): {}", id_params.len()),
                        suggested_test: "Broken Object Level Authorization (BOLA/IDOR) Test".to_string(),
                    });
                }

                // 2. Check for Auth & Sensitive Administrative Paths
                if p_lower.contains("/admin")
                    || p_lower.contains("/internal")
                    || p_lower.contains("/v1/debug")
                    || p_lower.contains("/actuator")
                    || p_lower.contains("/graphql")
                {
                    candidates.push(HighRiskCandidate {
                        endpoint_id: ep.id.clone(),
                        path: path.clone(),
                        method: method.clone(),
                        risk_reason: "Privileged / Internal endpoint exposed in attack surface".to_string(),
                        suggested_test: "Authentication Bypass & Sensitive Data Exposure Test".to_string(),
                    });
                }
            }
        }

        candidates
    }
}
