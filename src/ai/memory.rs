use crate::attack_surface::graph::AttackSurfaceGraph;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeRule {
    pub category: String,
    pub title: String,
    pub description: String,
    pub test_heuristic: String,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct SecurityKnowledgeBase {
    pub rules: Vec<KnowledgeRule>,
}

impl SecurityKnowledgeBase {
    pub fn default_owasp() -> Self {
        Self {
            rules: vec![
                KnowledgeRule {
                    category: "Broken Access Control / BOLA".to_string(),
                    title: "Missing Object-Level Authorization".to_string(),
                    description: "User A can access or manipulate User B's resource by altering the object identifier in the request.".to_string(),
                    test_heuristic: "Query endpoint with modified ID under unauthorized or unauthenticated context and compare response differential.".to_string(),
                    remediation: "Implement strict tenancy and record-level ownership checks on all data access queries.".to_string(),
                },
                KnowledgeRule {
                    category: "Security Misconfiguration".to_string(),
                    title: "Permissive Cross-Origin Resource Sharing (CORS)".to_string(),
                    description: "Origin reflection combined with Access-Control-Allow-Credentials: true permits arbitrary sites to read authenticated responses.".to_string(),
                    test_heuristic: "Send custom Origin: https://evil.com and inspect Access-Control-Allow-Origin and Allow-Credentials.".to_string(),
                    remediation: "Whitelist trusted origins strictly and never reflect untrusted origins when credentials are supported.".to_string(),
                },
                KnowledgeRule {
                    category: "Authentication Weakness".to_string(),
                    title: "Exposed Unauthenticated Sensitive/Admin Route".to_string(),
                    description: "Internal metrics, administration interfaces, or debug APIs exposed publicly without session checks.".to_string(),
                    test_heuristic: "Access administrative/internal path without session token and verify if response returns privileged data.".to_string(),
                    remediation: "Enforce gateway-level authentication and IP-allowlisting on all internal and debug endpoints.".to_string(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShortTermMemory {
    pub active_hypothesis: Option<String>,
    pub last_request_url: Option<String>,
    pub last_status_code: Option<u16>,
    pub observations: Vec<String>,
}

pub struct AssessmentMemory {
    pub graph: AttackSurfaceGraph,
    pub tested_endpoints: HashMap<String, usize>,
    pub discovered_anomalies: Vec<String>,
}

impl AssessmentMemory {
    pub fn new() -> Self {
        Self {
            graph: AttackSurfaceGraph::new(),
            tested_endpoints: HashMap::new(),
            discovered_anomalies: Vec::new(),
        }
    }
}

impl Default for AssessmentMemory {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AgentMemory {
    pub short_term: ShortTermMemory,
    pub assessment: AssessmentMemory,
    pub knowledge: SecurityKnowledgeBase,
}

impl AgentMemory {
    pub fn new() -> Self {
        Self {
            short_term: ShortTermMemory::default(),
            assessment: AssessmentMemory::new(),
            knowledge: SecurityKnowledgeBase::default_owasp(),
        }
    }
}

impl Default for AgentMemory {
    fn default() -> Self {
        Self::new()
    }
}
