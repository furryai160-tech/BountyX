use crate::errors::{BountyScopeError, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopePolicy {
    pub name: String,
    pub description: Option<String>,
    pub target_program: Option<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default = "default_max_requests")]
    pub max_requests: usize,
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default)]
    pub testing_restrictions: Vec<String>,
    #[serde(default)]
    pub custom_headers: std::collections::HashMap<String, String>,
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "PATCH".to_string(),
        "DELETE".to_string(),
        "HEAD".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_max_requests() -> usize {
    5000
}

fn default_rate_limit_rps() -> u32 {
    10
}

fn default_request_timeout_seconds() -> u64 {
    30
}

impl ScopePolicy {
    pub fn from_yaml_str(yaml_content: &str) -> Result<Self> {
        serde_yaml::from_str(yaml_content).map_err(|e| {
            BountyScopeError::Config(format!("Failed to parse ScopePolicy YAML: {}", e))
        })
    }

    pub fn from_json_str(json_content: &str) -> Result<Self> {
        serde_json::from_str(json_content).map_err(|e| {
            BountyScopeError::Config(format!("Failed to parse ScopePolicy JSON: {}", e))
        })
    }

    pub fn new_permissive(target: &str) -> Self {
        let domain = target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target)
            .split(':')
            .next()
            .unwrap_or(target)
            .to_string();

        let wildcard = if domain.starts_with("*.") {
            domain.clone()
        } else {
            format!("*.{}", domain)
        };

        Self {
            name: format!("Auto-Scope for {}", domain),
            description: Some("Autonomous scope generated for authorized assessment".to_string()),
            target_program: Some(domain.clone()),
            allowed_domains: vec![domain, wildcard],
            allowed_cidrs: Vec::new(),
            allowed_methods: default_allowed_methods(),
            excluded_paths: vec![
                "/logout".to_string(),
                "/signout".to_string(),
                "/auth/logout".to_string(),
                "/admin/delete".to_string(),
                "/user/delete".to_string(),
            ],
            allowed_paths: Vec::new(),
            max_requests: 2000,
            rate_limit_rps: 8,
            request_timeout_seconds: 25,
            testing_restrictions: vec![
                "No automated denial of service tests".to_string(),
                "No destructive delete payloads".to_string(),
            ],
            custom_headers: std::collections::HashMap::new(),
        }
    }

    pub fn validate_ip_in_cidrs(&self, ip: &IpAddr) -> bool {
        for cidr_str in &self.allowed_cidrs {
            if let Ok(net) = IpNet::from_str(cidr_str) {
                if net.contains(ip) {
                    return true;
                }
            }
        }
        false
    }
}
