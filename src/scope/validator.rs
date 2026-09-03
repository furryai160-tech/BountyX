use crate::scope::policy::ScopePolicy;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeViolation {
    InvalidUrl(String),
    OutOfScopeDomain { host: String },
    OutOfScopeIp { ip: String },
    ForbiddenPath { path: String, rule: String },
    DisallowedMethod { method: String },
    BudgetExceeded { current: usize, max: usize },
    RateLimited { rps: u32 },
    TestingRestrictionViolated(String),
}

impl std::fmt::Display for ScopeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(err) => write!(f, "Invalid URL format: {}", err),
            Self::OutOfScopeDomain { host } => write!(f, "Host '{}' is strictly out of authorized scope", host),
            Self::OutOfScopeIp { ip } => write!(f, "IP '{}' is not contained within authorized CIDRs", ip),
            Self::ForbiddenPath { path, rule } => write!(f, "Path '{}' is blocked by exclusion rule '{}'", path, rule),
            Self::DisallowedMethod { method } => write!(f, "HTTP Method '{}' is not permitted by policy", method),
            Self::BudgetExceeded { current, max } => write!(f, "Assessment request budget exceeded ({}/{})", current, max),
            Self::RateLimited { rps } => write!(f, "Rate limit exceeded (Max: {} req/s)", rps),
            Self::TestingRestrictionViolated(msg) => write!(f, "Testing restriction violated: {}", msg),
        }
    }
}

pub struct ScopeValidator;

impl ScopeValidator {
    pub fn is_host_allowed(host: &str, policy: &ScopePolicy) -> bool {
        let clean_host = host.to_lowercase();
        let clean_host = clean_host.trim_end_matches('.');

        // 1. Check direct IP against CIDRs
        if let Ok(ip) = IpAddr::from_str(&clean_host) {
            if policy.validate_ip_in_cidrs(&ip) {
                return true;
            }
        }


        // 2. Check domain rules
        for rule in &policy.allowed_domains {
            let clean_rule = rule.to_lowercase();
            let clean_rule = clean_rule.trim_end_matches('.');

            // Exact match
            if clean_host == clean_rule {
                return true;
            }

            // Wildcard match (*.example.com)
            if let Some(suffix) = clean_rule.strip_prefix("*.") {
                if clean_host == suffix || clean_host.ends_with(&format!(".{}", suffix)) {
                    return true;
                }
            }

            // Subdomain match (example.com allows sub.example.com if configured)
            if clean_host.ends_with(&format!(".{}", clean_rule)) {
                return true;
            }
        }

        false
    }

    pub fn is_path_allowed(path: &str, policy: &ScopePolicy) -> Result<(), ScopeViolation> {
        let clean_path = if path.is_empty() { "/" } else { path };

        // 1. Check excluded paths first (highest priority safety)
        for excluded in &policy.excluded_paths {
            if clean_path.starts_with(excluded) || clean_path == excluded {
                return Err(ScopeViolation::ForbiddenPath {
                    path: clean_path.to_string(),
                    rule: excluded.clone(),
                });
            }
        }

        // 2. Check allowed paths if non-empty
        if !policy.allowed_paths.is_empty() {
            let is_in_allowed = policy.allowed_paths.iter().any(|allowed| {
                clean_path.starts_with(allowed) || clean_path == allowed
            });
            if !is_in_allowed {
                return Err(ScopeViolation::ForbiddenPath {
                    path: clean_path.to_string(),
                    rule: "Allowed paths whitelist constraint".to_string(),
                });
            }
        }

        Ok(())
    }

    pub fn is_method_allowed(method: &str, policy: &ScopePolicy) -> Result<(), ScopeViolation> {
        let m_upper = method.to_uppercase();
        if policy.allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(&m_upper)) {
            Ok(())
        } else {
            Err(ScopeViolation::DisallowedMethod { method: m_upper })
        }
    }

    pub fn validate_url(url_str: &str, method: &str, policy: &ScopePolicy) -> Result<(), ScopeViolation> {
        // Method validation
        Self::is_method_allowed(method, policy)?;

        // URL parsing
        let parsed_url = Url::parse(url_str).map_err(|e| ScopeViolation::InvalidUrl(e.to_string()))?;
        let host = parsed_url.host_str().ok_or_else(|| {
            ScopeViolation::InvalidUrl("Missing host component in target URL".to_string())
        })?;

        // Host validation
        if !Self::is_host_allowed(host, policy) {
            return Err(ScopeViolation::OutOfScopeDomain {
                host: host.to_string(),
            });
        }

        // Path validation
        Self::is_path_allowed(parsed_url.path(), policy)?;

        Ok(())
    }
}
