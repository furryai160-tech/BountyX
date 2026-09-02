use crate::database::repository::Repository;
use crate::errors::{BountyScopeError, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRule {
    WildcardDomain(String),
    ExactDomain(String),
    Cidr(IpNet),
    UrlPrefix(String),
}

#[derive(Debug, Clone, Default)]
pub struct ScopeGuard {
    in_scope_rules: Vec<ScopeRule>,
    out_of_scope_rules: Vec<ScopeRule>,
}

impl ScopeGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_rules(in_scope: &[String], out_of_scope: &[String]) -> Self {
        let mut guard = Self::new();
        for rule_str in in_scope {
            if let Some(rule) = Self::parse_rule(rule_str) {
                guard.in_scope_rules.push(rule);
            }
        }
        for rule_str in out_of_scope {
            if let Some(rule) = Self::parse_rule(rule_str) {
                guard.out_of_scope_rules.push(rule);
            }
        }
        guard
    }

    pub fn add_in_scope(&mut self, target: &str) {
        if let Some(rule) = Self::parse_rule(target) {
            self.in_scope_rules.push(rule);
        }
    }

    pub fn add_out_of_scope(&mut self, target: &str) {
        if let Some(rule) = Self::parse_rule(target) {
            self.out_of_scope_rules.push(rule);
        }
    }

    pub fn total_in_scope_rules(&self) -> usize {
        self.in_scope_rules.len()
    }

    pub fn parse_rule(raw: &str) -> Option<ScopeRule> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        // 1. Try CIDR / IP
        if let Ok(net) = IpNet::from_str(trimmed) {
            return Some(ScopeRule::Cidr(net));
        }
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            let net = match ip {
                IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::new(v4, 32).ok()?),
                IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::new(v6, 128).ok()?),
            };
            return Some(ScopeRule::Cidr(net));
        }

        // 2. Try URL Prefix if it has http:// or https://
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            if let Ok(parsed_url) = Url::parse(trimmed) {
                let path = parsed_url.path();
                if path != "/" && !path.is_empty() {
                    return Some(ScopeRule::UrlPrefix(trimmed.to_lowercase()));
                }
                if let Some(host) = parsed_url.host_str() {
                    return Self::parse_domain_rule(host);
                }
            }
        }

        // 3. Domain or Wildcard
        Self::parse_domain_rule(trimmed)
    }

    fn parse_domain_rule(raw: &str) -> Option<ScopeRule> {
        let clean = raw
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()?
            .split(':')
            .next()?
            .to_lowercase();

        if clean.starts_with("*.") {
            let base = clean.trim_start_matches("*.").to_string();
            if !base.is_empty() {
                Some(ScopeRule::WildcardDomain(base))
            } else {
                None
            }
        } else if clean.starts_with('.') {
            let base = clean.trim_start_matches('.').to_string();
            if !base.is_empty() {
                Some(ScopeRule::WildcardDomain(base))
            } else {
                None
            }
        } else {
            Some(ScopeRule::ExactDomain(clean))
        }
    }

    /// Normalize an arbitrary input string (URL, host, IP) into a host/IP string for evaluation
    pub fn normalize_target(input: &str) -> String {
        let lower = input.trim().to_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            if let Ok(url) = Url::parse(&lower) {
                if let Some(host) = url.host_str() {
                    return host.to_string();
                }
            }
        }
        lower
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .trim_start_matches("*.")
            .to_string()
    }

    /// Strict Gate: Returns Ok(normalized_target) if in scope, otherwise Err(BountyScopeError::ScopeViolation)
    pub fn validate_target(&self, input: &str) -> Result<String> {
        let normalized = Self::normalize_target(input);
        if normalized.is_empty() {
            return Err(BountyScopeError::ScopeViolation {
                target: input.to_string(),
                reason: "Empty or invalid target host".to_string(),
            });
        }

        if !self.is_in_scope(input) {
            warn!(
                target: "scope_guard",
                "SECURITY GATE: Blocked out-of-scope target: '{}' (normalized: '{}')",
                input,
                normalized
            );
            return Err(BountyScopeError::ScopeViolation {
                target: input.to_string(),
                reason: "Target does not match any authorized in-scope asset or matches out-of-scope exclusions".to_string(),
            });
        }

        Ok(normalized)
    }

    /// Strict Gate with Audit Log recording
    pub async fn validate_target_with_audit(
        &self,
        input: &str,
        tool: Option<&str>,
        repo: Option<&Repository>,
    ) -> Result<String> {
        let normalized = Self::normalize_target(input);
        if normalized.is_empty() {
            if let Some(r) = repo {
                let _ = r
                    .record_audit_event(
                        "SCOPE_EVALUATION",
                        input,
                        "BLOCKED",
                        "Empty or invalid target format",
                        tool,
                        None,
                    )
                    .await;
            }
            return Err(BountyScopeError::ScopeViolation {
                target: input.to_string(),
                reason: "Empty or invalid target host".to_string(),
            });
        }

        if !self.is_in_scope(input) {
            warn!(
                target: "scope_guard",
                "SECURITY GATE: Blocked out-of-scope target: '{}' (normalized: '{}')",
                input,
                normalized
            );
            if let Some(r) = repo {
                let _ = r
                    .record_audit_event(
                        "SCOPE_EVALUATION",
                        input,
                        "BLOCKED",
                        "Target does not match authorized scope rules",
                        tool,
                        None,
                    )
                    .await;
            }
            return Err(BountyScopeError::ScopeViolation {
                target: input.to_string(),
                reason: "Target does not match any authorized in-scope asset".to_string(),
            });
        }

        if let Some(r) = repo {
            let _ = r
                .record_audit_event(
                    "SCOPE_EVALUATION",
                    input,
                    "AUTHORIZED",
                    "Target verified against active scope policy",
                    tool,
                    None,
                )
                .await;
        }

        Ok(normalized)
    }

    /// Validates an HTTP redirect target against authorized scope
    pub async fn validate_redirect(
        &self,
        original_url: &str,
        redirect_url: &str,
        repo: Option<&Repository>,
    ) -> Result<String> {
        let normalized_redirect = Self::normalize_target(redirect_url);

        if !self.is_in_scope(redirect_url) {
            warn!(
                target: "scope_guard",
                "REDIRECT SECURITY GATE: Blocked unauthorized redirect from '{}' to '{}'",
                original_url,
                redirect_url
            );

            if let Some(r) = repo {
                let metadata = serde_json::json!({
                    "original_url": original_url,
                    "redirect_url": redirect_url,
                })
                .to_string();

                let _ = r
                    .record_audit_event(
                        "REDIRECT_CHECK",
                        redirect_url,
                        "BLOCKED",
                        "Redirect destination is outside authorized scope",
                        Some("httpx"),
                        Some(&metadata),
                    )
                    .await;
            }

            return Err(BountyScopeError::ScopeViolation {
                target: redirect_url.to_string(),
                reason: format!("Unauthorized external redirect from '{}'", original_url),
            });
        }

        if let Some(r) = repo {
            let _ = r
                .record_audit_event(
                    "REDIRECT_CHECK",
                    redirect_url,
                    "AUTHORIZED",
                    "Redirect destination is within authorized scope",
                    Some("httpx"),
                    None,
                )
                .await;
        }

        Ok(normalized_redirect)
    }

    /// Checks whether an input (URL, domain, IP) is strictly in-scope and not excluded.
    pub fn is_in_scope(&self, input: &str) -> bool {
        let trimmed = input.trim();
        if trimmed.is_empty() || self.in_scope_rules.is_empty() {
            return false;
        }

        // 1. Check if it matches explicit out-of-scope rules (Hard Drop)
        if self.matches_any_rule(trimmed, &self.out_of_scope_rules) {
            debug!("Target '{}' matches explicit out-of-scope rule.", trimmed);
            return false;
        }

        // 2. Check if it matches in-scope rules
        self.matches_any_rule(trimmed, &self.in_scope_rules)
    }

    fn matches_any_rule(&self, input: &str, rules: &[ScopeRule]) -> bool {
        let normalized_host = Self::normalize_target(input);
        let parsed_ip = IpAddr::from_str(&normalized_host).ok();
        let input_lower = input.to_lowercase();

        for rule in rules {
            match rule {
                ScopeRule::ExactDomain(domain) => {
                    if normalized_host == *domain {
                        return true;
                    }
                }
                ScopeRule::WildcardDomain(domain) => {
                    if normalized_host == *domain
                        || normalized_host.ends_with(&format!(".{}", domain))
                    {
                        return true;
                    }
                }
                ScopeRule::Cidr(net) => {
                    if let Some(ip) = parsed_ip {
                        if net.contains(&ip) {
                            return true;
                        }
                    }
                }
                ScopeRule::UrlPrefix(prefix) => {
                    if input_lower.starts_with(prefix) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Filters a list of targets and retains only strictly authorized in-scope ones.
    pub fn filter_in_scope(&self, targets: &[String]) -> Vec<String> {
        targets
            .iter()
            .filter(|t| self.is_in_scope(t))
            .cloned()
            .collect()
    }
}
