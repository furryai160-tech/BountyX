use sha2::{Digest, Sha256};
use std::collections::HashSet;
use url::Url;

pub struct Deduplicator;

impl Deduplicator {
    /// Generates a unique SHA-256 fingerprint for a finding to prevent duplicate triage.
    pub fn compute_finding_fingerprint(
        program_handle: &str,
        asset: &str,
        template_id: &str,
        matcher_name: Option<&str>,
        matched_at: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(program_handle.trim().to_lowercase().as_bytes());
        hasher.update(b":");
        hasher.update(asset.trim().to_lowercase().as_bytes());
        hasher.update(b":");
        hasher.update(template_id.trim().to_lowercase().as_bytes());
        hasher.update(b":");
        if let Some(matcher) = matcher_name {
            hasher.update(matcher.trim().to_lowercase().as_bytes());
        }
        hasher.update(b":");
        // Normalize matched_at (strip query parameters if generic vulnerability)
        let normalized_matched_at = Self::normalize_url_for_dedup(matched_at);
        hasher.update(normalized_matched_at.as_bytes());

        format!("{:x}", hasher.finalize())
    }

    /// Computes a hash of the entire scope snapshot for change detection.
    pub fn compute_scope_hash(serialized_scope_json: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serialized_scope_json.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Deduplicates a list of strings while preserving order.
    pub fn deduplicate_strings(items: &[String]) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for item in items {
            let trimmed = item.trim().to_string();
            if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
                result.push(trimmed);
            }
        }
        result
    }

    /// Normalizes URLs for deduplication (removes tracking params, default ports, trailing slashes).
    pub fn normalize_url_for_dedup(raw_url: &str) -> String {
        if let Ok(parsed) = Url::parse(raw_url) {
            // Lowercase scheme and host
            let scheme = parsed.scheme().to_lowercase();
            let host = parsed.host_str().unwrap_or("").to_lowercase();
            let port = parsed.port();

            // Strip default ports
            let port_str = match (scheme.as_str(), port) {
                ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
                (_, Some(p)) => format!(":{}", p),
            };

            let path = parsed.path().trim_end_matches('/');
            let final_path = if path.is_empty() { "/" } else { path };

            let query = parsed.query().map(|q| format!("?{}", q)).unwrap_or_default();

            format!("{}://{}{}{}{}", scheme, host, port_str, final_path, query)
        } else {
            raw_url.trim().to_lowercase()
        }
    }
}
