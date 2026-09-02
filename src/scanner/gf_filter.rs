use serde::{Deserialize, Serialize};
use tracing::info;

/// GF (Grep Fast) Pattern Filter — Pure Rust implementation of tomnomnom's gf patterns.
///
/// gf is used by top bug bounty hunters to quickly filter thousands of URLs
/// and identify which ones are likely vulnerable to specific attack classes.
/// Instead of running a full scanner on every URL, we first filter URLs by
/// pattern to find promising targets, then run the appropriate scanner.
///
/// This is the "pre-scanner intelligence layer" that professional hunters use
/// to save time and maximize signal-to-noise ratio.
///
/// Pattern categories:
/// - **SQLi**: URLs with parameters that pattern-match SQL injection
/// - **XSS**: URLs with parameters reflecting into HTML context
/// - **SSRF**: Parameters that accept URL/host values
/// - **LFI**: Parameters that accept file path values
/// - **RCE**: Parameters that might execute commands
/// - **Redirect**: Parameters used for redirection
/// - **IDOR**: Parameters that look like object IDs (numeric, UUID)
/// - **Debug**: Parameters that enable debug mode

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GfPattern {
    Sqli,
    Xss,
    Ssrf,
    Lfi,
    Rce,
    Redirect,
    Idor,
    Debug,
    Secrets,
}

impl GfPattern {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sqli => "sqli",
            Self::Xss => "xss",
            Self::Ssrf => "ssrf",
            Self::Lfi => "lfi",
            Self::Rce => "rce",
            Self::Redirect => "redirect",
            Self::Idor => "idor",
            Self::Debug => "debug",
            Self::Secrets => "secrets",
        }
    }
}

/// A URL that matched a vulnerability pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GfMatch {
    /// The matched URL
    pub url: String,
    /// Which pattern matched
    pub pattern: String,
    /// The specific parameter name that triggered the match
    pub matched_param: String,
    /// Recommended next scanner to run
    pub recommended_scanner: String,
}

/// Pure Rust gf-style pattern filter for URL triage.
///
/// Processes URLs and classifies them by vulnerability type,
/// allowing the pipeline to run the RIGHT tool on each URL.
pub struct GfFilter;

// SQL Injection parameter patterns
const SQLI_PARAMS: &[&str] = &[
    "id", "select", "report", "role", "update", "query", "user",
    "name", "sort", "where", "search", "params", "process", "row",
    "view", "table", "from", "sel", "results", "sleep", "fetch",
    "order", "keyword", "column", "field", "delete", "string",
    "number", "filter", "cat", "category", "username", "uid",
    "item", "ref", "reference", "type", "next", "offset",
    "limit", "num", "page", "start", "end",
];

// XSS parameter patterns
const XSS_PARAMS: &[&str] = &[
    "q", "s", "search", "lang", "keyword", "query", "page", "keywords",
    "year", "view", "email", "type", "name", "p", "month", "immagine",
    "list_type", "url", "terms", "categoryid", "key", "l", "begindate",
    "enddate", "q", "term", "title", "text", "input", "message",
    "comment", "content", "description", "data", "redirect_uri",
    "next", "return", "redir", "target",
];

// SSRF parameter patterns
const SSRF_PARAMS: &[&str] = &[
    "dest", "redirect", "uri", "path", "continue", "url", "window",
    "next", "data", "reference", "site", "html", "val", "validate",
    "domain", "callback", "return", "page", "feed", "host", "port",
    "to", "out", "view", "dir", "image_url", "api_url", "service",
    "remote", "webhook", "proxy", "endpoint", "src", "source",
    "load", "fetch", "fetch_url", "file_url", "target",
];

// LFI parameter patterns
const LFI_PARAMS: &[&str] = &[
    "cat", "dir", "action", "board", "date", "detail", "file",
    "download", "path", "folder", "prefix", "include", "page",
    "inc", "locate", "show", "doc", "site", "type", "view",
    "content", "document", "root", "pg", "style", "template",
    "php_path", "filepath", "func", "mod", "conf", "lang",
];

// Open Redirect parameter patterns
const REDIRECT_PARAMS: &[&str] = &[
    "next", "url", "target", "rurl", "dest", "destination",
    "redir", "redirect_uri", "redirect_url", "redirect",
    "view", "to", "return_url", "returnTo", "return",
    "checkout_url", "continue", "return_path", "goto",
    "location", "ref", "r_url", "returl", "back",
];

// IDOR parameter patterns (numeric IDs, UUIDs)
const IDOR_PARAMS: &[&str] = &[
    "id", "user_id", "account_id", "uid", "userid", "user",
    "order_id", "orderid", "customer_id", "invoice_id",
    "message_id", "thread_id", "post_id", "comment_id",
    "record_id", "doc_id", "file_id", "item_id",
];

// Debug/Info disclosure parameter patterns
const DEBUG_PARAMS: &[&str] = &[
    "debug", "test", "development", "devmode", "verbose",
    "trace", "admin", "superuser", "internal", "staging",
];

impl GfFilter {
    /// Filter a list of URLs and classify them by vulnerability pattern.
    ///
    /// Returns a list of GfMatch structs, each containing the URL,
    /// the matched pattern, and the recommended scanner to run.
    pub fn filter(urls: &[String]) -> Vec<GfMatch> {
        let mut matches = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for url in urls {
            if let Some(query) = url.split('?').nth(1) {
                for param_pair in query.split('&') {
                    let param_name = param_pair
                        .split('=')
                        .next()
                        .unwrap_or("")
                        .to_lowercase();

                    if param_name.is_empty() {
                        continue;
                    }

                    let dedup_key = format!("{}:{}", url.split('?').next().unwrap_or(""), param_name);
                    if seen.contains(&dedup_key) {
                        continue;
                    }

                    // Check patterns in priority order
                    let matched = Self::classify_param(&param_name, url);

                    if let Some(gf_match) = matched {
                        seen.insert(dedup_key);
                        matches.push(gf_match);
                    }
                }
            }
        }

        info!("gf filter: classified {} URL-parameter pairs from {} URLs.", matches.len(), urls.len());
        matches
    }

    fn classify_param(param: &str, url: &str) -> Option<GfMatch> {
        // Priority: SSRF > LFI > SQLi > Redirect > XSS > IDOR > Debug
        if SSRF_PARAMS.iter().any(|&p| param == p || param.contains(p)) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Ssrf.as_str().to_string(),
                recommended_scanner: "interactsh-ssrf".to_string(),
            });
        }

        if LFI_PARAMS.iter().any(|&p| param == p) && !REDIRECT_PARAMS.iter().any(|&p| param == p) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Lfi.as_str().to_string(),
                recommended_scanner: "nuclei-lfi".to_string(),
            });
        }

        if SQLI_PARAMS.iter().any(|&p| param == p) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Sqli.as_str().to_string(),
                recommended_scanner: "sqlmap".to_string(),
            });
        }

        if REDIRECT_PARAMS.iter().any(|&p| param == p) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Redirect.as_str().to_string(),
                recommended_scanner: "open-redirect".to_string(),
            });
        }

        if XSS_PARAMS.iter().any(|&p| param == p) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Xss.as_str().to_string(),
                recommended_scanner: "dalfox".to_string(),
            });
        }

        if IDOR_PARAMS.iter().any(|&p| param == p) {
            // Only flag IDOR if the value looks like a numeric ID or UUID
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Idor.as_str().to_string(),
                recommended_scanner: "manual-idor".to_string(),
            });
        }

        if DEBUG_PARAMS.iter().any(|&p| param == p) {
            return Some(GfMatch {
                url: url.to_string(),
                matched_param: param.to_string(),
                pattern: GfPattern::Debug.as_str().to_string(),
                recommended_scanner: "nuclei-exposure".to_string(),
            });
        }

        None
    }

    /// Filter URLs for a specific pattern only.
    pub fn filter_pattern(urls: &[String], pattern: GfPattern) -> Vec<String> {
        let pattern_str = pattern.as_str();
        Self::filter(urls)
            .into_iter()
            .filter(|m| m.pattern == pattern_str)
            .map(|m| m.url)
            .collect()
    }

    /// Get all URLs that are likely SQLi targets (for sqlmap input).
    pub fn sqli_targets(urls: &[String]) -> Vec<String> {
        Self::filter_pattern(urls, GfPattern::Sqli)
    }

    /// Get all URLs that are likely SSRF targets (for interactsh probing).
    pub fn ssrf_targets(urls: &[String]) -> Vec<String> {
        Self::filter_pattern(urls, GfPattern::Ssrf)
    }

    /// Get all URLs that are likely XSS targets (for dalfox).
    pub fn xss_targets(urls: &[String]) -> Vec<String> {
        Self::filter_pattern(urls, GfPattern::Xss)
    }

    /// Get all URLs that are likely redirect targets (for open redirect scanner).
    pub fn redirect_targets(urls: &[String]) -> Vec<String> {
        Self::filter_pattern(urls, GfPattern::Redirect)
    }
}
