use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A single endpoint discovered by ffuf directory/parameter fuzzing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfufResult {
    /// Discovered URL/path
    pub url: String,
    /// HTTP status code
    pub status: u16,
    /// Response size in bytes
    pub length: u64,
    /// Number of words in response
    pub words: u64,
    /// Response time in milliseconds
    pub duration_ms: u64,
    /// The fuzzing input that caused the match (e.g. "admin", "api", ".git")
    pub input: String,
}

/// Adapter wrapping `ffuf` — the Fast Web Fuzzer.
///
/// ffuf is the de-facto standard for directory and parameter fuzzing in
/// bug bounty. This adapter runs it in directory brute-force mode using
/// a high-quality built-in wordlist to discover hidden endpoints, admin panels,
/// API paths, backup files, and development resources.
///
/// Key features of this integration:
/// - JSON output (`-of json -o /dev/stdout`) for reliable parsing
/// - Filters out common false-positive status codes (404, 400, 301 to same host)
/// - Rate-limited to 50 req/s to avoid triggering WAF bans
/// - Targets one URL at a time (per ffuf's design)
#[derive(Clone)]
pub struct FfufAdapter {
    binary_path: String,
    wordlist_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

/// High-value paths for bug bounty fuzzing — balanced between coverage and speed.
///
/// This wordlist targets the most commonly-found hidden paths that produce
/// real findings in bug bounty programs: admin panels, API endpoints,
/// backup files, debug endpoints, and development resources.
const BUILTIN_WORDLIST: &[&str] = &[
    // Admin and management interfaces
    "admin", "administrator", "admin.php", "admin.html", "admin-panel",
    "management", "manage", "backend", "dashboard", "controlpanel",
    "control", "wp-admin", "phpmyadmin", "adminer",
    // API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/user", "api/users",
    "api/admin", "api/config", "api/debug", "api/health", "api/status",
    "api/internal", "graphql", "swagger", "swagger.json", "openapi.json",
    "openapi.yaml", "api-docs", "api/docs",
    // Authentication endpoints
    "login", "signin", "auth", "authenticate", "oauth", "oauth2",
    "sso", "saml", "oidc", "token", "logout", "register", "signup",
    "forgot-password", "reset-password", "password-reset",
    // Development and debug endpoints
    "debug", "test", "testing", "dev", "development", "staging",
    "internal", "phpinfo.php", "info.php", "server-status",
    "server-info", ".env", ".git", ".svn", "trace", "actuator",
    "actuator/env", "actuator/health", "actuator/mappings",
    // Backup and configuration files
    "backup", "backup.sql", "backup.zip", "dump.sql", "db.sql",
    "config.php", "config.json", "config.yml", "settings.php",
    "wp-config.php", "web.config", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    // User and account management
    "user", "users", "account", "accounts", "profile", "profiles",
    "me", "self", "whoami",
    // Common file extensions to probe
    "index.php", "index.bak", "index.old", "home.php",
    // Cloud/infrastructure metadata
    "metadata", "health", "healthz", "ready", "readyz", "ping",
    "status", "version", "metrics", "prometheus",
];

impl FfufAdapter {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            wordlist_path: String::new(), // empty = use built-in
            timeout_secs,
            repository: None,
        }
    }

    pub fn with_repository(mut self, repo: Repository) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn with_wordlist(mut self, path: &str) -> Self {
        self.wordlist_path = path.to_string();
        self
    }

    /// Parse ffuf JSON output into FfufResult structs.
    ///
    /// ffuf JSON format per result:
    /// {"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,...}
    pub fn parse_results(&self, output: &ToolOutput) -> Vec<FfufResult> {
        let mut results = Vec::new();

        // ffuf outputs a single JSON object wrapping all results
        // OR JSONL depending on version and flags
        let full_stdout = output.raw_lines.join("\n");

        // Try parsing as ffuf's wrapped JSON format first
        if let Ok(parsed) = serde_json::from_str::<RawFfufOutput>(&full_stdout) {
            for r in parsed.results {
                if let Some(result) = Self::map_raw_result(r) {
                    results.push(result);
                }
            }
            return results;
        }

        // Fallback: try JSONL line-by-line
        for line in output.raw_lines.iter() {
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                if let Ok(r) = serde_json::from_str::<RawFfufResult>(trimmed) {
                    if let Some(result) = Self::map_raw_result(r) {
                        results.push(result);
                    }
                }
            }
        }

        info!("ffuf parsed {} discovered paths.", results.len());
        results
    }

    fn map_raw_result(r: RawFfufResult) -> Option<FfufResult> {
        // Skip typical error/noise statuses
        if r.status == 400 || r.status == 0 {
            return None;
        }

        let input_word = r.input
            .get("FUZZ")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let duration_ms = r.duration.unwrap_or(0) / 1_000_000; // nanoseconds → ms

        Some(FfufResult {
            url: r.url.unwrap_or_default(),
            status: r.status,
            length: r.length.unwrap_or(0),
            words: r.words.unwrap_or(0),
            duration_ms,
            input: input_word,
        })
    }

    /// Write built-in wordlist to a temp file and return its path.
    async fn write_builtin_wordlist() -> Result<String> {
        let tmp_path = format!("/tmp/bountyscope_fuzz_{}.txt", uuid::Uuid::new_v4());
        let content = BUILTIN_WORDLIST.join("\n");
        tokio::fs::write(&tmp_path, content).await.map_err(|e| {
            crate::errors::BountyScopeError::Internal(format!("Failed to write wordlist: {}", e))
        })?;
        Ok(tmp_path)
    }
}

#[derive(Deserialize)]
struct RawFfufOutput {
    #[serde(default)]
    results: Vec<RawFfufResult>,
}

#[derive(Deserialize)]
struct RawFfufResult {
    #[serde(default)]
    pub input: std::collections::HashMap<String, String>,
    pub status: u16,
    pub length: Option<u64>,
    pub words: Option<u64>,
    pub url: Option<String>,
    pub duration: Option<u64>,
}

#[async_trait]
impl SecurityTool for FfufAdapter {
    fn name(&self) -> &'static str {
        "ffuf"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-V");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Run ffuf directory fuzzing against a single base URL.
    ///
    /// The adapter:
    /// 1. Writes the wordlist to a temp file if using built-in words
    /// 2. Runs ffuf with JSON output, reasonable rate limits
    /// 3. Filters status codes that are almost always false positives
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Use provided wordlist or generate from built-in
        let (wordlist_path, is_temp) = if self.wordlist_path.is_empty() {
            let path = Self::write_builtin_wordlist().await?;
            (path, true)
        } else {
            (self.wordlist_path.clone(), false)
        };

        // Base URL — ffuf needs FUZZ placeholder in the URL
        let base_url = if input.target.ends_with('/') {
            format!("{}FUZZ", input.target)
        } else {
            format!("{}/FUZZ", input.target)
        };

        let args: Vec<&str> = vec![
            "-u", &base_url,
            "-w", &wordlist_path,
            "-of", "json",            // JSON output for reliable parsing
            "-o", "/dev/stdout",       // write to stdout
            "-ac",                     // auto-calibrate — smart false positive removal
            "-r",                      // follow redirects
            "-rate", "50",             // 50 req/s — safe for most targets
            "-t", "40",                // 40 concurrent threads
            "-timeout", "8",           // 8s per request
            "-mc", "200,201,204,301,302,307,401,403,405,500",  // status codes to match
            "-fs", "0",                // filter out empty responses
            "-s",                      // silent — no progress bar
        ];

        let result = SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            None, // ffuf doesn't use stdin
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await;

        // Clean up temp wordlist
        if is_temp {
            let _ = tokio::fs::remove_file(&wordlist_path).await;
        }

        result
    }
}
