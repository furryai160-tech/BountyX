use crate::config::AppConfig;
use crate::errors::Result;
use crate::recon::ProcessExecutor;
use crate::scanner::parser::{NucleiFinding, NucleiParser};
use crate::scanner::severity::Severity;
use crate::validation::ScopeGuard;
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct NucleiRunner {
    binary_path: String,
    severities: Vec<String>,
    templates: Option<String>,
    tags: Option<String>,
    timeout_secs: u64,
}

impl NucleiRunner {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            binary_path: config.nuclei_path.clone(),
            severities: config.nuclei_severities.clone(),
            templates: config.nuclei_templates.clone(),
            tags: config.nuclei_tags.clone(),
            timeout_secs: config.process_timeout_seconds,
        }
    }

    pub async fn scan_targets(
        &self,
        targets: &[String],
        scope_guard: &ScopeGuard,
    ) -> Result<Vec<NucleiFinding>> {
        // Strict Gate: Verify all targets with ScopeGuard before running Nuclei
        let authorized_targets = scope_guard.filter_in_scope(targets);
        if authorized_targets.is_empty() {
            info!("No authorized targets to scan with Nuclei.");
            return Ok(Vec::new());
        }

        info!(
            "Starting Nuclei vulnerability scan on {} authorized targets (Severities: {})",
            authorized_targets.len(),
            self.severities.join(",")
        );

        let input_data = authorized_targets.join("\n");
        let severity_arg = self.severities.join(",");

        let mut args: Vec<&str> = vec![
            "-silent",
            "-jsonl",
            "-severity",
            &severity_arg,
            "-include-rr",
            "-rate-limit",
            "50",
            "-concurrency",
            "10",
            "-timeout",
            "10",
        ];

        if let Some(ref t) = self.templates {
            args.push("-t");
            args.push(t.as_str());
        }

        if let Some(ref tags) = self.tags {
            args.push("-tags");
            args.push(tags.as_str());
        }

        let timeout = Duration::from_secs(self.timeout_secs);

        let (stdout, stderr) = match ProcessExecutor::execute(&self.binary_path, &args, Some(&input_data), timeout).await {
            Ok(res) => res,
            Err(e) => {
                warn!("Nuclei scan execution failed or binary not found ({}): {}", self.binary_path, e);
                return Ok(Vec::new());
            }
        };

        if !stderr.is_empty() {
            debug!("Nuclei stderr: {}", stderr);
        }

        let mut findings = Vec::new();
        for line in stdout.lines() {
            if let Some(finding) = NucleiParser::parse_line(line) {
                // Strict Gate: Re-verify finding target URL with ScopeGuard
                if !scope_guard.is_in_scope(&finding.matched_at) && !scope_guard.is_in_scope(&finding.host) {
                    warn!(
                        "Dropping Nuclei finding for out-of-scope host/matched-at: '{}'",
                        finding.matched_at
                    );
                    continue;
                }

                // Filter by severity
                let sev_str = finding.severity.as_str();
                if self.severities.iter().any(|s| s.eq_ignore_ascii_case(sev_str)) {
                    findings.push(finding);
                }
            }
        }

        info!("Nuclei scan completed. Found {} potential findings requiring review.", findings.len());
        Ok(findings)
    }
}
