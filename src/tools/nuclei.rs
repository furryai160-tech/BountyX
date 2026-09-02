use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::Result;
use crate::scanner::parser::{NucleiFinding, NucleiParser};
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;

#[derive(Clone)]
pub struct NucleiAdapter {
    binary_path: String,
    severities: Vec<String>,
    templates: Option<String>,
    tags: Option<String>,
    verification_header: Option<String>,
    timeout_secs: u64,
    repository: Option<Repository>,
}


impl NucleiAdapter {
    pub fn new(config: &AppConfig) -> Self {
        Self {
            binary_path: config.nuclei_path.clone(),
            severities: config.nuclei_severities.clone(),
            templates: config.nuclei_templates.clone(),
            tags: config.nuclei_tags.clone(),
            verification_header: config.hackerone_verification_header.clone(),
            timeout_secs: config.process_timeout_seconds,
            repository: None,
        }
    }

    pub fn with_repository(mut self, repo: Repository) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn with_tags(mut self, tags: Option<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_templates(mut self, templates: Option<String>) -> Self {
        self.templates = templates;
        self
    }


    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<NucleiFinding> {
        let mut findings = Vec::new();
        for line in &output.raw_lines {
            if let Some(finding) = NucleiParser::parse_line(line) {
                let sev_str = finding.severity.as_str();
                if self.severities.is_empty()
                    || self.severities.iter().any(|s| s.eq_ignore_ascii_case(sev_str))
                {
                    findings.push(finding);
                }
            }
        }
        findings
    }
}

#[async_trait]
impl SecurityTool for NucleiAdapter {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stdout.is_empty() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);
        let severity_arg = if self.severities.is_empty() {
            "medium,high,critical".to_string()
        } else {
            self.severities.join(",")
        };

        let mut args: Vec<String> = vec![
            "-silent".to_string(),
            "-jsonl".to_string(),
            "-severity".to_string(),
            severity_arg,
            "-include-rr".to_string(),
            "-rate-limit".to_string(),
            "50".to_string(),
            "-concurrency".to_string(),
            "10".to_string(),
            "-timeout".to_string(),
            "10".to_string(),
        ];

        if let Some(ref t) = self.templates {
            args.push("-t".to_string());
            args.push(t.clone());
        }

        if let Some(ref tags) = self.tags {
            args.push("-tags".to_string());
            args.push(tags.clone());
        }

        if let Some(ref hdr) = self.verification_header {
            args.push("-H".to_string());
            args.push(hdr.clone());
        }

        args.extend(input.extra_args.clone());


        let args_str_slices: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let stdin_content = if let Some(ref s) = input.stdin_data {
            s.clone()
        } else {
            input.targets.join("\n")
        };

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args_str_slices,
            Some(&stdin_content),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
