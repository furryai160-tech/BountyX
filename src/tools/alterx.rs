use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A discovered permutation subdomain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlterxResult {
    pub subdomain: String,
}

/// Adapter for `alterx` — smart subdomain permutation engine.
///
/// alterx generates intelligent subdomain permutations based on patterns
/// observed in the target's existing subdomains. For example, if you have:
///   api.example.com → api-dev, api2, api-staging, api-v2
///   app.example.com → app-dev, app2, app-admin, app-internal
///
/// These permutations catch development/staging/admin servers that are
/// intentionally hidden from passive recon but still DNS-resolvable.
///
/// Combined with dnsx for resolution, this finds subdomains that:
/// - Subfinder misses (not in CT logs, not indexed)
/// - Amass misses (not in any database)
/// - Are goldmines: staging servers with debug APIs, admin panels, etc.
#[derive(Clone)]
pub struct AlterxAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl AlterxAdapter {
    pub fn new(binary_path: &str, timeout_secs: u64) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            timeout_secs,
            repository: None,
        }
    }

    pub fn with_repository(mut self, repo: Repository) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn parse_results(&self, output: &ToolOutput) -> Vec<AlterxResult> {
        let results: Vec<AlterxResult> = output.raw_lines
            .iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && l.contains('.'))
            .map(|subdomain| AlterxResult { subdomain })
            .collect();

        info!("alterx generated {} subdomain permutations.", results.len());
        results
    }
}

#[async_trait]
impl SecurityTool for AlterxAdapter {
    fn name(&self) -> &'static str {
        "alterx"
    }

    fn binary_path(&self) -> &str {
        &self.binary_path
    }

    async fn check_available(&self) -> Result<bool> {
        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-version");
        match tokio::time::timeout(Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(out)) => Ok(out.status.success() || !out.stderr.is_empty()),
            _ => Ok(false),
        }
    }

    /// Generate subdomain permutations from a list of known subdomains (stdin).
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Pass known subdomains via stdin for pattern-based permutation
        let stdin_data = if input.targets.len() > 1 {
            input.targets.join("\n")
        } else {
            input.target.clone()
        };

        let args: Vec<&str> = vec![
            "-silent",
            "-en",   // Enable enrichment (adds dev, staging, admin, api, etc.)
            "-pp", "word=dev,staging,admin,api,internal,test,beta,v2,old,backup,prod,qa",
        ];

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args,
            Some(&stdin_data),
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
