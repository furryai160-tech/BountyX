use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "bountyscope",
    author = "BountyScope Team",
    version = "0.1.0",
    about = "Headless Bug Bounty Automation Engine in Rust",
    long_about = "BountyScope is a headless, asynchronous, production-grade bug bounty automation engine designed exclusively for authorized HackerOne scope monitoring, continuous reconnaissance, targeted scanning, evidence collection, and Telegram-controlled triage."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize local directories, database schema, and configuration
    Init,

    /// Execute system diagnostics and dependency health checks
    Health,

    /// List tracked HackerOne programs and their status
    Programs,

    /// Manage in-scope assets and synchronization
    Scope {
        #[command(subcommand)]
        action: ScopeAction,
    },

    /// Run continuous scope monitoring, automatic diffing, and worker pipeline
    Monitor,

    /// Trigger manual reconnaissance on an authorized in-scope target
    Recon(TargetArgs),

    /// Trigger manual targeted scanner on an authorized in-scope target
    Scan(TargetArgs),

    /// List and inspect recorded security findings
    Findings {
        /// Optional status filter (NEW, POTENTIAL, REQUIRES_REVIEW, CONFIRMED_BY_USER, REJECTED)
        #[arg(short, long)]
        status: Option<String>,
    },

    /// List generated draft markdown reports
    Reports,
}

#[derive(Subcommand, Debug)]
pub enum ScopeAction {
    /// Synchronize latest scope from HackerOne and update local database
    Sync,

    /// Display diff between current and previous scope snapshots
    Diff,
}

#[derive(Args, Debug)]
pub struct TargetArgs {
    /// The target host, URL, or domain to process (--target or -t)
    #[arg(short, long)]
    pub target: Option<String>,

    /// Positional target host, URL, or domain
    pub positional_target: Option<String>,

    /// The associated HackerOne program handle
    #[arg(short, long, default_value = "manual")]
    pub program: String,

    /// Perform a safe dry-run simulation without running external security tools
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

impl TargetArgs {
    pub fn resolved_target(&self) -> String {
        self.target
            .clone()
            .or_else(|| self.positional_target.clone())
            .unwrap_or_default()
    }
}


