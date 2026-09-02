use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::hackerone::client::HackerOneClientTrait;
use std::sync::Arc;
use sysinfo::{Disks, System};
use tokio::process::Command;

#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthItem {
    pub category: &'static str,
    pub name: &'static str,
    pub path: Option<String>,
    pub status: bool,
    pub details: String,
}

pub struct HealthChecker {
    config: AppConfig,
    repository: Repository,
    hackerone_client: Arc<dyn HackerOneClientTrait>,
}

impl HealthChecker {
    pub fn new(
        config: AppConfig,
        repository: Repository,
        hackerone_client: Arc<dyn HackerOneClientTrait>,
    ) -> Self {
        Self {
            config,
            repository,
            hackerone_client,
        }
    }

    pub async fn run_all_checks(&self) -> Vec<HealthItem> {
        let mut results = Vec::new();

        // ---------------------------------------------------------------------
        // Group 1: Core System & Services
        // ---------------------------------------------------------------------
        results.push(HealthItem {
            category: "Core",
            name: "Rust Runtime",
            path: None,
            status: true,
            details: format!("Tokio Async Runtime ({} worker threads)", self.config.max_concurrent_jobs),
        });

        let db_res = self.repository.get_stats().await;
        results.push(HealthItem {
            category: "Core",
            name: "Database",
            path: Some(self.config.database_url.clone()),
            status: db_res.is_ok(),
            details: match db_res {
                Ok(stats) => format!("SQLite WAL Active ({} Programs, {} In-Scope Assets)", stats.total_programs, stats.in_scope_assets),
                Err(e) => format!("Connection Failed: {}", e),
            },
        });

        let h1_ok = self.config.is_hackerone_configured();
        results.push(HealthItem {
            category: "Core",
            name: "HackerOne Configuration",
            path: None,
            status: h1_ok,
            details: if h1_ok {
                format!("Configured for user: {}", self.config.hackerone_username)
            } else {
                "HACKERONE_API_TOKEN or HACKERONE_USERNAME missing (Mock Adapter active)".to_string()
            },
        });

        let tg_ok = self.config.is_telegram_configured();
        results.push(HealthItem {
            category: "Core",
            name: "Telegram Configuration",
            path: None,
            status: tg_ok,
            details: if tg_ok {
                format!("Chat ID: {}", self.config.telegram_chat_id)
            } else {
                "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing".to_string()
            },
        });

        // ---------------------------------------------------------------------
        // Group 2: Security Tools (Kali Linux External Binaries)
        // ---------------------------------------------------------------------
        results.push(self.check_tool("subfinder", &self.config.subfinder_path, &["-version"]).await);
        results.push(self.check_tool("httpx", &self.config.httpx_path, &["-version"]).await);
        results.push(self.check_tool("katana", &self.config.katana_path, &["-version"]).await);
        results.push(self.check_tool("gau", &self.config.gau_path, &["--version"]).await);
        results.push(self.check_tool("nuclei", &self.config.nuclei_path, &["-version"]).await);
        results.push(self.check_tool("dalfox", &self.config.dalfox_path, &["version"]).await);
        results.push(self.check_tool("arjun", &self.config.arjun_path, &["-h"]).await);
        results.push(self.check_tool("ffuf", &self.config.ffuf_path, &["-V"]).await);
        // Phase 3: Elite Professional Tools
        results.push(self.check_tool("sqlmap", &self.config.sqlmap_path, &["--version"]).await);
        results.push(self.check_tool("naabu", &self.config.naabu_path, &["-version"]).await);
        results.push(self.check_tool("dnsx", &self.config.dnsx_path, &["-version"]).await);
        results.push(self.check_tool("crlfuzz", &self.config.crlfuzz_path, &["-h"]).await);
        // Phase 4: Elite Expansion
        results.push(self.check_tool("kxss", &self.config.kxss_path, &["-h"]).await);
        results.push(self.check_tool("amass", &self.config.amass_path, &["-version"]).await);
        results.push(self.check_tool("gitleaks", &self.config.gitleaks_path, &["version"]).await);
        results.push(self.check_tool("alterx", &self.config.alterx_path, &["-h"]).await);
        results.push(self.check_tool("gospider", &self.config.gospider_path, &["-h"]).await);
        results.push(self.check_tool("smuggler", &self.config.smuggler_path, &["--help"]).await);
        results.push(self.check_tool("paramspider", &self.config.paramspider_path, &["--help"]).await);

        // ---------------------------------------------------------------------
        // Group 3: System Resources (Disk & Memory)
        // ---------------------------------------------------------------------
        let mut sys = System::new_all();
        sys.refresh_memory();
        let total_mem = sys.total_memory() / (1024 * 1024);
        let used_mem = sys.used_memory() / (1024 * 1024);
        let free_mem = sys.available_memory() / (1024 * 1024);

        let mem_ok = free_mem > 200; // at least 200MB free
        results.push(HealthItem {
            category: "System",
            name: "Memory",
            path: None,
            status: mem_ok,
            details: format!("{}/{} MB available ({} MB free)", used_mem, total_mem, free_mem),
        });

        let disks = Disks::new_with_refreshed_list();
        let mut disk_ok = true;
        let mut disk_details = "Disk operational".to_string();

        if let Some(disk) = disks.first() {
            let available_gb = disk.available_space() / (1024 * 1024 * 1024);
            let total_gb = disk.total_space() / (1024 * 1024 * 1024);
            disk_ok = available_gb >= 1; // at least 1GB free
            disk_details = format!("{} GB available / {} GB total", available_gb, total_gb);
        }

        results.push(HealthItem {
            category: "System",
            name: "Disk",
            path: None,
            status: disk_ok,
            details: disk_details,
        });

        results
    }

    async fn check_tool(&self, name: &'static str, path: &str, test_args: &[&str]) -> HealthItem {
        let resolved_path = if std::path::Path::new(path).exists() {
            path.to_string()
        } else {
            let candidates = [
                format!("/home/yaseen/go/bin/{}", name),
                format!("/home/yaseen/.local/bin/{}", name),
                format!("/usr/local/bin/{}", name),
                format!("/usr/bin/{}", name),
                path.to_string(),
            ];
            candidates
                .into_iter()
                .find(|p| std::path::Path::new(p).exists())
                .unwrap_or_else(|| path.to_string())
        };

        let mut cmd = Command::new(&resolved_path);
        cmd.args(test_args);
        cmd.stdin(std::process::Stdio::null()); // Prevent stdin-waiting tools (like kxss) from blocking

        match tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output()).await {
            Ok(Ok(output)) => {
                if output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() || std::path::Path::new(&resolved_path).exists() {
                    let version_str = String::from_utf8_lossy(&output.stdout);
                    let err_str = String::from_utf8_lossy(&output.stderr);
                    let first_line = version_str
                        .lines()
                        .find(|l| !l.trim().is_empty())
                        .or_else(|| err_str.lines().find(|l| !l.trim().is_empty()))
                        .unwrap_or("Installed");

                    HealthItem {
                        category: "Security Tools",
                        name,
                        path: Some(resolved_path.clone()),
                        status: true,
                        details: format!("Found at '{}' ({})", resolved_path, first_line.trim()),
                    }
                } else {
                    HealthItem {
                        category: "Security Tools",
                        name,
                        path: Some(resolved_path.clone()),
                        status: false,
                        details: format!("Path: {}\nStatus: RETURNED FAILURE", resolved_path),
                    }
                }
            }
            _ => {
                if std::path::Path::new(&resolved_path).exists() {
                    HealthItem {
                        category: "Security Tools",
                        name,
                        path: Some(resolved_path.clone()),
                        status: true,
                        details: format!("Found at '{}' (Installed)", resolved_path),
                    }
                } else {
                    HealthItem {
                        category: "Security Tools",
                        name,
                        path: Some(resolved_path.clone()),
                        status: false,
                        details: format!("Path: {}\nStatus: NOT FOUND", resolved_path),
                    }
                }
            }
        }
    }
}

