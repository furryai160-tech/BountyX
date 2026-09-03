use crate::database::repository::Repository;
use crate::errors::Result;
use crate::tools::adapter::{SecurityTool, ToolInput, ToolOutput};
use crate::tools::executor::SafeProcessExecutor;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// A discovered open port on a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFinding {
    /// Host/IP that has the port open
    pub host: String,
    /// Open port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Service name if detected (http, https, ssh, etc.)
    pub service: String,
}

/// Adapter for `naabu` — projectdiscovery's ultra-fast port scanner.
///
/// In bug bounty, unexpected open ports are goldmines:
/// - Port 8080, 8443, 8888 → Development/staging servers with weak auth
/// - Port 6379 → Redis without authentication (P1)
/// - Port 27017 → MongoDB open to internet (P1)
/// - Port 9200 → Elasticsearch public (P1)
/// - Port 4848, 8161 → Admin panels for Java app servers
/// - Port 3000, 5000 → Dev servers with debug endpoints
///
/// This adapter scans the top 1000 ports by default, with SYN or CONNECT
/// scan mode depending on privileges.
#[derive(Clone)]
pub struct NaabuAdapter {
    binary_path: String,
    timeout_secs: u64,
    repository: Option<Repository>,
}

impl NaabuAdapter {
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

    /// Parse naabu JSON output lines into PortFinding structs.
    ///
    /// naabu JSON format:
    /// {"ip":"1.2.3.4","port":8080,"protocol":"tcp"}
    pub fn parse_findings(&self, output: &ToolOutput) -> Vec<PortFinding> {
        let mut findings = Vec::new();

        for line in &output.raw_lines {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let host = val.get("ip")
                    .or_else(|| val.get("host"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let port = val.get("port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;

                let protocol = val.get("protocol")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tcp")
                    .to_string();

                if host.is_empty() || port == 0 {
                    continue;
                }

                // Map common ports to service names
                let service = Self::port_to_service(port);

                info!("🔌 Open port [{}/{}] on '{}' → {}", port, protocol, host, service);

                findings.push(PortFinding {
                    host,
                    port,
                    protocol,
                    service,
                });
            }
        }

        info!("naabu found {} open port(s).", findings.len());
        findings
    }

    fn port_to_service(port: u16) -> String {
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            1433 => "MSSQL",
            1521 => "Oracle",
            2375 | 2376 => "Docker API",
            3000 => "Dev Server",
            3306 => "MySQL",
            3389 => "RDP",
            4848 => "GlassFish Admin",
            5000 => "Dev/Flask",
            5432 => "PostgreSQL",
            5601 => "Kibana",
            6379 => "Redis",
            8080 => "HTTP-Alt",
            8161 => "ActiveMQ Admin",
            8443 => "HTTPS-Alt",
            8888 => "Jupyter/Dev",
            9000 => "SonarQube/PHP-FPM",
            9200 | 9300 => "Elasticsearch",
            27017 => "MongoDB",
            _ => "Unknown",
        }.to_string()
    }
}

#[async_trait]
impl SecurityTool for NaabuAdapter {
    fn name(&self) -> &'static str {
        "naabu"
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

    /// Scan top ports on a target host.
    async fn run(&self, input: ToolInput) -> Result<ToolOutput> {
        let timeout = Duration::from_secs(self.timeout_secs);

        // Strip protocol from target for naabu
        let host = input.target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(&input.target);

        let args: Vec<String> = vec![
            "-host".to_string(), host.to_string(),
            "-sC".to_string(),                          // Connect scan (non-root safe)
            "-json".to_string(),
            "-silent".to_string(),
            "-top-ports".to_string(), "1000".to_string(),
            "-rate".to_string(), "500".to_string(),     // 500 packets/sec — safe
            "-timeout".to_string(), "1000".to_string(), // 1s per host timeout (ms)
            "-retries".to_string(), "1".to_string(),
            "-c".to_string(), "25".to_string(),         // 25 concurrent probes
        ];


        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        SafeProcessExecutor::execute(
            self.name(),
            &self.binary_path,
            &args_ref,
            None,
            timeout,
            self.repository.as_ref(),
            input.job_id.as_deref(),
            &input.target,
        )
        .await
    }
}
