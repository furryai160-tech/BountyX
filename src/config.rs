use crate::errors::{BountyScopeError, Result};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    // HackerOne
    pub hackerone_username: String,
    pub hackerone_api_token: String,
    pub hackerone_adapter: String, // "api" or "mock"
    pub hackerone_verification_header: Option<String>,
    pub h1_sync_concurrency: usize,



    // Telegram
    pub telegram_bot_token: String,
    pub telegram_chat_id: i64,
    pub telegram_admin_pin: Option<String>,

    // Database
    pub database_url: String,

    // Concurrency & Timeouts
    pub max_concurrent_jobs: usize,
    pub request_timeout_seconds: u64,
    pub process_timeout_seconds: u64,
    pub retry_count: u32,

    // Scope Monitor
    pub scope_poll_interval_seconds: u64,

    // Scanner
    pub nuclei_severities: Vec<String>,
    pub nuclei_templates: Option<String>,
    pub nuclei_tags: Option<String>,

    // External Tools Binary Paths
    pub subfinder_path: String,
    pub httpx_path: String,
    pub katana_path: String,
    pub gau_path: String,
    pub nuclei_path: String,
    pub dalfox_path: String,
    pub arjun_path: String,
    pub ffuf_path: String,
    pub sqlmap_path: String,
    pub naabu_path: String,
    pub dnsx_path: String,
    pub crlfuzz_path: String,
    // Phase 4: Elite Expansion
    pub kxss_path: String,
    pub amass_path: String,
    pub gitleaks_path: String,
    pub alterx_path: String,
    pub gospider_path: String,
    pub smuggler_path: String,
    pub paramspider_path: String,

    // Paths
    pub data_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        // Load .env if present (ignore error if not found)
        let _ = dotenvy::dotenv();

        let hackerone_username = std::env::var("HACKERONE_USERNAME").unwrap_or_default();
        let hackerone_api_token = std::env::var("HACKERONE_API_TOKEN").unwrap_or_default();
        let hackerone_adapter = std::env::var("HACKERONE_ADAPTER")
            .unwrap_or_else(|_| "api".to_string())
            .to_lowercase();
        let hackerone_verification_header = std::env::var("HACKERONE_VERIFICATION_HEADER")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let h1_sync_concurrency = std::env::var("H1_SYNC_CONCURRENCY")

            .unwrap_or_else(|_| "10".to_string())
            .parse::<usize>()
            .unwrap_or(10)
            .clamp(1, 30);


        let telegram_bot_token = std::env::var("TELEGRAM_BOT_TOKEN").unwrap_or_default();
        let telegram_chat_id = std::env::var("TELEGRAM_CHAT_ID")
            .unwrap_or_else(|_| "0".to_string())
            .parse::<i64>()
            .unwrap_or(0);

        let telegram_admin_pin = std::env::var("TELEGRAM_ADMIN_PIN")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://data/bountyscope.db".to_string());

        let max_concurrent_jobs = std::env::var("MAX_CONCURRENT_JOBS")
            .unwrap_or_else(|_| "10".to_string())
            .parse::<usize>()
            .unwrap_or(10);

        let request_timeout_seconds = std::env::var("REQUEST_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .unwrap_or(30);

        let process_timeout_seconds = std::env::var("PROCESS_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "600".to_string())
            .parse::<u64>()
            .unwrap_or(600);

        let retry_count = std::env::var("RETRY_COUNT")
            .unwrap_or_else(|_| "3".to_string())
            .parse::<u32>()
            .unwrap_or(3);

        let scope_poll_interval_seconds = std::env::var("SCOPE_POLL_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse::<u64>()
            .unwrap_or(300);

        let severities_str = std::env::var("NUCLEI_SEVERITIES")
            .unwrap_or_else(|_| "medium,high,critical".to_string());
        let nuclei_severities = severities_str
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let nuclei_templates = std::env::var("NUCLEI_TEMPLATES")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let nuclei_tags = std::env::var("NUCLEI_TAGS")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let subfinder_path =
            std::env::var("SUBFINDER_PATH").unwrap_or_else(|_| "subfinder".to_string());
        let httpx_path = std::env::var("HTTPX_PATH").unwrap_or_else(|_| "httpx".to_string());
        let katana_path = std::env::var("KATANA_PATH").unwrap_or_else(|_| "katana".to_string());
        let gau_path = std::env::var("GAU_PATH").unwrap_or_else(|_| "gau".to_string());
        let nuclei_path = std::env::var("NUCLEI_PATH").unwrap_or_else(|_| "nuclei".to_string());
        let dalfox_path = std::env::var("DALFOX_PATH").unwrap_or_else(|_| {
            if std::path::Path::new("/home/yaseen/go/bin/dalfox").exists() {
                "/home/yaseen/go/bin/dalfox".to_string()
            } else {
                "dalfox".to_string()
            }
        });
        let arjun_path = std::env::var("ARJUN_PATH").unwrap_or_else(|_| {
            if std::path::Path::new("/home/yaseen/.local/bin/arjun").exists() {
                "/home/yaseen/.local/bin/arjun".to_string()
            } else {
                "arjun".to_string()
            }
        });
        let ffuf_path = std::env::var("FFUF_PATH").unwrap_or_else(|_| "ffuf".to_string());

        let sqlmap_path = std::env::var("SQLMAP_PATH").unwrap_or_else(|_| {
            if std::path::Path::new("/usr/bin/sqlmap").exists() {
                "/usr/bin/sqlmap".to_string()
            } else {
                "sqlmap".to_string()
            }
        });

        let go_bin = "/home/yaseen/go/bin";
        let naabu_path = std::env::var("NAABU_PATH").unwrap_or_else(|_| {
            let p = format!("{}/naabu", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "naabu".to_string() }
        });
        let dnsx_path = std::env::var("DNSX_PATH").unwrap_or_else(|_| {
            let p = format!("{}/dnsx", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "dnsx".to_string() }
        });
        let crlfuzz_path = std::env::var("CRLFUZZ_PATH").unwrap_or_else(|_| {
            let p = format!("{}/crlfuzz", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "crlfuzz".to_string() }
        });

        let kxss_path = std::env::var("KXSS_PATH").unwrap_or_else(|_| {
            let p = format!("{}/kxss", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "kxss".to_string() }
        });
        let amass_path = std::env::var("AMASS_PATH").unwrap_or_else(|_| {
            let p = format!("{}/amass", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "amass".to_string() }
        });
        let gitleaks_path = std::env::var("GITLEAKS_PATH").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/yaseen".to_string());
            for p in &[
                format!("{}/go/bin/gitleaks", home),
                "/usr/local/bin/gitleaks".to_string(),
                "/usr/bin/gitleaks".to_string(),
            ] {
                if std::path::Path::new(p).exists() { return p.to_string(); }
            }
            "gitleaks".to_string()
        });
        let alterx_path = std::env::var("ALTERX_PATH").unwrap_or_else(|_| {
            let p = format!("{}/alterx", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "alterx".to_string() }
        });
        let gospider_path = std::env::var("GOSPIDER_PATH").unwrap_or_else(|_| {
            let p = format!("{}/gospider", go_bin);
            if std::path::Path::new(&p).exists() { p } else { "gospider".to_string() }
        });
        let smuggler_path = std::env::var("SMUGGLER_PATH").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/yaseen".to_string());
            let p = format!("{}/.local/bin/smuggler", home);
            if std::path::Path::new(&p).exists() { p } else { "smuggler".to_string() }
        });
        let paramspider_path = std::env::var("PARAMSPIDER_PATH").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/yaseen".to_string());
            let p = format!("{}/.local/bin/paramspider", home);
            if std::path::Path::new(&p).exists() { p } else { "paramspider".to_string() }
        });

        let data_dir = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "data".to_string()));
        let reports_dir =
            PathBuf::from(std::env::var("REPORTS_DIR").unwrap_or_else(|_| "reports".to_string()));
        let logs_dir = PathBuf::from(std::env::var("LOGS_DIR").unwrap_or_else(|_| "logs".to_string()));

        Ok(Self {
            hackerone_username,
            hackerone_api_token,
            hackerone_adapter,
            hackerone_verification_header,
            h1_sync_concurrency,
            telegram_bot_token,


            telegram_chat_id,
            telegram_admin_pin,
            database_url,
            max_concurrent_jobs,
            request_timeout_seconds,
            process_timeout_seconds,
            retry_count,
            scope_poll_interval_seconds,
            nuclei_severities,
            nuclei_templates,
            nuclei_tags,
            subfinder_path,
            httpx_path,
            katana_path,
            gau_path,
            nuclei_path,
            dalfox_path,
            arjun_path,
            ffuf_path,
            sqlmap_path,
            naabu_path,
            dnsx_path,
            crlfuzz_path,
            kxss_path,
            amass_path,
            gitleaks_path,
            alterx_path,
            gospider_path,
            smuggler_path,
            paramspider_path,
            data_dir,
            reports_dir,
            logs_dir,
        })
    }

    pub fn validate_for_runtime(&self) -> Result<()> {
        if self.max_concurrent_jobs == 0 {
            return Err(BountyScopeError::Config(
                "MAX_CONCURRENT_JOBS must be greater than 0".to_string(),
            ));
        }
        if self.request_timeout_seconds == 0 {
            return Err(BountyScopeError::Config(
                "REQUEST_TIMEOUT_SECONDS must be greater than 0".to_string(),
            ));
        }
        if self.process_timeout_seconds == 0 {
            return Err(BountyScopeError::Config(
                "PROCESS_TIMEOUT_SECONDS must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_hackerone_configured(&self) -> bool {
        !self.hackerone_username.trim().is_empty() && !self.hackerone_api_token.trim().is_empty()
    }

    pub fn is_telegram_configured(&self) -> bool {
        !self.telegram_bot_token.trim().is_empty()
    }
}

