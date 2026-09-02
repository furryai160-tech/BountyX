# 🛡️ BountyScope (BountyX)
### Autonomous Rust Security Automation & Bug Bounty Orchestration Engine

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust%202021-orange.svg?style=for-the-badge&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/badge/Tools_Arsenal-19_Engines-green.svg?style=for-the-badge" alt="19 Tools Arsenal">
  <img src="https://img.shields.io/badge/Cloud-Railway_%7C_Docker_%7C_Vercel-purple.svg?style=for-the-badge" alt="Cloud Ready">
  <img src="https://img.shields.io/badge/UI-Cyber_SOC_Dashboard-cyan.svg?style=for-the-badge" alt="Cyber SOC Dashboard">
  <img src="https://img.shields.io/badge/Community-Open_Source-brightgreen.svg?style=for-the-badge" alt="Open Source">
</p>

<p align="center">
  <b>BountyScope</b> is an open-source, high-performance security automation and reconnaissance orchestration engine written in <b>Rust</b>. Designed for authorized security research, continuous asset discovery, and professional bug bounty workflows with <b>zero unauthorized probing</b>.
</p>

---

## 🌟 Why BountyScope?

Most bug bounty automation setups are fragile collections of bash scripts that lack state persistence, duplicate network requests, and easily run out of scope. 

**BountyScope replaces shell scripts with an enterprise-grade Rust core:**
- 🦀 **Async Concurrency:** Powered by `Tokio` and a worker queue supporting configurable concurrent jobs with graceful shutdown.
- 🛡️ **Strict Scope Guard:** Every target, IP, and URL must validate against authorized wildcard and CIDR scope rules before active execution.
- 🗄️ **Persistent SQLite WAL Storage:** Stores programs, assets, discovered endpoints, HTTP hosts, findings, and forensic audit logs.
- 🔄 **Continuous Platform Sync:** Automatically synchronizes scope changes from platforms like HackerOne every 5 minutes and flags diffs.
- 🧩 **19-Tool Automated Pipeline:** Seamlessly orchestrates leading open-source security tools alongside native Rust analyzers.
- 📊 **Cyber SOC Web Dashboard:** Dark Glassmorphism interface deployable to **Vercel** with real-time telemetry and POC evidence viewer.
- 🤖 **Interactive Telegram Bot:** Secure phone-authenticated bot with interactive control keyboards and instant vulnerability alerts.

---

## 🛠️ The 19-Tool Security Arsenal

BountyScope coordinates 19 industry-standard security tools and 5 custom native Rust scanning engines:

| Category | Tools Orchestrated | Purpose |
|---|---|---|
| **Subdomain Recon** | `subfinder`, `alterx`, `amass` | Passive discovery and permutation wordlists |
| **DNS & Resolution** | `dnsx` | High-speed DNS resolution, wildcard filtering, and CNAME extraction |
| **Dangling CNAMEs** | `Takeover Radar` *(Rust)* | Instant verification of dangling CNAMEs (AWS S3, GitHub Pages, Heroku, Azure...) |
| **Port Scanning** | `naabu` | High-speed SYN port discovery for exposed services |
| **Web Probing** | `httpx` | Live web probing, tech stack fingerprinting, and status codes |
| **Web Crawling** | `katana`, `gau`, `gospider` | Dynamic headless crawling, form extraction, and historical archive URLs |
| **Secrets & Endpoints** | `JS Miner` *(Rust)*, `gitleaks` | Automated regex parsing of JavaScript files for internal endpoints & leaked keys |
| **Parameter Mining** | `arjun`, `paramspider` | Hidden parameter discovery for query, body, and JSON requests |
| **Surgical Vulnerabilities**| `nuclei v3` | Rapid CVE detection with targeted severity templates (Critical, High, Medium) |
| **XSS & Injection** | `dalfox`, `kxss` | Context-aware reflection verification and DOM XSS hunting |
| **SQL Injection** | `sqlmap` | Non-destructive detection of SQL injection attack vectors |
| **CRLF & Smuggling** | `crlfuzz`, `smuggler` | HTTP request smuggling and CRLF header injection probes |
| **Directory Fuzzing** | `ffuf` | High-speed directory and endpoint discovery |
| **Web Defense Bypasses**| `CORS Scanner` *(Rust)*, `Bypass 403` *(Rust)* | Misconfigured Access-Control headers and 403 authorization bypasses |

---

## 🏛️ System Architecture

```
                                    ┌────────────────────────────┐
                                    │    HackerOne REST API      │
                                    └──────────────┬─────────────┘
                                                   │ (Every 300s)
                                                   ▼
┌────────────────────────────┐      ┌────────────────────────────┐      ┌────────────────────────────┐
│   Cyber SOC Web Dashboard  │◄────►│   BountyScope Core Engine  │◄────►│    Interactive Telegram    │
│    (Deploy on Vercel)      │ REST │      (Rust Async Daemon)   │ Bot  │     Bot & Notifications    │
└────────────────────────────┘      └──────────────┬─────────────┘      └────────────────────────────┘
                                                   │
                                    ┌──────────────┴─────────────┐
                                    │     Scope Guard (Safety)   │
                                    └──────────────┬─────────────┘
                                                   │ [Validated]
                                                   ▼
                                    ┌────────────────────────────┐
                                    │    19-Tool Recon Pipeline  │
                                    │ (Subfinder ➔ Nuclei ➔ ...) │
                                    └──────────────┬─────────────┘
                                                   │
                                    ┌──────────────┴─────────────┐
                                    │ Evidence & Markdown Report │
                                    └────────────────────────────┘
```

For complete technical specifications, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 🚀 Quick Start

### 1. Run via Docker Compose (Recommended)
```bash
git clone https://github.com/furryai160-tech/BountyX.git
cd BountyX

# Copy environment template
cp .env.example .env
# Edit .env with your Telegram bot token and credentials

# Build and start container
docker compose up -d
```

### 2. Local Build (Debian / Kali Linux)
```bash
# Install system dependencies
sudo apt-get update && sudo apt-get install -y libsqlite3-dev pkg-config build-essential

# Check environment health
cargo run -- health

# Start continuous monitoring engine
cargo run -- monitor

# Or execute a single targeted scan
cargo run -- scan example.com
```

### 3. Deploy Backend to Railway
The repository includes a ready `Dockerfile` and `railway.toml`. Simply import this repository into [Railway.app](https://railway.app) and configure your environment variables.

### 4. Deploy Frontend to Vercel
The frontend dashboard in `dashboard/` is ready for instant deployment to [Vercel](https://vercel.com). Import the repo, hit **Deploy**, and enter your Railway backend URL!

---

## 🛡️ Safe-by-Default Principles

BountyScope enforces strict defensive guardrails:
1. **Zero Out-of-Scope Execution:** Every target must be validated by `ScopeGuard` before active scanning begins.
2. **Safe Payloads:** Active scanners run in non-destructive detection mode.
3. **Forensic Audit Logging:** Every executed tool, target, and outcome is permanently logged in SQLite.

Please read our [SECURITY.md](SECURITY.md) policy for responsible disclosure guidelines.

---

## 🤝 Contributing & Community Roadmap

We welcome contributions from security researchers and software engineers worldwide! 

- Read our [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
- Review our [ROADMAP.md](ROADMAP.md) to explore upcoming features like AI finding triage, distributed workers, and custom WASM plugin architecture.
- Check open issues labeled `good first issue` and `help wanted`.

Please review our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

<p align="center">
  Made with ❤️ by the BountyScope Open Source Community.<br>
  <b>Developed & Architected by:</b> Yasseen Sabry Elawamy<br>
  تم التطوير بواسطة: <b>ياسين صبري العوامي</b>
</p>

