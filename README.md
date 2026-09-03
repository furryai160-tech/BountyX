# 🛡️ BountyX V3 — Autonomous AI Security Research Platform
### Autonomous AI Security Research, Attack Surface Mapping & Bug Bounty Orchestration Engine

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0.0--Enterprise-blue.svg?style=for-the-badge" alt="V3.0 Enterprise">
  <img src="https://img.shields.io/badge/Language-Rust%202021-orange.svg?style=for-the-badge&logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/badge/AI_Agent-Reasoning_%26_Planning-purple.svg?style=for-the-badge" alt="AI Reasoning">
  <img src="https://img.shields.io/badge/Scope_Guard-Non--Bypassable-red.svg?style=for-the-badge" alt="Scope Guard Safe">
  <img src="https://img.shields.io/badge/Platform-Railway_%7C_Vercel_%7C_Docker-cyan.svg?style=for-the-badge" alt="Cloud Ready">
</p>

<p align="center">
  <b>BountyX V3</b> is an open-source, production-grade <b>Autonomous AI Security Research Platform</b> written in <b>Rust</b>. Designed to act as an autonomous security researcher that understands scope rules, maps attack surfaces into structural graph memory, formulates evidence-based hypotheses, executes sandboxed tests, and eliminates false positives with zero unauthorized probing.
</p>

---

## 🌟 The V3 Paradigm Shift: AI-Assisted Security Research

BountyX V3 is neither a simple vulnerability scanner nor a generic chatbot. It implements a rigorous, hypothesis-driven scientific testing cycle:

```text
OBSERVE ➔ UNDERSTAND ➔ HYPOTHESIZE ➔ PLAN ➔ SAFELY TEST ➔ ANALYZE ➔ VALIDATE ➔ UPDATE KNOWLEDGE
```

1. **🛡️ Non-Bypassable Scope Guard:** Hard-coded security boundary checking wildcard domains, CIDRs, forbidden paths, and request quotas before every network probe.
2. **🗺️ Attack Surface Graph Memory:** Converts recon data into a directed graph tracking hosts, endpoints, parameters, authentication boundaries, and object relationships.
3. **🧠 3-Layer AI Agent Memory:** Short-Term Test Memory, Assessment Memory, and OWASP Security Knowledge Base.
4. **🔬 Multi-Stage Finding Validator:** Every detection undergoes reproduction probing and differential analysis before being confirmed.
5. **🔏 Secret Redaction & Evidence Bundles:** Automatically redacts tokens, credentials, and cookies from evidence captures.
6. **⚖️ Human Approval Gate:** Reports cannot be submitted externally without explicit human review and approval.


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

### 2. Local CLI Commands
```bash
# Run system doctor and tool checks
cargo run -- doctor

# Validate target or custom scope policy
cargo run -- scope validate example.com

# Map attack surface graph
cargo run -- map example.com

# Run autonomous AI security research assessment
cargo run -- assess example.com

# Review findings & approve report for submission
cargo run -- findings
cargo run -- reports --id rep-12345 --approve "Yasseen Sabry Elawamy"
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

