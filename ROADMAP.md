# 🗺️ BountyScope Roadmap

Welcome to the BountyScope Community Roadmap. This document tracks our development milestones, architectural vision, and opportunities for community contribution.

---

## 🏁 Phase 1: Core Automation Foundation (Completed ✅)
- [x] **Rust Core Engine:** Fully asynchronous, concurrent job pipeline using Tokio and SQLx SQLite WAL.
- [x] **Scope Guard:** Strict wildcard, domain, and CIDR scope validation with deduplication.
- [x] **19-Tool Security Arsenal:** Adapters for Subfinder, Naabu, HTTPX, DNSX, Katana, GAU, Nuclei v3, Dalfox, SQLMap, Arjun, FFUF, CRLFuzz, KXSS, Gitleaks, GoSpider, Smuggler, ParamSpider, AlterX, Amass.
- [x] **Specialized Rust Scanners:**
  - Takeover Radar (Dangling DNS CNAME verification).
  - JS Miner (Regex extraction of endpoints and leaked secrets).
  - CORS Misconfiguration Scanner.
  - 403 Forbidden Header Bypass Engine.
  - Open Redirect Probe.
- [x] **HackerOne Continuous Sync:** Automated scope change detection and differential alerting.
- [x] **Telegram Control & Bot:** Phone number authentication, command execution, and live status.
- [x] **REST API & Web SOC Dashboard:** Axum API server + Vercel-ready Cyber SOC Web Dashboard.

---

## 🚀 Phase 2: Community & Extensibility (Current Milestones ⏳)
- [ ] **Dynamic Plugin Architecture:** Load custom tool adapters via dynamic libraries or WebAssembly (Wasm).
- [ ] **PostgreSQL & Distributed Storage:** Support PostgreSQL/MySQL for large-scale enterprise deployments alongside SQLite.
- [ ] **AI-Powered Finding Triage:** LLM-assisted false-positive deduplication and severity scoring.
- [ ] **WebSocket Live Telemetry:** Stream real-time scanner terminal logs to the Web Dashboard.
- [ ] **Bugcrowd & Intigriti Adapters:** Extend platform scope synchronizers beyond HackerOne.
- [ ] **Enhanced Evidence Engine:** Capture full HTTP request/response replayable HAR files.

---

## 🔮 Phase 3: Distributed Fleet & Scaling (Future Vision 🔭)
- [ ] **Multi-Node Cluster Execution:** Distributed worker agents coordinated via Redis or gRPC.
- [ ] **Cloud Asset Discovery:** AWS / GCP / Azure asset inventory reconnaissance adapters.
- [ ] **Automated Retesting Engine:** Periodic re-validation of past reported vulnerabilities.
- [ ] **CLI Interactive TUI:** Terminal User Interface using Ratatui for headless terminal power users.

---

## 🌟 Good First Issues for New Contributors

Looking to get involved? Check out these areas:
1. **Tool Adapters:** Add support for new OSINT or reconnaissance tools in `src/tools/`.
2. **Regex Patterns:** Expand the secret scanning patterns in `src/recon/js_miner.rs` or `src/sast/scanner.rs`.
3. **Web Dashboard Widgets:** Enhance visualizations and metrics in `dashboard/app.js`.
4. **Documentation & Guides:** Translate and improve documentation in `docs/`.
