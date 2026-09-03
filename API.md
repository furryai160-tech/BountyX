# 📡 BountyX V3 API & CLI Specification Reference

This document provides a comprehensive reference for both the **BountyX V3 CLI Commands** and the **Cyber SOC REST API Endpoints**.

---

## 💻 CLI Commands Reference

### 1. Initialization & Diagnostics
```bash
# Initialize local database, directories, and configuration
bountyx init

# Run system doctor, tool checks, and environment verification
bountyx doctor
```

### 2. Scope Policy & Boundary Validation
```bash
# Validate target against autonomous scope rules
bountyx scope validate target.com

# Validate custom YAML scope policy
bountyx scope validate ./scope.yaml

# Synchronize scope targets from HackerOne
bountyx scope sync

# View scope difference summary
bountyx scope diff
```

### 3. Attack Surface Graph Mapping
```bash
# Ingest URLs and build structural attack surface graph
bountyx map example.com
```

### 4. Autonomous AI Security Research Assessment
```bash
# Execute autonomous assessment (Observe -> Hypothesize -> Safely Test -> Validate -> Report)
bountyx assess target.com

# Assess target with custom scope policy and custom output report path
bountyx assess target.com --scope ./scope.yaml --output ./reports/audit.md
```

### 5. Findings & Human Review Gate
```bash
# List recorded security findings
bountyx findings

# Filter findings by severity or status
bountyx findings --status CONFIRMED

# List generated bug bounty draft reports
bountyx reports

# Human Approval Gate: Approve report for external submission
bountyx reports --id rep-12345 --approve "Yasseen Sabry Elawamy"
```

---

## 🌐 Cyber SOC REST API Endpoints

The BountyX HTTP REST API runs on port `8080` (or Railway dynamic `$PORT`) with full CORS support:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Telemetry counters, active worker pool state, findings summary. |
| `GET` | `/api/scope` | List of authorized in-scope assets and CIDRs. |
| `GET` | `/api/findings` | Discovered security findings with severity and status. |
| `GET` | `/api/findings/:id/evidence` | Redacted cURL commands, raw request, and raw response evidence. |
| `GET` | `/api/reports` | List of generated Markdown bug bounty draft reports. |
| `GET` | `/api/queue` | Active reconnaissance jobs and queue backlog. |
| `GET` | `/api/health` | Diagnostic matrix of system tools and system memory. |
| `POST` | `/api/scan` | Trigger a targeted scan or assessment from the web interface. |
| `POST` | `/api/control/pause` | Pause worker execution pool. |
| `POST` | `/api/control/resume` | Resume worker execution pool. |
