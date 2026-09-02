---
name: "🧩 New Tool Adapter Proposal"
about: Propose integrating a new security reconnaissance or vulnerability tool
title: "[TOOL] Add adapter for "
labels: ["tool-adapter", "community"]
assignees: ""
---

### 🛠️ Tool Overview
- **Tool Name:** 
- **Repository / Homepage:** 
- **Language / Runtime:** (e.g., Go, Python, Rust, C)
- **Primary Function:** (e.g., Subdomain Enumeration, Parameter Fuzzing, Secrets Scanning)

### 🛡️ Safe-by-Default & Scope Compliance
- Does this tool support scoped execution (limiting to specific host/CIDR)?
- Does this tool support non-destructive / passive-only mode?
- How are rate limits / concurrency controlled?

### 📥 Input & Output Specification
- **Input expected:** (e.g., list of hosts via stdin, target URL via flag)
- **Output format:** (e.g., JSON Lines, standard text, CSV)
- **Proposed Adapter location:** `src/tools/<tool_name>.rs`
