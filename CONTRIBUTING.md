# 🤝 Contributing to BountyScope

Thank you for your interest in contributing to **BountyScope**! We welcome security researchers, Rust developers, and open-source enthusiasts of all skill levels.

---

## 🛠️ Local Development Setup

### Prerequisites
- **Rust Toolchain:** Stable 1.80+ (recommended: latest stable). Install via [rustup.rs](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **SQLite Development Libraries:**
  ```bash
  # Debian / Ubuntu / Kali Linux
  sudo apt-get update && sudo apt-get install -y libsqlite3-dev pkg-config build-essential
  
  # macOS
  brew install sqlite
  ```

### Clone & Build
```bash
git clone https://github.com/furryai160-tech/BountyX.git
cd BountyX

# Build debug binary
cargo build

# Run unit and integration tests
cargo test

# Run health check against your local environment
cargo run -- health
```

---

## 🚀 Contribution Workflow

1. **Find or Create an Issue:**
   - Check open issues marked with `good first issue` or `help wanted`.
   - If proposing a major feature or new tool adapter, please open an Issue first to discuss design.
2. **Fork and Branch:**
   ```bash
   git checkout -b feat/my-new-feature
   ```
3. **Write Tests:**
   - Any new scanner, tool adapter, or parser must include unit tests under `tests/`.
4. **Code Quality Standards:**
   - Format your code:
     ```bash
     cargo fmt --all
     ```
   - Run Clippy and ensure zero warnings:
     ```bash
     cargo clippy -- -D warnings
     ```
   - Verify all tests pass:
     ```bash
     cargo test
     ```
5. **Open a Pull Request:**
   - Submit a PR against the `main` branch.
   - Use our Pull Request template to summarize your changes and verify safety compliance.

---

## 🛡️ Scope Guard & Safety Policy for PRs

Because BountyScope is an automated security orchestrator, **safety and auditability are non-negotiable core principles**:

- ❌ **No Destructive Exploits:** Any tool adapter that performs automated destructive operations (dropping databases, changing credentials, denial of service) will be rejected.
- ✅ **Scope Enforcement:** Every network action must check `ScopeGuard::is_in_scope()`.
- ✅ **Audit Logging:** Any new target discovery or scanning event must log an audit record via `repository.record_audit_event()`.

---

## 💡 Where to Contribute

- 🦀 **Rust Core:** Optimize async concurrency, job queue scheduling, and memory efficiency.
- 🧩 **Tool Adapters:** Add new tools in `src/tools/` (e.g., Ksubdomain, Masscan, TruffleHog).
- 🔬 **Vulnerability Scanners:** Add native Rust heuristics for Prototype Pollution, SSRF detection, and JWT misconfigurations.
- 📊 **Web Dashboard:** Enhance the frontend in `dashboard/` with charts, real-time log viewers, and filters.
- 📱 **Telegram Bot:** Add new interactive commands and customizable alert templates.
- 📚 **Documentation:** Improve guides, deployment tutorials, and architecture diagrams.
