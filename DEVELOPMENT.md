# 🛠️ BountyX V3 Local Development & Testing Guide

This guide covers everything required to develop, test, and contribute to **BountyX V3**.

---

## 📋 Prerequisites
- **Rust Toolchain:** 1.80+ (stable). Install via `rustup`:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **System Libraries:**
  ```bash
  # Debian / Ubuntu / Kali Linux
  sudo apt-get update && sudo apt-get install -y libsqlite3-dev pkg-config build-essential
  
  # macOS
  brew install sqlite
  ```

---

## 🧪 Running the Test Suites

BountyX V3 includes comprehensive unit and integration test suites covering the entire platform:

```bash
# 1. Run all unit and integration tests
cargo test

# 2. Test the Scope Guard & Policy Engine
cargo test --test scope_guard_v3_tests

# 3. Test the Autonomous AI Security Agent with local simulation lab
cargo test --test ai_research_agent_v3_tests

# 4. Test Attack Surface Deduplication & Normalization
cargo test --test dedup_tests

# 5. Test Tool Adapters & Parsers
cargo test --test tools_tests
```

---

## 🚀 Building & Running Locally

```bash
# Build optimized release binary
cargo build --release

# Run system health diagnostics
cargo run -- doctor

# Run dry-run simulation against a target
cargo run -- scan example.com --dry-run

# Run autonomous AI assessment
cargo run -- assess example.com
```

---

## 🛡️ Coding & Safety Guidelines
- Always verify code formatting: `cargo fmt --all -- --check`
- Always verify linting: `cargo clippy -- -D warnings`
- Never bypass the `ScopeGuard` when implementing network operations.
- Ensure all sensitive data (tokens, passwords, authorization headers) is redacted via `SecretRedactor`.
