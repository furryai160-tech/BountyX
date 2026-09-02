## 📌 Description of Changes
Please provide a clear summary of what this PR introduces, modifies, or fixes.

## 🧱 Category of Change
- [ ] 🦀 Rust Core & Pipeline
- [ ] 🛡️ Scope Guard & Safety Hardening
- [ ] 🧩 New Tool Adapter (`src/tools/`)
- [ ] 🔬 Vulnerability Scanner / Heuristics
- [ ] 📊 Web Dashboard & REST API
- [ ] 🤖 Telegram Bot & Notifications
- [ ] 🧪 Tests & Fuzzing
- [ ] 📚 Documentation

## 🛡️ Scope Guard & Safety Checklist
- [ ] Does this change respect in-scope asset boundaries defined by `ScopeGuard`?
- [ ] Does this change avoid unsafe/destructive actions by default?
- [ ] Are audit events recorded for any new reconnaissance actions?

## 🧪 Quality Assurance & Testing
- [ ] `cargo check --all-targets` passes without warnings
- [ ] `cargo test` passes
- [ ] `cargo fmt -- --check` has been run
- [ ] New unit or integration tests have been added for the changes
