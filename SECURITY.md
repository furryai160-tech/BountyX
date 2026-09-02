# Security Policy

## 🛡️ Safe-by-Default Principles

BountyScope is designed strictly for **authorized security audits, defensive research, and bug bounty programs** where explicit testing permission has been granted.

### Mandatory Safety Guardrails
1. **Strict Scope Enforcement (`ScopeGuard`):**
   - Every target must pass strict validation against the authorized scope whitelist before any active network probe or tool execution.
   - Out-of-scope targets are dropped immediately with an audit log event (`BLOCKED_OUT_OF_SCOPE`).
2. **Non-Destructive Testing:**
   - Adapters must not execute destructive payload commands (e.g., automated SQL drop/delete, denial-of-service stress tests).
   - Tools like `sqlmap` are executed strictly in batch detection mode without automated exploitation payloads.
3. **Audit Trail:**
   - Every tool execution, discovered endpoint, and network activity is immutably logged to SQLite with timestamps and parameters for forensic verification.

---

## ⚖️ Legal Disclaimer

Usage of BountyScope for attacking targets without prior mutual consent is strictly prohibited. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers and maintainers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 🚨 Reporting Security Vulnerabilities in BountyScope

If you discover a security vulnerability within BountyScope itself (such as arbitrary command injection via untrusted target strings, deserialization vulnerabilities, or authentication bypasses), please follow responsible disclosure:

1. **Do not create a public GitHub issue.**
2. Send an advisory via **GitHub Private Security Advisory** under the repository's Security tab, or email the maintainers directly.
3. Include details of the vulnerability, reproduction steps, and potential impact.
4. We aim to acknowledge reports within 48 hours and release fixes in an expedited timeline.
