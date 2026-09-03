# 🔌 BountyX V3 Plugin Architecture & Extension Guide

BountyX V3 features a modular, safe-by-default plugin architecture that allows security researchers to extend the platform with custom tool adapters, specialized vulnerability detectors, and reconnaissance miners.

---

## 🏛️ Plugin Design Principles

1. **Declared Permissions & Capabilities:** Every plugin must explicitly declare the actions it intends to perform (e.g., `PassiveRecon`, `ActiveNetworkProbe`, `LocalFileInspection`).
2. **Mandatory Scope Compliance:** No plugin can execute network requests directly without routing through the `ScopeGuard` and `SandboxedHttpClient`.
3. **Safe-by-Default Execution:** Destructive payload execution, Denial-of-Service stress tests, and automated data deletion are strictly forbidden.

---

## 🧱 Plugin Manifest Structure

A plugin is declared with the following specification:

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCapability {
    SubdomainRecon,
    PortScanning,
    EndpointCrawling,
    VulnerabilityDetector,
    EvidenceEnricher,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<PluginCapability>,
    pub requires_binaries: Vec<String>,
}
```

---

## 🛠️ Implementing a Custom Security Detector Plugin

All custom detectors implement the `SecurityDetector` trait:

```rust
#[async_trait]
pub trait SecurityDetector: Send + Sync {
    /// Returns the unique rule identifier (e.g., "sec-custom-jwt-none")
    fn id(&self) -> &'static str;

    /// Formulates security hypotheses based on the attack surface graph
    fn formulate_hypotheses(
        &self,
        graph: &AttackSurfaceGraph,
        base_url: &str,
    ) -> Vec<SecurityHypothesis>;

    /// Executes sandboxed verification against a target hypothesis
    async fn verify(
        &self,
        client: &SandboxedHttpClient,
        hypothesis: &SecurityHypothesis,
    ) -> Option<VerifiedFinding>;
}
```

---

## 🧪 Testing Your Plugin

Plugins must be verified in local sandbox labs before being merged into the core repository:

1. Place your detector in `src/security/detectors/<my_detector>.rs`.
2. Add comprehensive unit tests verifying that benign targets yield **0 false positives** and vulnerable targets yield **100% confirmed findings**.
3. Run:
   ```bash
   cargo test --test <my_detector>_tests
   ```
