use crate::ai::memory::AgentMemory;
use crate::ai::planner::{AgentPlanner, SecurityHypothesis};
use crate::ai::tool_router::{AgentTool, ToolRouter};
use crate::attack_surface::mapper::AttackSurfaceMapper;
use crate::errors::Result;
use crate::sandbox::client::SandboxedHttpClient;
use crate::security::validator::{FindingValidator, VerifiedFinding};
use tracing::{info, warn};

pub struct AutonomousSecurityAgent {
    pub memory: AgentMemory,
    pub http_client: SandboxedHttpClient,
}

impl AutonomousSecurityAgent {
    pub fn new(http_client: SandboxedHttpClient) -> Self {
        Self {
            memory: AgentMemory::new(),
            http_client,
        }
    }

    /// Primary autonomous research assessment loop
    pub async fn run_assessment(
        &mut self,
        target_domain: &str,
        base_url: &str,
        discovered_urls: &[String],
    ) -> Result<Vec<VerifiedFinding>> {
        info!("🤖 [Agent] Starting Autonomous Assessment on target: {}", target_domain);

        // 1. OBSERVE & UNDERSTAND: Map attack surface into structural graph
        info!("🗺️ [Agent] Ingesting {} discovered URLs into Attack Surface Graph...", discovered_urls.len());
        for url in discovered_urls {
            AttackSurfaceMapper::ingest_url(&mut self.memory.assessment.graph, target_domain, url, "GET");
        }

        info!(
            "📊 [Agent] Attack Surface Graph mapped: {} nodes, {} edges",
            self.memory.assessment.graph.node_count(),
            self.memory.assessment.graph.edge_count()
        );

        // 2. HYPOTHESIZE: Formulate security hypotheses based on graph and knowledge base
        let hypotheses = AgentPlanner::formulate_hypotheses(base_url, &self.memory);
        info!("💡 [Agent] Formulated {} security hypotheses for verification", hypotheses.len());

        let total_hyp = hypotheses.len();
        let mut confirmed_findings = Vec::new();

        // 3. PLAN, TEST & VALIDATE LOOP
        for (idx, hyp) in hypotheses.into_iter().enumerate() {
            if self.http_client.kill_switch().is_triggered() {
                warn!("🛑 [Agent] Assessment aborted early: Kill switch was triggered.");
                break;
            }

            info!(
                "🔬 [Agent] [{}/{}] Testing Hypothesis: {} ({})",
                idx + 1,
                total_hyp,
                hyp.title,
                hyp.target_url
            );


            // Execute test tool through sandboxed router
            let test_res = ToolRouter::execute_tool(
                &self.http_client,
                AgentTool::TestHypothesis {
                    hypothesis: hyp.clone(),
                },
            )
            .await;

            match test_res {
                Ok(resp) => {
                    // Validate hypothesis and eliminate false positives
                    if let Some(finding) = FindingValidator::validate_hypothesis(
                        &self.http_client,
                        &hyp,
                        &resp,
                        None,
                    )
                    .await
                    {
                        info!(
                            "🚨 [Agent] Finding Validated! [{}] {} (Confidence: {}%)",
                            finding.risk.severity, finding.title, finding.risk.confidence_score
                        );
                        confirmed_findings.push(finding);
                    }
                }
                Err(err) => {
                    warn!("⚠️ [Agent] Probe skipped: {}", err);
                }
            }
        }

        info!(
            "🏁 [Agent] Assessment complete. Total confirmed findings: {}",
            confirmed_findings.len()
        );

        Ok(confirmed_findings)
    }
}
