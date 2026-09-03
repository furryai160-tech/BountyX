use crate::reporting::ai_writer::{EvidencePackage, SmartReportWriter};
use crate::security::validator::VerifiedFinding;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugBountyReport {
    pub id: String,
    pub title: String,
    pub target_domain: String,
    pub generated_at: DateTime<Utc>,
    pub is_approved_by_human: bool,
    pub approved_by: Option<String>,
    pub approval_timestamp: Option<DateTime<Utc>>,
    pub findings: Vec<VerifiedFinding>,
}

impl BugBountyReport {
    pub fn new(target_domain: &str, findings: Vec<VerifiedFinding>) -> Self {
        Self {
            id: format!("rep-{}", uuid::Uuid::new_v4().simple()),
            title: format!("BountyX Autonomous Security Assessment — {}", target_domain),
            target_domain: target_domain.to_string(),
            generated_at: Utc::now(),
            is_approved_by_human: false,
            approved_by: None,
            approval_timestamp: None,
            findings,
        }
    }

    /// Human-in-the-Loop approval gate
    pub fn approve(&mut self, reviewer_name: &str) {
        self.is_approved_by_human = true;
        self.approved_by = Some(reviewer_name.to_string());
        self.approval_timestamp = Some(Utc::now());
    }

    pub fn can_submit_externally(&self) -> bool {
        self.is_approved_by_human
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Synthesize executive-grade report using AI Smart Report Writer with deterministic CVSS & Anti-Hallucination Gate
    pub fn to_markdown(&self) -> String {
        let packages: Vec<EvidencePackage> = self.findings.iter().map(EvidencePackage::from).collect();
        let mut draft = SmartReportWriter::generate_report(&self.target_domain, &packages);
        draft.id = self.id.clone();
        draft.is_approved_by_human = self.is_approved_by_human;
        draft.approved_by = self.approved_by.clone();
        draft.approval_timestamp = self.approval_timestamp;
        draft.to_markdown()
    }
}
