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

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str(&format!("# {}\n\n", self.title));
        md.push_str(&format!("- **Target Asset:** `{}`\n", self.target_domain));
        md.push_str(&format!("- **Generated At:** `{}`\n", self.generated_at.to_rfc3339()));
        md.push_str(&format!(
            "- **Human Review Status:** {}\n\n",
            if self.is_approved_by_human {
                format!("✅ APPROVED by `{}` on `{}`", self.approved_by.as_deref().unwrap_or("Unknown"), self.approval_timestamp.map(|t| t.to_rfc3339()).unwrap_or_default())
            } else {
                "⚠️ PENDING HUMAN REVIEW (External submission blocked)".to_string()
            }
        ));

        md.push_str("## 📊 Executive Findings Summary\n\n");
        md.push_str("| Finding ID | Severity | Confidence | Category | Title |\n");
        md.push_str("|---|---|---|---|---|\n");

        for f in &self.findings {
            md.push_str(&format!(
                "| `{}` | **{}** | {}% | {} | {} |\n",
                f.id, f.risk.severity, f.risk.confidence_score, f.category, f.title
            ));
        }
        md.push_str("\n---\n\n");

        for (idx, f) in self.findings.iter().enumerate() {
            md.push_str(&format!("### {}. {}\n\n", idx + 1, f.title));
            md.push_str(&format!("- **Finding ID:** `{}`\n", f.id));
            md.push_str(&format!("- **Severity:** **{}** (CVSS: {:.1})\n", f.risk.severity, f.risk.cvss_score));
            md.push_str(&format!("- **Confidence Score:** {}%\n", f.risk.confidence_score));
            md.push_str(&format!("- **Vulnerable Endpoint:** `{}`\n\n", f.target_url));

            md.push_str("#### 📝 Description & Risk Reasoning\n");
            md.push_str(&format!("{}\n\n", f.risk.reasoning));

            md.push_str("#### 🔁 Step-by-Step Reproduction Proof of Concept\n");
            md.push_str("Execute the following verified cURL command against the authorized target:\n");
            md.push_str(&format!("```bash\n{}\n```\n\n", f.evidence.reproduction_curl));

            md.push_str("#### 🔬 Observed Response Evidence\n");
            md.push_str(&format!("- **HTTP Status:** `{}`\n", f.evidence.response_status));
            md.push_str(&format!("- **Differential Notes:** {}\n", f.evidence.differential_notes));
            md.push_str("```json\n");
            md.push_str(&f.evidence.response_snippet);
            md.push_str("\n```\n\n");

            md.push_str("#### 💡 Remediation Guidance\n");
            md.push_str(&format!("{}\n\n", f.remediation));
            md.push_str("---\n\n");
        }

        md.push_str("\n*Generated autonomously by BountyX V3 AI Security Research Platform with Human-in-the-Loop verification.*\n");
        md
    }
}
