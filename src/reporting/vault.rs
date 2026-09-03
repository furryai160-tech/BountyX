use crate::errors::Result;
use crate::reporting::generator::BugBountyReport;
use crate::reporting::pdf::PdfReportGenerator;
use chrono::Utc;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct SubmissionVault;

impl SubmissionVault {
    /// Archives an approved report into the official submission vault:
    /// reports/approved/{REPORT_ID}/
    /// ├── report.md
    /// ├── report.pdf
    /// ├── evidence.json
    /// └── submission.txt
    pub async fn archive_approved_report(
        report: &BugBountyReport,
        reviewer_name: &str,
    ) -> Result<PathBuf> {
        let vault_root = Path::new("reports").join("approved").join(&report.id);
        tokio::fs::create_dir_all(&vault_root).await?;

        // 1. Write full report.md
        let md_content = report.to_markdown();
        let md_path = vault_root.join("report.md");
        tokio::fs::write(&md_path, &md_content).await?;

        // 2. Generate and write report.pdf
        let pdf_path = vault_root.join("report.pdf");
        PdfReportGenerator::generate_pdf(report, &pdf_path).await?;

        // 3. Write evidence.json
        let evidence_json = serde_json::to_string_pretty(&report.findings).unwrap_or_default();
        let evidence_path = vault_root.join("evidence.json");
        tokio::fs::write(&evidence_path, evidence_json).await?;

        // 4. Generate platform-ready submission.txt (HackerOne / Bugcrowd formatted)
        let submission_content = Self::generate_platform_submission_text(report, reviewer_name);
        let sub_path = vault_root.join("submission.txt");
        tokio::fs::write(&sub_path, submission_content).await?;

        info!("✅ Archived approved report package into Submission Vault at: {:?}", vault_root);
        Ok(vault_root)
    }

    /// Pre-formats a platform-ready submission document for instant copy-pasting
    pub fn generate_platform_submission_text(report: &BugBountyReport, reviewer_name: &str) -> String {
        let mut txt = String::new();

        txt.push_str("================================================================================\n");
        txt.push_str("               HACKERONE / BUGCROWD SUBMISSION PACKAGE VAULT                   \n");
        txt.push_str(&format!("Report ID:       {}\n", report.id));
        txt.push_str(&format!("Target Asset:    {}\n", report.target_domain));
        txt.push_str(&format!("Human Reviewer:  {} (Approved at {})\n", reviewer_name, Utc::now().to_rfc3339()));
        txt.push_str("================================================================================\n\n");

        if let Some(primary) = report.findings.first() {
            txt.push_str("[REPORT TITLE / اسم التقرير]\n");
            txt.push_str(&format!("{}: {} on {}\n\n", primary.risk.severity, primary.title, report.target_domain));

            txt.push_str("[VULNERABILITY TYPE / نوع الثغرة]\n");
            txt.push_str(&format!("{}\n\n", primary.category));

            txt.push_str("[SEVERITY / درجة الخطورة]\n");
            txt.push_str(&format!("{} (CVSS 3.1 Base Score: {:.1})\n\n", primary.risk.severity, primary.risk.cvss_score));

            txt.push_str("[AFFECTED ASSET / الرابط المتأثر]\n");
            txt.push_str(&format!("{}\n\n", primary.target_url));

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[SUMMARY / ملخص التقرير جاهز للنسخ]\n");
            txt.push_str(&format!(
                "An authorized security assessment on {} identified a verified {} vulnerability on endpoint {}.\n\
                The finding was validated with reproducible differential network telemetry.\n\n",
                report.target_domain, primary.category, primary.target_url
            ));

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[STEPS TO REPRODUCE / خطوات إعادة التشغيل الآمنة]\n");
            txt.push_str("1. Ensure testing is authorized under the program's bug bounty policy.\n");
            txt.push_str(&format!("2. Execute the following verified cURL proof-of-concept command against {}:\n\n", primary.target_url));
            txt.push_str(&format!("   {}\n\n", primary.evidence.reproduction_curl));
            txt.push_str(&format!("3. Inspect the HTTP response code (HTTP {}) and response payload.\n", primary.evidence.response_status));
            txt.push_str("4. Verify that differential unauthorized data or sensitive administrative access is consistently demonstrated.\n\n");

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[PROOF OF CONCEPT (cURL)]\n");
            txt.push_str(&format!("```bash\n{}\n```\n\n", primary.evidence.reproduction_curl));

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[OBSERVED EVIDENCE TELEMETRY]\n");
            txt.push_str(&format!("HTTP Status: {}\n", primary.evidence.response_status));
            txt.push_str(&format!("Differential Notes: {}\n", primary.evidence.differential_notes));
            txt.push_str("Response Snippet:\n");
            txt.push_str(&format!("{}\n\n", primary.evidence.response_snippet));

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[IMPACT / الأثر الأمني والعملي]\n");
            txt.push_str(&format!(
                "Direct unauthorized access or manipulation of protected tenant resources on {}.\n\
                Violates access control boundaries and may expose sensitive customer or operational data under standard threat models.\n\n",
                report.target_domain
            ));

            txt.push_str("--------------------------------------------------------------------------------\n");
            txt.push_str("[REMEDIATION / الحل المقترح للمطورين]\n");
            txt.push_str(&format!("{}\n", primary.remediation));
        }

        txt.push_str("================================================================================\n");
        txt
    }
}
