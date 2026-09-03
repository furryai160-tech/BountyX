use bountyscope::reporting::generator::BugBountyReport;
use bountyscope::reporting::vault::SubmissionVault;
use bountyscope::security::evidence::EvidenceBundle;
use bountyscope::security::risk::{RiskAssessment, Severity};
use bountyscope::security::validator::{FindingStatus, VerifiedFinding};
use chrono::Utc;
use std::collections::HashMap;

#[tokio::test]
async fn test_submission_vault_archives_all_artifacts() {
    let finding = VerifiedFinding {
        id: "find-vault-test-1".to_string(),
        title: "BOLA IDOR on Order Endpoint".to_string(),
        category: "Broken Access Control (BOLA/IDOR)".to_string(),
        status: FindingStatus::Confirmed,
        target_url: "https://api.target.com/api/v1/orders/999".to_string(),
        risk: RiskAssessment {
            severity: Severity::High,
            cvss_score: 8.1,
            impact_score: 6,
            confidence_score: 95,
            reasoning: "Confirmed unauthorized tenant order exposure".to_string(),
        },
        evidence: EvidenceBundle {
            finding_id: "find-vault-test-1".to_string(),
            timestamp: Utc::now(),
            target_url: "https://api.target.com/api/v1/orders/999".to_string(),
            method: "GET".to_string(),
            request_headers: HashMap::new(),
            request_body: None,
            response_status: 200,
            response_headers: HashMap::new(),
            response_snippet: r#"{"order": 999, "owner": "victim@domain.internal"}"#.to_string(),
            reproduction_curl: "curl -i -s https://api.target.com/api/v1/orders/999".to_string(),
            differential_notes: "Differential baseline comparison verified cross-tenant leak".to_string(),
        },
        remediation: "Enforce strict tenant authorization checks on object identifiers.".to_string(),
    };

    let mut report = BugBountyReport::new("api.target.com", vec![finding]);
    report.approve("Yasseen Sabry Elawamy");

    let vault_path = SubmissionVault::archive_approved_report(&report, "Yasseen Sabry Elawamy")
        .await
        .expect("Vault archiving must succeed");

    assert!(vault_path.exists(), "Vault directory must exist");
    assert!(vault_path.join("report.md").exists(), "report.md must be written");
    assert!(vault_path.join("report.pdf").exists(), "report.pdf must be generated");
    assert!(vault_path.join("evidence.json").exists(), "evidence.json must be written");
    assert!(vault_path.join("submission.txt").exists(), "submission.txt must be written");

    // Verify submission.txt contains pre-formatted HackerOne copy-paste sections
    let sub_content = tokio::fs::read_to_string(vault_path.join("submission.txt"))
        .await
        .expect("Must read submission.txt");

    assert!(sub_content.contains("HACKERONE / BUGCROWD SUBMISSION PACKAGE VAULT"));
    assert!(sub_content.contains("[REPORT TITLE / اسم التقرير]"));
    assert!(sub_content.contains("[STEPS TO REPRODUCE / خطوات إعادة التشغيل الآمنة]"));
    assert!(sub_content.contains("curl -i -s https://api.target.com/api/v1/orders/999"));
    assert!(sub_content.contains("[PROOF OF CONCEPT (cURL)]"));
    assert!(sub_content.contains("[REMEDIATION / الحل المقترح للمطورين]"));
    assert!(sub_content.contains("Yasseen Sabry Elawamy"));
}
