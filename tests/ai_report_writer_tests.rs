use bountyscope::reporting::ai_writer::{
    AntiHallucinationGate, EvidencePackage, SmartReportWriter, VerificationStatus,
};
use bountyscope::reporting::cvss::{
    AttackComplexity, AttackVector, Cvss31Engine, Cvss31Metrics, CvssScope, ImpactMetric, PrivilegesRequired, UserInteraction,
};
use bountyscope::security::risk::Severity;

#[test]
fn test_deterministic_cvss31_calculator() {
    // 1. Critical BOLA/RCE vector: Network, Low Complexity, No Privileges, No User Interaction, High C/I/A
    let critical_metrics = Cvss31Metrics {
        attack_vector: AttackVector::Network,
        attack_complexity: AttackComplexity::Low,
        privileges_required: PrivilegesRequired::None,
        user_interaction: UserInteraction::None,
        scope: CvssScope::Unchanged,
        confidentiality: ImpactMetric::High,
        integrity: ImpactMetric::High,
        availability: ImpactMetric::High,
    };

    let (score, vector, sev) = Cvss31Engine::calculate_base_score(&critical_metrics);
    assert_eq!(score, 9.8);
    assert_eq!(sev, Severity::Critical);
    assert_eq!(vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

    // 2. Low Severity Header vector
    let low_metrics = Cvss31Metrics {
        attack_vector: AttackVector::Network,
        attack_complexity: AttackComplexity::High,
        privileges_required: PrivilegesRequired::None,
        user_interaction: UserInteraction::Required,
        scope: CvssScope::Unchanged,
        confidentiality: ImpactMetric::None,
        integrity: ImpactMetric::Low,
        availability: ImpactMetric::None,
    };

    let (score_low, vector_low, sev_low) = Cvss31Engine::calculate_base_score(&low_metrics);
    assert!(score_low <= 3.9);
    assert_eq!(sev_low, Severity::Low);
    assert_eq!(vector_low, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N");
}

#[test]
fn test_anti_hallucination_gate_enforces_evidence() {
    let unproven_package = EvidencePackage {
        finding_id: "find-unverified-1".to_string(),
        target_domain: "example.com".to_string(),
        endpoint: "https://example.com/api/test".to_string(),
        http_method: "GET".to_string(),
        category: "Information Disclosure".to_string(),
        request_sent: None,
        response_status: 0, // Missing HTTP status
        response_snippet: "generic html page".to_string(),
        differential_notes: "heuristic only".to_string(),
        reproduction_curl: "".to_string(), // Missing cURL
        evidence_confidence: 40,
        ai_confidence: 50,
        raw_finding_title: "Suspected Exposure".to_string(),
    };

    let unverified_aspects = AntiHallucinationGate::audit_evidence(&unproven_package);
    assert!(!unverified_aspects.is_empty());
    assert!(unverified_aspects.iter().any(|u| u.contains("cURL")));
    assert!(unverified_aspects.iter().any(|u| u.contains("رمز استجابة")));

    let block = SmartReportWriter::synthesize_finding_block(&unproven_package);
    assert_eq!(block.verification_status, VerificationStatus::RequiresHumanReview);
    assert!(!block.unverified_aspects.is_empty());
}

#[test]
fn test_dual_confidence_and_verification_status() {
    let verified_package = EvidencePackage {
        finding_id: "find-bola-101".to_string(),
        target_domain: "api.target.com".to_string(),
        endpoint: "https://api.target.com/api/v1/orders/101".to_string(),
        http_method: "GET".to_string(),
        category: "Broken Object Level Authorization (BOLA)".to_string(),
        request_sent: Some("curl https://api.target.com/api/v1/orders/101".to_string()),
        response_status: 200,
        response_snippet: r#"{"order_id": 101, "tenant_token": "secret_token_live"}"#.to_string(),
        differential_notes: "Differential comparison confirmed unauthorized tenant data exposed".to_string(),
        reproduction_curl: "curl -i -s https://api.target.com/api/v1/orders/101".to_string(),
        evidence_confidence: 95,
        ai_confidence: 92,
        raw_finding_title: "BOLA on orders endpoint".to_string(),
    };

    let block = SmartReportWriter::synthesize_finding_block(&verified_package);
    assert_eq!(block.evidence_confidence, 95);
    assert_eq!(block.ai_confidence, 92);
    assert_eq!(block.verification_status, VerificationStatus::Confirmed);
    assert_eq!(block.severity, Severity::High);
    assert!(block.cvss_base_score >= 7.0);
}

#[test]
fn test_deduplication_and_severity_ordering() {
    let pkg_low = EvidencePackage {
        finding_id: "find-1".to_string(),
        target_domain: "target.com".to_string(),
        endpoint: "https://target.com/index.html".to_string(),
        http_method: "GET".to_string(),
        category: "Missing Clickjacking Defense Headers".to_string(),
        request_sent: Some("curl".to_string()),
        response_status: 200,
        response_snippet: "<html>ok</html>".to_string(),
        differential_notes: "X-Frame-Options missing".to_string(),
        reproduction_curl: "curl https://target.com/index.html".to_string(),
        evidence_confidence: 80,
        ai_confidence: 85,
        raw_finding_title: "Missing XFO".to_string(),
    };

    // Duplicate of pkg_low
    let pkg_low_dup = EvidencePackage {
        finding_id: "find-2".to_string(),
        target_domain: "target.com".to_string(),
        endpoint: "https://target.com/index.html".to_string(),
        http_method: "GET".to_string(),
        category: "Missing Clickjacking Defense Headers".to_string(),
        request_sent: Some("curl".to_string()),
        response_status: 200,
        response_snippet: "<html>ok</html>".to_string(),
        differential_notes: "X-Frame-Options missing again".to_string(),
        reproduction_curl: "curl https://target.com/index.html".to_string(),
        evidence_confidence: 80,
        ai_confidence: 85,
        raw_finding_title: "Missing XFO Duplicate".to_string(),
    };

    let pkg_high = EvidencePackage {
        finding_id: "find-3".to_string(),
        target_domain: "target.com".to_string(),
        endpoint: "https://target.com/admin/telemetry".to_string(),
        http_method: "GET".to_string(),
        category: "Exposed Privileged Administrative Interface".to_string(),
        request_sent: Some("curl".to_string()),
        response_status: 200,
        response_snippet: r#"{"admin": true, "session": "root"}"#.to_string(),
        differential_notes: "Unauthenticated admin telemetry access".to_string(),
        reproduction_curl: "curl https://target.com/admin/telemetry".to_string(),
        evidence_confidence: 95,
        ai_confidence: 92,
        raw_finding_title: "Admin exposure".to_string(),
    };

    let packages = vec![pkg_low, pkg_low_dup, pkg_high];
    let draft = SmartReportWriter::generate_report("target.com", &packages);

    // Assert deduplication happened: 3 input packages -> 2 unique findings
    assert_eq!(draft.total_evidence_analyzed, 3);
    assert_eq!(draft.deduplicated_findings_count, 2);
    assert_eq!(draft.findings.len(), 2);

    // Assert strict severity sorting: High must come before Low
    assert_eq!(draft.findings[0].severity, Severity::High);
    assert_eq!(draft.findings[1].severity, Severity::Low);

    // Assert markdown rendering includes executive structure
    let markdown = draft.to_markdown();
    assert!(markdown.contains("# BountyX Autonomous Security Assessment — target.com"));
    assert!(markdown.contains("Evidence Conf."));
    assert!(markdown.contains("AI Conf."));
    assert!(markdown.contains("Deterministic CVSS v3.1"));
    assert!(markdown.contains("Actionable Remediation Guidance"));
}
