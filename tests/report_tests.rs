use bountyscope::evidence::CollectedEvidence;
use bountyscope::reporting::ReportTemplate;

#[test]
fn test_markdown_report_rendering() {
    let evidence = CollectedEvidence {
        target: "api.example.com".to_string(),
        matched_url: "https://api.example.com/admin/config.json".to_string(),
        template_id: "exposed-config-json".to_string(),
        template_name: "Exposed Configuration File".to_string(),
        severity: "high".to_string(),
        curl_command: Some("curl -i https://api.example.com/admin/config.json".to_string()),
        request: Some("GET /admin/config.json HTTP/1.1\nHost: api.example.com".to_string()),
        response: Some("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"db_host\": \"internal\"}".to_string()),
        extracted_data: vec!["internal.db.local".to_string()],
        raw_scanner_output: "{\"template-id\":\"exposed-config-json\"}".to_string(),
    };

    let markdown = ReportTemplate::render_markdown(&evidence, "example_bounty");

    assert!(markdown.contains("# Vulnerability Report: Exposed Configuration File"));
    assert!(markdown.contains("Automated Finding — Requires Human Verification"));
    assert!(markdown.contains("curl -i https://api.example.com/admin/config.json"));
    assert!(markdown.contains("GET /admin/config.json HTTP/1.1"));
    assert!(markdown.contains("HTTP/1.1 200 OK"));
    assert!(markdown.contains("example_bounty"));
    assert!(markdown.contains("api.example.com"));
}
