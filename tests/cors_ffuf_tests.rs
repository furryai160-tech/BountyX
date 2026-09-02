use bountyscope::scanner::cors::CorsSeverity;
use bountyscope::tools::adapter::ToolOutput;
use bountyscope::tools::arjun::ArjunAdapter;
use bountyscope::tools::dalfox::DalfoxAdapter;
use bountyscope::tools::ffuf::FfufAdapter;

#[test]
fn test_cors_severity_levels() {
    assert_eq!(CorsSeverity::Critical.as_str(), "CRITICAL");
    assert_eq!(CorsSeverity::High.as_str(), "HIGH");
    assert_eq!(CorsSeverity::Medium.as_str(), "MEDIUM");
    assert_eq!(CorsSeverity::Low.as_str(), "LOW");
}

#[test]
fn test_dalfox_output_parsing() {
    let adapter = DalfoxAdapter::new("dalfox", 60);
    let output = ToolOutput {
        tool_name: "dalfox".to_string(),
        target: "https://example.com".to_string(),
        stdout: "".to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 120,
        raw_lines: vec![
            "[V] Verified XSS [param=query] https://example.com/search?query=%3Cscript%3E".to_string(),
            "[R] Reflected XSS https://example.com/profile?name=test".to_string(),
            "Random log line that should be ignored".to_string(),
        ],
    };

    let findings = adapter.parse_findings(&output);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0].vuln_type, "V");
    assert_eq!(findings[0].severity, "HIGH");
    assert_eq!(findings[0].url, "https://example.com/search?query=%3Cscript%3E");
    assert_eq!(findings[1].vuln_type, "R");
    assert_eq!(findings[1].severity, "MEDIUM");
}

#[test]
fn test_arjun_output_parsing() {
    let adapter = ArjunAdapter::new("arjun", 60);
    let json_output = r#"[{"url": "https://example.com/api/test", "params": ["user_id", "auth_token", "debug"]}]"#;
    let output = ToolOutput {
        tool_name: "arjun".to_string(),
        target: "https://example.com".to_string(),
        stdout: json_output.to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 150,
        raw_lines: vec![json_output.to_string()],
    };

    let results = adapter.parse_results(&output);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://example.com/api/test");
    assert_eq!(results[0].params, vec!["user_id", "auth_token", "debug"]);
}

#[test]
fn test_ffuf_output_parsing() {
    let adapter = FfufAdapter::new("ffuf", 60);
    let raw_json = r#"{
        "results": [
            {
                "input": {"FUZZ": "admin"},
                "status": 200,
                "length": 1542,
                "words": 320,
                "url": "https://example.com/admin",
                "duration": 50000000
            },
            {
                "input": {"FUZZ": ".env"},
                "status": 403,
                "length": 220,
                "words": 15,
                "url": "https://example.com/.env",
                "duration": 45000000
            },
            {
                "input": {"FUZZ": "invalid"},
                "status": 400,
                "length": 0,
                "words": 0,
                "url": "https://example.com/invalid",
                "duration": 10000000
            }
        ]
    }"#;

    let output = ToolOutput {
        tool_name: "ffuf".to_string(),
        target: "https://example.com".to_string(),
        stdout: raw_json.to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 200,
        raw_lines: vec![raw_json.to_string()],
    };

    let results = adapter.parse_results(&output);
    // Note: status 400 is filtered out as noise, so results should have 2 elements (200 and 403)
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].input, "admin");
    assert_eq!(results[0].status, 200);
    assert_eq!(results[1].input, ".env");
    assert_eq!(results[1].status, 403);
}
