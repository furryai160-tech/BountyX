use bountyscope::tools::{
    GauAdapter, HttpxAdapter, KatanaAdapter, NucleiAdapter, SecurityTool,
    SubfinderAdapter, ToolInput, ToolOutput,
};

#[tokio::test]
async fn test_tool_adapter_input_output_structures() {
    let input = ToolInput::single("example.com")
        .with_job_id(Some("job-456"))
        .with_extra_args(vec!["-v".to_string()]);

    assert_eq!(input.target, "example.com");
    assert_eq!(input.targets, vec!["example.com"]);
    assert_eq!(input.job_id, Some("job-456".to_string()));
    assert_eq!(input.extra_args, vec!["-v".to_string()]);

    let output = ToolOutput {
        tool_name: "subfinder".to_string(),
        target: "example.com".to_string(),
        stdout: "api.example.com\nadmin.example.com\n".to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 150,
        raw_lines: vec!["api.example.com".to_string(), "admin.example.com".to_string()],
    };

    let subfinder = SubfinderAdapter::new("subfinder", 30);
    assert_eq!(subfinder.name(), "subfinder");

    let subdomains = subfinder.parse_subdomains(&output, "example.com");
    assert_eq!(subdomains.len(), 2);
    assert_eq!(subdomains[0].subdomain, "api.example.com");
    assert_eq!(subdomains[0].parent_asset, "example.com");
}

#[tokio::test]
async fn test_httpx_json_parsing() {
    let raw_json = r#"{"url":"https://api.example.com","host":"api.example.com","port":443,"scheme":"https","status_code":200,"title":"API Home","content_length":1234,"techs":["Cloudflare","Nginx"]}"#;
    let output = ToolOutput {
        tool_name: "httpx".to_string(),
        target: "api.example.com".to_string(),
        stdout: raw_json.to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 200,
        raw_lines: vec![raw_json.to_string()],
    };

    let httpx = HttpxAdapter::new("httpx", 30);
    let results = httpx.parse_results(&output);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].url, "https://api.example.com");
    assert_eq!(results[0].status_code, Some(200));
    assert_eq!(results[0].title, Some("API Home".to_string()));
    assert_eq!(results[0].technologies, vec!["Cloudflare", "Nginx"]);
}

#[tokio::test]
async fn test_katana_and_gau_parsing() {
    let katana_raw = r#"{"request":{"endpoint":"https://api.example.com/v1/auth"}}"#;
    let katana_output = ToolOutput {
        tool_name: "katana".to_string(),
        target: "api.example.com".to_string(),
        stdout: katana_raw.to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 300,
        raw_lines: vec![katana_raw.to_string()],
    };

    let katana = KatanaAdapter::new("katana", 30);
    let urls = katana.parse_urls(&katana_output);
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "https://api.example.com/v1/auth");

    let gau_output = ToolOutput {
        tool_name: "gau".to_string(),
        target: "example.com".to_string(),
        stdout: "https://example.com/login\nhttps://example.com/docs\n".to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 250,
        raw_lines: vec![
            "https://example.com/login".to_string(),
            "https://example.com/docs".to_string(),
        ],
    };

    let gau = GauAdapter::new("gau", 30);
    let gau_urls = gau.parse_urls(&gau_output);
    assert_eq!(gau_urls.len(), 2);
    assert_eq!(gau_urls[0], "https://example.com/login");
}

#[tokio::test]
async fn test_nuclei_adapter_finding_parsing() {
    let config = bountyscope::AppConfig::load().unwrap_or_else(|_| bountyscope::AppConfig {
        hackerone_username: "".to_string(),
        hackerone_api_token: "".to_string(),
        hackerone_adapter: "mock".to_string(),
        hackerone_verification_header: None,
        h1_sync_concurrency: 10,
        telegram_bot_token: "".to_string(),


        telegram_chat_id: 0,
        telegram_admin_pin: None,
        database_url: "sqlite://data/test.db".to_string(),
        max_concurrent_jobs: 5,
        request_timeout_seconds: 30,
        process_timeout_seconds: 60,
        retry_count: 3,
        scope_poll_interval_seconds: 300,
        nuclei_severities: vec!["medium".to_string(), "high".to_string(), "critical".to_string()],
        nuclei_templates: None,
        nuclei_tags: None,
        subfinder_path: "subfinder".to_string(),
        httpx_path: "httpx".to_string(),
        katana_path: "katana".to_string(),
        gau_path: "gau".to_string(),
        nuclei_path: "nuclei".to_string(),
        dalfox_path: "dalfox".to_string(),
        arjun_path: "arjun".to_string(),
        ffuf_path: "ffuf".to_string(),
        sqlmap_path: "sqlmap".to_string(),
        naabu_path: "naabu".to_string(),
        dnsx_path: "dnsx".to_string(),
        crlfuzz_path: "crlfuzz".to_string(),
        kxss_path: "kxss".to_string(),
        amass_path: "amass".to_string(),
        gitleaks_path: "gitleaks".to_string(),
        alterx_path: "alterx".to_string(),
        gospider_path: "gospider".to_string(),
        smuggler_path: "smuggler".to_string(),
        paramspider_path: "paramspider".to_string(),
        data_dir: std::path::PathBuf::from("data"),
        reports_dir: std::path::PathBuf::from("reports"),
        logs_dir: std::path::PathBuf::from("logs"),
    });

    let raw_nuclei = r#"{"template-id":"cve-2023-1234","info":{"name":"Test Vulnerability","severity":"high"},"matched-at":"https://api.example.com/vuln","curl-command":"curl -i https://api.example.com/vuln"}"#;
    let output = ToolOutput {
        tool_name: "nuclei".to_string(),
        target: "api.example.com".to_string(),
        stdout: raw_nuclei.to_string(),
        stderr: "".to_string(),
        exit_code: Some(0),
        duration_ms: 500,
        raw_lines: vec![raw_nuclei.to_string()],
    };

    let adapter = NucleiAdapter::new(&config);
    let findings = adapter.parse_findings(&output);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].template_id, "cve-2023-1234");
    assert_eq!(findings[0].template_name, "Test Vulnerability");
    assert_eq!(findings[0].matched_at, "https://api.example.com/vuln");
    assert_eq!(findings[0].severity.as_str(), "high");
}
