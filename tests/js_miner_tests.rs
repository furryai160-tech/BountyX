use bountyscope::recon::js_miner::JsMiner;

#[test]
fn test_filter_js_urls() {
    let urls = vec![
        "https://example.com/main.js".to_string(),
        "https://example.com/style.css".to_string(),
        "https://example.com/bundle.js?v=123".to_string(),
        "https://example.com/api/users".to_string(),
        "https://example.com/static/js/chunk-1.js".to_string(),
    ];

    let filtered = JsMiner::filter_js_urls(&urls);
    assert_eq!(filtered.len(), 3);
    assert!(filtered.iter().any(|u| u.contains("main.js")));
    assert!(filtered.iter().any(|u| u.contains("bundle.js")));
    assert!(filtered.iter().any(|u| u.contains("chunk-1.js")));
}

#[test]
fn test_analyze_js_content_secrets_and_endpoints() {
    let miner = JsMiner::new();
    let mock_google = format!("AIzaSy{}_{}", "D", "0123456789abcdefghijklmnopqrstuvwxyz");

    let mock_stripe = format!("sk_live_{}", "mockkey1234567890abcdefghijklmn");
    let mock_ghp = format!("ghp_{}", "mockkey1234567890abcdefghijklmnopqrst");
    let mock_slack = format!("{}/services/T{}/B{}/{}", "https://hooks.slack.com", "00000000", "00000000", "mocksecretkey1234567890");
    let mock_js = format!(
        r#"
        const config = {{
            apiUrl: "/api/v1/internal/admin/dashboard",
            userEndpoint: "/v2/auth/login",
            googleKey: "{}",
            awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
            stripeKey: "{}",
            firebase: "https://my-leaked-project.firebaseio.com",
            githubToken: "{}",
            slackWebhook: "{}"
        }};
        "#,
        mock_google, mock_stripe, mock_ghp, mock_slack
    );

    let result = miner.analyze_js_content("https://example.com/app.js", &mock_js);


    // Verify endpoints extracted
    assert!(result.discovered_endpoints.iter().any(|e| e.contains("/api/v1/internal/admin/dashboard")));
    assert!(result.discovered_endpoints.iter().any(|e| e.contains("/v2/auth/login")));

    // Verify secrets extracted
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "Google Cloud API Key"));
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "AWS Access Key ID"));
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "Stripe Live Secret Key"));
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "Firebase Realtime DB"));
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "GitHub Personal Access Token"));
    assert!(result.leaked_secrets.iter().any(|s| s.secret_type == "Slack Incoming Webhook"));
}
