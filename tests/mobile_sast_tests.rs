use bountyscope::mobile::MobileAnalyzer;
use bountyscope::sast::SastScanner;
use bountyscope::validation::ScopeGuard;

#[test]
fn test_mobile_secret_and_endpoint_extraction() {
    let mut scope_guard = ScopeGuard::new();
    scope_guard.add_in_scope("*.example.com");

    let sample_manifest_and_strings = r#"
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.target.app">
            <application android:usesCleartextTraffic="true" android:exported="true">
                <meta-data android:name="com.google.android.geo.API_KEY" android:value="AIzaSyA1234567890abcdefABCDEF123456789" />
                <string name="firebase_url">https://target-prod-123.firebaseio.com</string>
                <string name="aws_key">AKIAIOSFODNN7EXAMPLE</string>
                <string name="api_url">https://api.example.com/v1/mobile/login</string>
                <string name="out_of_scope">https://api.thirdparty-vendor.com/track</string>
            </application>
        </manifest>
    "#;

    let analysis = MobileAnalyzer::analyze_app_metadata(
        "com.target.app",
        "Android",
        sample_manifest_and_strings,
        &scope_guard,
    )
    .expect("Analysis failed");

    // Check Google API key detected
    assert!(analysis.leaked_secrets.iter().any(|s| s.secret_type == "Google API Key"));
    // Check Firebase DB detected
    assert!(analysis.leaked_secrets.iter().any(|s| s.secret_type == "Firebase Realtime Database"));
    // Check AWS key detected
    assert!(analysis.leaked_secrets.iter().any(|s| s.secret_type == "AWS Access Key"));

    // Check In-scope endpoint was retained
    assert!(analysis.extracted_endpoints.iter().any(|e| e.contains("api.example.com")));
    // Check Out-of-scope thirdparty endpoint was dropped
    assert!(!analysis.extracted_endpoints.iter().any(|e| e.contains("thirdparty-vendor.com")));
}

#[test]
fn test_sast_secret_scanner() {
    let mock_slack = format!("{}/services/T{}/B{}/{}", "https://hooks.slack.com", "00000000", "00000000", "mocksecretkey12345");
    let mock_ghp = format!("ghp_{}", "0123456789abcdefghijklmnopqrstuvwxyz");

    let sample_code = format!(
        r#"
        // Database credentials
        const dbUrl = "postgres://admin_user:SuperSecretP@ss123@prod-db.internal.target.com:5432/main_db";
        // Slack webhook
        const slackHook = "{}";
        // GitHub PAT
        const githubToken = "{}";
        "#,
        mock_slack, mock_ghp
    );

    let findings = SastScanner::scan_content("config/database.js", &sample_code)
        .expect("SAST scan failed");

    assert!(findings.iter().any(|f| f.rule_id == "sec-leak-db-connection-string"));
    assert!(findings.iter().any(|f| f.rule_id == "sec-leak-slack-webhook"));
    assert!(findings.iter().any(|f| f.rule_id == "sec-leak-github-pat"));
}

