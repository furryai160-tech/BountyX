use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use bountyscope::ai::AutonomousSecurityAgent;
use bountyscope::reporting::BugBountyReport;
use bountyscope::sandbox::{KillSwitch, SandboxedHttpClient};
use bountyscope::scope::{ScopeGuard, ScopePolicy};
use bountyscope::security::FindingStatus;
use serde_json::json;
use tokio::net::TcpListener;

// 1. Mock Target Web Application with both Vulnerable and Secure Endpoints
async fn handle_vulnerable_order(_headers: HeaderMap) -> impl IntoResponse {

    // Intentionally vulnerable BOLA endpoint: returns sensitive order details without checking ownership
    Json(json!({
        "id": 101,
        "customer": "Alice Corp",
        "email": "alice@alicecorp.internal",
        "billing_amount": 5420.50,
        "token": "order_secret_token_123"
    }))
}

async fn handle_secure_ping() -> impl IntoResponse {
    // Normal secure endpoint: no sensitive data, strictly informational
    Json(json!({ "status": "ok", "service": "orders-microservice" }))
}

async fn handle_vulnerable_cors(headers: HeaderMap) -> impl IntoResponse {
    let mut resp_headers = axum::http::HeaderMap::new();
    if let Some(origin) = headers.get("origin") {
        resp_headers.insert("access-control-allow-origin", origin.clone());
        resp_headers.insert("access-control-allow-credentials", "true".parse().unwrap());
    }
    (resp_headers, Json(json!({ "user": "alice", "balance": 1500 })))
}

#[tokio::test]
async fn test_autonomous_ai_security_agent_workflow() {
    // Step 1: Launch Local Simulation Server
    let app = Router::new()
        .route("/api/v1/orders", get(handle_vulnerable_order))
        .route("/api/v1/public/ping", get(handle_secure_ping))
        .route("/api/v1/user/profile", get(handle_vulnerable_cors));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let base_url = format!("http://127.0.0.1:{}", port);

    // Step 2: Initialize ScopePolicy & ScopeGuard
    let mut policy = ScopePolicy::new_permissive("127.0.0.1");
    policy.allowed_domains = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    policy.max_requests = 100;
    policy.rate_limit_rps = 50;

    let guard = ScopeGuard::new(policy);
    let kill_switch = KillSwitch::new();
    let http_client = SandboxedHttpClient::new(guard, kill_switch).unwrap();

    // Step 3: Initialize Autonomous AI Agent
    let mut agent = AutonomousSecurityAgent::new(http_client);

    // Discovered URLs fed into agent observation stage
    let discovered_urls = vec![
        format!("{}/api/v1/orders?id=101", base_url),
        format!("{}/api/v1/public/ping", base_url),
        format!("{}/api/v1/user/profile", base_url),
    ];

    // Step 4: Run Autonomous Assessment
    let findings = agent
        .run_assessment("127.0.0.1", &base_url, &discovered_urls)
        .await
        .unwrap();

    // Step 5: Verify Findings & Zero False Positives on Secure Ping
    assert!(!findings.is_empty(), "Should discover confirmed security findings");

    let has_bola = findings.iter().any(|f| {
        f.category.contains("BOLA")
            && f.status == FindingStatus::Confirmed
            && f.risk.confidence_score >= 80
    });
    assert!(has_bola, "Must detect and confirm BOLA/IDOR vulnerability");

    let ping_falsely_flagged = findings.iter().any(|f| f.target_url.contains("/api/v1/public/ping"));
    assert!(!ping_falsely_flagged, "Secure ping endpoint MUST NOT be flagged as vulnerable (0% FP)");

    // Step 6: Generate Professional Bug Bounty Report & Verify Human Approval Gate
    let mut report = BugBountyReport::new("127.0.0.1", findings);

    // Report cannot be submitted externally without human approval
    assert!(!report.can_submit_externally(), "Unreviewed reports cannot be submitted");

    // Human reviews and approves
    report.approve("Yasseen Sabry Elawamy");
    assert!(report.can_submit_externally(), "Approved report is cleared for submission");

    let markdown = report.to_markdown();
    assert!(markdown.contains("BountyX Autonomous Security Assessment"));
    assert!(markdown.contains("Step-by-Step Reproduction Proof of Concept"));
    assert!(markdown.contains("APPROVED by `Yasseen Sabry Elawamy`"));
}
