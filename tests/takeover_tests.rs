use bountyscope::scanner::takeover::{TakeoverScanner, TAKEOVER_SIGNATURES};

#[test]
fn test_takeover_signatures_presence() {
    assert!(!TAKEOVER_SIGNATURES.is_empty());
    assert!(TAKEOVER_SIGNATURES.iter().any(|s| s.service == "GitHub Pages"));
    assert!(TAKEOVER_SIGNATURES.iter().any(|s| s.service == "AWS S3 Bucket"));
    assert!(TAKEOVER_SIGNATURES.iter().any(|s| s.service == "Heroku"));
    assert!(TAKEOVER_SIGNATURES.iter().any(|s| s.service == "Zendesk"));
    assert!(TAKEOVER_SIGNATURES.iter().any(|s| s.service == "Shopify"));
}

#[test]
fn test_inspect_response_body_github_pages() {
    let body = "<html><head><title>404</title></head><body><h1>There isn't a GitHub Pages site here</h1></body></html>";
    let finding = TakeoverScanner::inspect_response_body("sub.example.com", "https://sub.example.com", body);

    assert!(finding.is_some());
    let f = finding.unwrap();
    assert_eq!(f.service, "GitHub Pages");
    assert_eq!(f.severity, "HIGH");
    assert!(f.matched_fingerprint.contains("GitHub Pages"));
}

#[test]
fn test_inspect_response_body_aws_s3() {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"#;
    let finding = TakeoverScanner::inspect_response_body("assets.example.com", "http://assets.example.com", body);

    assert!(finding.is_some());
    let f = finding.unwrap();
    assert_eq!(f.service, "AWS S3 Bucket");
    assert_eq!(f.severity, "HIGH");
}

#[test]
fn test_inspect_response_body_benign() {
    let body = "<html><body>Welcome to our official website!</body></html>";
    let finding = TakeoverScanner::inspect_response_body("valid.example.com", "https://valid.example.com", body);

    assert!(finding.is_none());
}
