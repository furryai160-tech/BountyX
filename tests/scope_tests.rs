use bountyscope::validation::ScopeGuard;

#[test]
fn test_exact_domain_matching() {
    let in_scope = vec!["example.com".to_string(), "api.target.com".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &[]);

    assert!(guard.is_in_scope("example.com"));
    assert!(guard.is_in_scope("https://example.com"));
    assert!(guard.is_in_scope("http://example.com/login"));
    assert!(guard.is_in_scope("api.target.com"));

    // Subdomains should NOT match exact domain rule
    assert!(!guard.is_in_scope("sub.example.com"));
    assert!(!guard.is_in_scope("other.com"));
}

#[test]
fn test_wildcard_domain_matching() {
    let in_scope = vec!["*.example.com".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &[]);

    assert!(guard.is_in_scope("example.com"));
    assert!(guard.is_in_scope("sub.example.com"));
    assert!(guard.is_in_scope("a.b.c.example.com"));
    assert!(guard.is_in_scope("https://api.example.com:8443/v1"));

    // Different domain must be rejected
    assert!(!guard.is_in_scope("notexample.com"));
    assert!(!guard.is_in_scope("example.org"));
}

#[test]
fn test_explicit_out_of_scope_blocking() {
    let in_scope = vec!["*.example.com".to_string()];
    let out_of_scope = vec!["blog.example.com".to_string(), "admin.example.com".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &out_of_scope);

    // In-scope subdomains pass
    assert!(guard.is_in_scope("api.example.com"));
    assert!(guard.is_in_scope("dev.example.com"));

    // Explicitly excluded subdomains must be HARD BLOCKED
    assert!(!guard.is_in_scope("blog.example.com"));
    assert!(!guard.is_in_scope("admin.example.com"));
    assert!(!guard.is_in_scope("https://blog.example.com/post/1"));
}

#[test]
fn test_cidr_matching() {
    let in_scope = vec!["192.168.1.0/24".to_string(), "10.0.0.5".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &[]);

    assert!(guard.is_in_scope("192.168.1.1"));
    assert!(guard.is_in_scope("192.168.1.254"));
    assert!(guard.is_in_scope("10.0.0.5"));

    // Out of range
    assert!(!guard.is_in_scope("192.168.2.1"));
    assert!(!guard.is_in_scope("10.0.0.6"));
}

#[test]
fn test_target_normalization() {
    assert_eq!(ScopeGuard::normalize_target("https://api.example.com:8080/v1/users"), "api.example.com");
    assert_eq!(ScopeGuard::normalize_target("*.sub.example.com"), "sub.example.com");
    assert_eq!(ScopeGuard::normalize_target("HTTP://EXAMPLE.COM/"), "example.com");
}

#[tokio::test]
async fn test_redirect_validation() {
    let in_scope = vec!["*.example.com".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &[]);

    // Authorized internal redirect
    let res1 = guard.validate_redirect("https://example.com/login", "https://auth.example.com/sso", None).await;
    assert!(res1.is_ok());
    assert_eq!(res1.unwrap(), "auth.example.com");

    // Unauthorized external redirect (e.g. Open redirect to attacker or third party)
    let res2 = guard.validate_redirect("https://example.com/redirect?url=https://attacker.com", "https://attacker.com", None).await;
    assert!(res2.is_err());
}

