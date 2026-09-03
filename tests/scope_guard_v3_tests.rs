use bountyscope::sandbox::KillSwitch;
use bountyscope::scope::{ScopeGuard, ScopePolicy, ScopeValidator, ScopeViolation};


#[test]
fn test_scope_wildcard_matching() {
    let mut policy = ScopePolicy::new_permissive("target.com");
    policy.allowed_domains = vec!["*.target.com".to_string(), "target.com".to_string()];

    // Allowed
    assert!(ScopeValidator::is_host_allowed("target.com", &policy));
    assert!(ScopeValidator::is_host_allowed("api.target.com", &policy));
    assert!(ScopeValidator::is_host_allowed("v1.staging.target.com", &policy));

    // Strictly blocked out of scope
    assert!(!ScopeValidator::is_host_allowed("other-company.com", &policy));
    assert!(!ScopeValidator::is_host_allowed("eviltarget.com", &policy));
    assert!(!ScopeValidator::is_host_allowed("target.com.evil.com", &policy));
}

#[test]
fn test_scope_path_exclusions() {
    let mut policy = ScopePolicy::new_permissive("api.target.com");
    policy.excluded_paths = vec!["/logout".to_string(), "/admin/destructive".to_string()];

    assert!(ScopeValidator::is_path_allowed("/api/v1/users", &policy).is_ok());
    assert!(ScopeValidator::is_path_allowed("/dashboard", &policy).is_ok());

    // Excluded paths must fail closed
    let res = ScopeValidator::is_path_allowed("/logout", &policy);
    assert!(matches!(res, Err(ScopeViolation::ForbiddenPath { .. })));

    let res2 = ScopeValidator::is_path_allowed("/admin/destructive/drop", &policy);
    assert!(matches!(res2, Err(ScopeViolation::ForbiddenPath { .. })));
}

#[test]
fn test_scope_budget_exhaustion() {
    let mut policy = ScopePolicy::new_permissive("target.com");
    policy.max_requests = 3;

    let guard = ScopeGuard::new(policy);

    // 1st request
    assert!(guard.validate_and_record_request("https://target.com/api/1", "GET").is_ok());
    // 2nd request
    assert!(guard.validate_and_record_request("https://target.com/api/2", "GET").is_ok());
    // 3rd request
    assert!(guard.validate_and_record_request("https://target.com/api/3", "GET").is_ok());

    // 4th request must be strictly BLOCKED
    let res = guard.validate_and_record_request("https://target.com/api/4", "GET");
    assert!(matches!(res, Err(ScopeViolation::BudgetExceeded { .. })));
    assert_eq!(guard.remaining_budget(), 0);
}

#[test]
fn test_kill_switch_triggers_safely() {
    let kill_switch = KillSwitch::new();
    assert!(!kill_switch.is_triggered());

    kill_switch.trigger();
    assert!(kill_switch.is_triggered());
}
