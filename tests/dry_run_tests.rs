use bountyscope::database::init_db;
use bountyscope::validation::ScopeGuard;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_dry_run_authorized_and_blocked_simulation() {
    let tmp = NamedTempFile::new().unwrap();
    let db_url = format!("sqlite://{}", tmp.path().to_string_lossy());
    let (_pool, repo) = init_db(&db_url).await.expect("Failed to init DB");

    let in_scope = vec!["*.example.com".to_string(), "api.company.com".to_string()];
    let guard = ScopeGuard::from_rules(&in_scope, &[]);

    // 1. Authorized target dry run
    let auth_target = "sub.example.com";
    assert!(guard.is_in_scope(auth_target));
    let audit_id1 = repo
        .record_audit_event(
            "DRY_RUN",
            auth_target,
            "AUTHORIZED",
            "Dry-run simulation passed",
            Some("recon"),
            None,
        )
        .await
        .expect("Failed to record dry run audit");
    assert!(!audit_id1.is_empty());

    // 2. Blocked target dry run
    let blocked_target = "malicious-thirdparty.com";
    assert!(!guard.is_in_scope(blocked_target));
    let audit_id2 = repo
        .record_audit_event(
            "DRY_RUN",
            blocked_target,
            "BLOCKED",
            "Target rejected by Scope Guard",
            Some("recon"),
            None,
        )
        .await
        .expect("Failed to record blocked dry run audit");
    assert!(!audit_id2.is_empty());

    // Verify audit logs stored
    let events = repo.list_audit_events(10).await.expect("Failed to list audit events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].decision, "BLOCKED");
    assert_eq!(events[1].decision, "AUTHORIZED");
}
