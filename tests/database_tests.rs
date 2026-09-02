use bountyscope::database::init_db;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_database_migration_and_audit_tool_runs() {
    let tmp = NamedTempFile::new().unwrap();
    let db_url = format!("sqlite://{}", tmp.path().to_string_lossy());

    let (_pool, repo) = init_db(&db_url).await.expect("Failed to init DB");

    // 1. Test audit logging
    let audit_id = repo
        .record_audit_event(
            "SCOPE_EVALUATION",
            "api.example.com",
            "AUTHORIZED",
            "Matched *.example.com wildcard",
            Some("subfinder"),
            Some("{\"rule\":\"*.example.com\"}"),
        )
        .await
        .expect("Failed to record audit event");

    assert!(!audit_id.is_empty());

    let audit_events = repo.list_audit_events(10).await.expect("Failed to list audit events");
    assert_eq!(audit_events.len(), 1);
    assert_eq!(audit_events[0].target, "api.example.com");
    assert_eq!(audit_events[0].decision, "AUTHORIZED");
    assert_eq!(audit_events[0].event_type, "SCOPE_EVALUATION");

    // 2. Test tool run logging
    let run_id = repo
        .record_tool_start(
            Some("job-123"),
            "subfinder",
            "example.com",
            "-d example.com -silent -all",
        )
        .await
        .expect("Failed to start tool run");

    assert!(!run_id.is_empty());

    repo.record_tool_finish(&run_id, Some(0), "SUCCESS", None)
        .await
        .expect("Failed to finish tool run");

    let runs = repo.list_tool_runs(10).await.expect("Failed to list tool runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].tool, "subfinder");
    assert_eq!(runs[0].target, "example.com");
    assert_eq!(runs[0].status, "SUCCESS");
    assert_eq!(runs[0].exit_code, Some(0));
}
