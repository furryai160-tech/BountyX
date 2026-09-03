use bountyscope::config::AppConfig;
use bountyscope::database::repository::Repository;
use bountyscope::telegram::commands::TelegramCommandHandler;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

async fn setup_test_repo() -> Repository {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to connect to in-memory SQLite");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    Repository::new(pool)
}

#[tokio::test]
async fn test_telegram_scope_guard_blocks_unauthorized_target() {
    let repo = setup_test_repo().await;
    repo.authorize_telegram_chat(12345, "01550613063").await.unwrap();
    let config = AppConfig::load().unwrap();
    let is_paused = Arc::new(AtomicBool::new(false));

    let handler = TelegramCommandHandler::new(config, repo.clone(), is_paused.clone());

    // 1. Attempt /scan on an out-of-scope target
    let res = handler
        .handle_command(12345, "/scan evil-unauthorized-target.com")
        .await
        .expect("Handler must return response");

    assert!(res.contains("الهدف خارج النطاق المصرح به"));
    assert!(res.contains("حارس النطاق (Scope Guard)"));
    assert!(res.contains("تم حظر طلب الفحص تلقائياً"));

    // 2. Attempt /scan on local loopback (allowed for security testing)
    let res_lab = handler
        .handle_command(12345, "/scan 127.0.0.1")
        .await
        .expect("Handler must return response");

    assert!(res_lab.contains("تم التحقق وإدراج الهدف في قائمة الفحص"));
    assert!(res_lab.contains("local-security-lab"));
}

#[tokio::test]
async fn test_telegram_pause_and_resume_control() {
    let repo = setup_test_repo().await;
    repo.authorize_telegram_chat(12345, "01550613063").await.unwrap();
    let config = AppConfig::load().unwrap();
    let is_paused = Arc::new(AtomicBool::new(false));

    let handler = TelegramCommandHandler::new(config, repo, is_paused.clone());

    // 1. Pause command
    let pause_resp = handler.handle_command(12345, "/pause").await.unwrap();
    assert!(pause_resp.contains("تم إيقاف محرك الفحص مؤقتاً"));
    assert!(is_paused.load(Ordering::SeqCst), "Engine must be paused");

    // 2. Resume command
    let resume_resp = handler.handle_command(12345, "/resume").await.unwrap();
    assert!(resume_resp.contains("تم استئناف محرك الفحص بنجاح"));
    assert!(!is_paused.load(Ordering::SeqCst), "Engine must be resumed");
}

#[tokio::test]
async fn test_telegram_stats_command() {
    let repo = setup_test_repo().await;
    repo.authorize_telegram_chat(12345, "01550613063").await.unwrap();
    let config = AppConfig::load().unwrap();
    let is_paused = Arc::new(AtomicBool::new(false));

    let handler = TelegramCommandHandler::new(config, repo, is_paused);

    let stats_resp = handler.handle_command(12345, "/stats").await.unwrap();
    assert!(stats_resp.contains("إحصائيات منصة BountyX V3 الشاملة"));
    assert!(stats_resp.contains("توزيع الثغرات المكتشفة"));
    assert!(stats_resp.contains("التقارير المعتمدة في الخزنة"));
}
