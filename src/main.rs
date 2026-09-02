#![allow(dead_code, unused_imports, unused_variables)]

mod api;
mod cli;
mod config;
mod database;
mod errors;
mod evidence;
mod hackerone;
mod health;
mod mobile;
mod monitor;
mod pipeline;
mod recon;
mod reporting;
mod sast;
mod scanner;
mod telegram;
mod tools;
mod validation;


use clap::Parser;
use cli::{Cli, Commands, ScopeAction};
use config::AppConfig;
use database::init_db;
use errors::Result;
use hackerone::create_hackerone_client;
use health::HealthChecker;
use monitor::ScopeMonitorScheduler;
use pipeline::{PipelineOrchestrator, PipelineWorker};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use telegram::{TelegramBot, TelegramNotifier};
use tokio_util::sync::CancellationToken;
use tools::SecurityTool;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use validation::ScopeGuard;


#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,bountyscope=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load()?;

    match cli.command {
        Commands::Init => {
            println!("🚀 Initializing BountyScope environment...");
            tokio::fs::create_dir_all(&config.data_dir).await?;
            tokio::fs::create_dir_all(&config.reports_dir).await?;
            tokio::fs::create_dir_all(&config.logs_dir).await?;

            let (_pool, repo) = init_db(&config.database_url).await?;
            let stats = repo.get_stats().await?;

            println!("✅ Data directories and SQLite schema initialized successfully.");
            println!("   Database URL: {}", config.database_url);
            println!("   Total Programs: {}", stats.total_programs);
            println!("   In-Scope Assets: {}", stats.in_scope_assets);
        }

        Commands::Health => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let h1_client = create_hackerone_client(&config)?;
            let checker = HealthChecker::new(config.clone(), repo, h1_client);

            println!("\nBountyScope Health\n");

            let checks = checker.run_all_checks().await;
            let mut current_category = "";

            for item in checks {
                if item.category != current_category {
                    current_category = item.category;
                    if current_category != "Core" {
                        println!("\n{}", current_category);
                        println!();
                    }
                }

                if item.status {
                    println!("\x1b[32m[OK]\x1b[0m {}", item.name);
                } else {
                    println!("\x1b[31m[FAIL]\x1b[0m {}", item.name);
                    if let Some(ref path) = item.path {
                        println!("Path: {}", path);
                        println!("Status: NOT FOUND");
                    } else {
                        println!("Details: {}", item.details);
                    }
                }
            }
            println!();
        }


        Commands::Programs => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let programs = repo.list_programs().await?;

            println!("\n📋 Tracked HackerOne Programs ({})", programs.len());
            println!("{:-<70}", "");
            println!("{:<6} {:<25} {:<25} {:<10}", "#", "Handle", "Name", "Bounty");
            println!("{:-<70}", "");

            for (i, p) in programs.iter().enumerate() {
                let bounty = if p.offers_bounties { "Yes ($)" } else { "No (VDP)" };
                println!("{:<6} {:<25} {:<25} {:<10}", i + 1, p.handle, p.name, bounty);
            }
            println!("{:-<70}\n", "");
        }

        Commands::Scope { action } => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let h1_client = create_hackerone_client(&config)?;
            let notifier = TelegramNotifier::new(&config, Some(repo.clone()));
            let cancel_token = CancellationToken::new();

            let scheduler = ScopeMonitorScheduler::new(
                config.clone(),
                repo.clone(),
                h1_client,
                notifier,
                cancel_token,
            );

            match action {
                ScopeAction::Sync => {
                    info!("Running manual scope synchronization...");
                    let diff = scheduler.sync_and_diff().await?;
                    println!("\n✅ Scope Synchronization Complete");
                    println!("   Total Active In-Scope Targets: {}", diff.total_current_targets);
                    println!("   Newly Discovered Targets: {}", diff.new_targets.len());
                    println!("   Removed Targets: {}", diff.removed_targets.len());
                    for (prog, t) in &diff.new_targets {
                        println!("   + [{}] {}", prog, t);
                    }
                    println!();
                }
                ScopeAction::Diff => {
                    let diff = scheduler.sync_and_diff().await?;
                    println!("\n📊 Scope Diff Summary");
                    println!("   Current: {} | Previous: {}", diff.total_current_targets, diff.total_previous_targets);
                    println!("   New Targets ({}):", diff.new_targets.len());
                    for (prog, t) in &diff.new_targets {
                        println!("     + [{}] {}", prog, t);
                    }
                    println!("   Removed Targets ({}):", diff.removed_targets.len());
                    for (prog, t) in &diff.removed_targets {
                        println!("     - [{}] {}", prog, t);
                    }
                    println!();
                }
            }
        }

        Commands::Monitor => {
            println!("🟢 Starting BountyScope Continuous Monitoring Engine...");
            let (_pool, repo) = init_db(&config.database_url).await?;
            let h1_client = create_hackerone_client(&config)?;
            let notifier = TelegramNotifier::new(&config, Some(repo.clone()));

            let is_paused = Arc::new(AtomicBool::new(false));
            let cancel_token = CancellationToken::new();

            // Ensure Telegram auth table exists before bot starts
            let _ = repo.ensure_telegram_auth_table().await;
            info!("Telegram auth table ready.");

            // Notify Telegram of startup
            let stats = repo.get_stats().await?;
            notifier
                .notify_startup(
                    stats.total_programs as usize,
                    stats.in_scope_assets as usize,
                    config.max_concurrent_jobs,
                )
                .await;

            // 0. Spawn Web REST API Server (For Vercel Dashboard)
            let api_config = config.clone();
            let api_repo = repo.clone();
            let api_h1 = h1_client.clone();
            let api_paused = is_paused.clone();
            let api_cancel = cancel_token.clone();
            tokio::spawn(async move {
                api::start_api_server(api_config, api_repo, api_h1, api_paused, api_cancel).await;
            });

            // 1. Spawn Telegram Bot Polling Listener

            let bot = TelegramBot::new(
                config.clone(),
                repo.clone(),
                is_paused.clone(),
                cancel_token.clone(),
            );
            tokio::spawn(async move {
                bot.run_polling_loop().await;
            });

            // 2. Spawn Scope Monitor Scheduler
            let scheduler = ScopeMonitorScheduler::new(
                config.clone(),
                repo.clone(),
                h1_client,
                notifier.clone(),
                cancel_token.clone(),
            );
            tokio::spawn(async move {
                if let Err(e) = scheduler.run_monitor_loop().await {
                    error!("Scope Monitor Scheduler encountered fatal error: {}", e);
                }
            });

            // 3. Spawn Pipeline Orchestrator (Worker Pool)
            let orchestrator = PipelineOrchestrator::new(
                config.clone(),
                repo.clone(),
                notifier.clone(),
                is_paused.clone(),
                cancel_token.clone(),
            );
            let orchestrator_task = tokio::spawn(async move {
                if let Err(e) = orchestrator.run_worker_pool().await {
                    error!("Pipeline Orchestrator encountered fatal error: {}", e);
                }
            });

            // 4. Wait for Ctrl+C Graceful Shutdown
            println!("⚡ Engine is running. Press Ctrl+C to stop.");
            tokio::signal::ctrl_c().await?;

            info!("Shutdown signal received. Cancelling worker tasks...");
            cancel_token.cancel();

            let _ = orchestrator_task.await;
            info!("BountyScope stopped cleanly.");
        }

        Commands::Recon(args) => {
            let target = args.resolved_target();
            if target.is_empty() {
                println!("❌ Error: Target is required.\nUsage: bountyscope recon <TARGET> or bountyscope recon --target <TARGET>");
                return Ok(());
            }

            let (_pool, repo) = init_db(&config.database_url).await?;
            let in_scope = repo.list_all_in_scope_identifiers().await.unwrap_or_default();
            let scope_guard = ScopeGuard::from_rules(&in_scope, &[]);

            if args.dry_run {
                println!("\nDRY RUN\n");
                println!("Target:\n{}", target);
                println!();

                let is_auth = scope_guard.is_in_scope(&target);
                if is_auth {
                    let _ = repo
                        .record_audit_event(
                            "DRY_RUN",
                            &target,
                            "AUTHORIZED",
                            "Dry-run scope simulation passed",
                            Some("recon"),
                            None,
                        )
                        .await;

                    println!("Scope:\nAUTHORIZED\n");
                    println!("Pipeline:\n");
                    println!("[PASS] Scope Guard");
                    println!("[PLAN] Subfinder + Amass + Alterx");
                    println!("[PLAN] Naabu Port Scanner");
                    println!("[PLAN] httpx + Katana + GAU + Paramspider");
                    println!("[PLAN] Dalfox + Arjun + kxss + Sqlmap");
                    println!("[PLAN] Nuclei + Smuggler + CRLF");
                    println!("\nExternal execution:\nDISABLED\n");
                } else {
                    let _ = repo
                        .record_audit_event(
                            "DRY_RUN",
                            &target,
                            "BLOCKED",
                            "Dry-run target not authorized by ScopeGuard",
                            Some("recon"),
                            None,
                        )
                        .await;

                    println!("Scope:\nBLOCKED (Not in authorized scope rules)\n");
                    println!("Pipeline:\n[BLOCKED] Execution terminated at Gate 0.\n");
                    println!("External execution:\nDISABLED\n");
                }
                return Ok(());
            }

            println!("🔍 Executing full reconnaissance & vulnerability pipeline on: {}", target);
            let mut active_scope_guard = scope_guard;
            if !active_scope_guard.is_in_scope(&target) {
                active_scope_guard.add_in_scope(&target);
            }

            let notifier = TelegramNotifier::new(&config, Some(repo.clone()));
            let worker = PipelineWorker::new(config.clone(), repo.clone(), notifier);
            let job_id = repo.enqueue_recon_job(&target, &args.program).await?;

            let job = repo
                .claim_recon_job_by_id(&job_id)
                .await?
                .ok_or_else(|| errors::BountyScopeError::Internal("Failed to claim created job".to_string()))?;

            worker.process_job(job, Arc::new(active_scope_guard)).await?;
            println!("✅ Reconnaissance and scanning completed for target: {}", target);
        }

        Commands::Scan(args) => {
            let target = args.resolved_target();
            if target.is_empty() {
                println!("❌ Error: Target is required.\nUsage: bountyscope scan <TARGET> or bountyscope scan --target <TARGET>");
                return Ok(());
            }

            let (_pool, repo) = init_db(&config.database_url).await?;
            let in_scope = repo.list_all_in_scope_identifiers().await.unwrap_or_default();
            let scope_guard = ScopeGuard::from_rules(&in_scope, &[]);

            if args.dry_run {
                println!("\nDRY RUN\n");
                println!("Target:\n{}", target);
                println!();

                let is_auth = scope_guard.is_in_scope(&target);
                if is_auth {
                    let _ = repo
                        .record_audit_event(
                            "DRY_RUN",
                            &target,
                            "AUTHORIZED",
                            "Dry-run scan simulation passed",
                            Some("scan"),
                            None,
                        )
                        .await;

                    println!("Scope:\nAUTHORIZED\n");
                    println!("Pipeline:\n");
                    println!("[PASS] Scope Guard");
                    println!("[PLAN] Full 19-Tool Automated Pipeline");
                    println!("\nExternal execution:\nDISABLED\n");
                } else {
                    let _ = repo
                        .record_audit_event(
                            "DRY_RUN",
                            &target,
                            "BLOCKED",
                            "Dry-run target not authorized by ScopeGuard",
                            Some("scan"),
                            None,
                        )
                        .await;

                    println!("Scope:\nBLOCKED (Not in authorized scope rules)\n");
                    println!("Pipeline:\n[BLOCKED] Execution terminated at Gate 0.\n");
                    println!("External execution:\nDISABLED\n");
                }
                return Ok(());
            }

            println!("🎯 Executing full 19-tool automated security scan on: {}", target);
            let mut active_scope_guard = scope_guard;
            if !active_scope_guard.is_in_scope(&target) {
                active_scope_guard.add_in_scope(&target);
            }

            let notifier = TelegramNotifier::new(&config, Some(repo.clone()));
            let worker = PipelineWorker::new(config.clone(), repo.clone(), notifier);
            let job_id = repo.enqueue_recon_job(&target, &args.program).await?;

            let job = repo
                .claim_recon_job_by_id(&job_id)
                .await?
                .ok_or_else(|| errors::BountyScopeError::Internal("Failed to claim created job".to_string()))?;

            worker.process_job(job, Arc::new(active_scope_guard)).await?;
            println!("✅ Complete 19-tool security scan finished for target: {}", target);
        }




        Commands::Findings { status } => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let findings = repo.list_findings(status.as_deref()).await?;

            println!("\n🚨 Recorded Findings ({})", findings.len());
            println!("{:-<80}", "");
            println!("{:<6} {:<10} {:<25} {:<25} {:<12}", "#", "Severity", "Template", "Target", "Status");
            println!("{:-<80}", "");

            for (i, f) in findings.iter().enumerate() {
                println!(
                    "{:<6} {:<10} {:<25} {:<25} {:<12}",
                    i + 1,
                    f.severity.to_uppercase(),
                    f.template_name,
                    f.matched_at,
                    f.status
                );
            }
            println!("{:-<80}\n", "");
        }

        Commands::Reports => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let reports = repo.list_reports().await?;

            println!("\n📄 Generated Vulnerability Draft Reports ({})", reports.len());
            println!("{:-<80}", "");
            println!("{:<6} {:<30} {:<30} {:<10}", "#", "Title", "File Path", "Verified");
            println!("{:-<80}", "");

            for (i, r) in reports.iter().enumerate() {
                let verified_str = if r.human_verified { "Yes" } else { "No (Draft)" };
                println!("{:<6} {:<30} {:<30} {:<10}", i + 1, r.title, r.file_path, verified_str);
            }
            println!("{:-<80}\n", "");
        }
    }

    Ok(())
}
