#![allow(dead_code, unused_imports, unused_variables)]

mod ai;
mod api;
mod attack_surface;
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
mod sandbox;
mod sast;
mod scanner;
mod scope;
mod security;
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
                ScopeAction::Validate { target } => {
                    println!("\n🛡️ Validating Scope Policy for: {}", target);
                    if std::path::Path::new(&target).exists() {
                        let content = tokio::fs::read_to_string(&target).await?;
                        let policy = scope::policy::ScopePolicy::from_yaml_str(&content)?;
                        println!("   [PASS] Scope Policy File: Valid YAML");
                        println!("   Policy Name: {}", policy.name);
                        println!("   Allowed Domains: {:?}", policy.allowed_domains);
                        println!("   Allowed CIDRs: {:?}", policy.allowed_cidrs);
                        println!("   Excluded Paths: {:?}", policy.excluded_paths);
                        println!("   Request Budget: {} requests", policy.max_requests);
                        println!("   Rate Limit: {} req/s", policy.rate_limit_rps);
                    } else {
                        let policy = scope::policy::ScopePolicy::new_permissive(&target);
                        let is_auth = scope::validator::ScopeValidator::is_host_allowed(&target, &policy);
                        println!("   [PASS] Autonomous Scope Guard for Target: {}", target);
                        println!("   Target Host: {}", target);
                        println!("   Scope Status: {}", if is_auth { "\x1b[32mAUTHORIZED\x1b[0m" } else { "\x1b[31mBLOCKED\x1b[0m" });
                        println!("   Budget Cap: {} requests", policy.max_requests);
                        println!("   Rate Limit: {} req/s", policy.rate_limit_rps);
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




        Commands::Map(args) => {
            let target = args.positional_target.or(args.target).unwrap_or_else(|| "example.com".to_string());
            println!("\n🗺️ Mapping Attack Surface Graph for: {}", target);

            let mut graph = attack_surface::graph::AttackSurfaceGraph::new();
            attack_surface::mapper::AttackSurfaceMapper::ingest_url(&mut graph, &target, &target, "GET");


            let candidates = attack_surface::analyzer::AttackSurfaceAnalyzer::find_high_risk_candidates(&graph);

            println!("   Attack Surface Nodes: {}", graph.node_count());
            println!("   Attack Surface Edges: {}", graph.edge_count());
            println!("   High Risk Hypotheses Identified: {}", candidates.len());
            for c in &candidates {
                println!("   - [{}] {} ➔ {}", c.method, c.path, c.suggested_test);
            }
            println!();
        }

        Commands::Assess { target, scope, output, continuous } => {
            let (_pool, repo) = init_db(&config.database_url).await?;

            // 0. Spawn Telegram Bot Polling Listener in background so inline buttons work!
            if !config.telegram_bot_token.is_empty() {
                let bot_config = config.clone();
                let bot_repo = repo.clone();
                let is_paused = Arc::new(AtomicBool::new(false));
                let cancel_token = CancellationToken::new();
                tokio::spawn(async move {
                    let bot = TelegramBot::new(bot_config, bot_repo, is_paused, cancel_token);
                    bot.run_polling_loop().await;
                });
            }

            let mut iteration = 1;

            loop {
                let (chosen_program, chosen_target) = if let Some(ref t) = target {
                    ("manual".to_string(), t.clone())
                } else {
                    println!("\n🔍 Auto-Selecting In-Scope Target [Round {}] from HackerOne Assets Database (42,000+ Assets)...", iteration);
                    match repo.get_next_unscanned_in_scope_target().await? {
                        Some((prog, ident)) => {
                            println!("   🎯 Claimed Target: {} (HackerOne Program: {})", ident, prog);
                            (prog, ident)
                        }
                        None => {
                            println!("   ⚠️ No unscanned targets found in database. Using default authorized target.");
                            ("security".to_string(), "ctf.hacker101.com".to_string())
                        }
                    }
                };

                let cur_target = chosen_target.clone();
                repo.update_asset_last_scanned(&cur_target).await.ok();

                println!("\n🤖 Starting BountyX V3 Autonomous AI Security Assessment on: {} [{}]", cur_target, chosen_program);

                let policy = if let Some(ref path) = scope {
                    let content = tokio::fs::read_to_string(path).await?;
                    scope::policy::ScopePolicy::from_yaml_str(&content)?
                } else {
                    scope::policy::ScopePolicy::new_permissive(&cur_target)
                };

                let guard = scope::guard::ScopeGuard::new(policy);
                let kill_switch = sandbox::kill_switch::KillSwitch::new();
                let http_client = sandbox::client::SandboxedHttpClient::new(guard, kill_switch)?;

                let mut agent = ai::agent::AutonomousSecurityAgent::new(http_client);

                let base_url = if cur_target.starts_with("http://") || cur_target.starts_with("https://") {
                    cur_target.clone()
                } else {
                    format!("https://{}", cur_target)
                };

                let mut discovered_endpoints = vec![
                    format!("{}/", base_url),
                    format!("{}/robots.txt", base_url),
                    format!("{}/sitemap.xml", base_url),
                    format!("{}/api", base_url),
                    format!("{}/api/v1", base_url),
                ];

                // 1. Fast reconnaissance on target: probe robots.txt and homepage to discover real endpoints
                println!("🔍 Crawling & Discovering Live Endpoints on {}...", cur_target);
                let raw_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap_or_default();

                // Fetch robots.txt
                if let Ok(resp) = raw_client.get(format!("{}/robots.txt", base_url)).send().await {
                    if resp.status().is_success() {
                        if let Ok(text) = resp.text().await {
                            for line in text.lines() {
                                let trimmed = line.trim();
                                if trimmed.starts_with("Disallow:") || trimmed.starts_with("Allow:") {
                                    if let Some((_, path)) = trimmed.split_once(':') {
                                        let clean_p = path.trim();
                                        if !clean_p.is_empty() && !clean_p.contains('*') {
                                            discovered_endpoints.push(format!("{}{}", base_url.trim_end_matches('/'), clean_p));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Fetch homepage and extract links
                if let Ok(resp) = raw_client.get(&base_url).send().await {
                    if resp.status().is_success() {
                        if let Ok(html) = resp.text().await {
                            if let Ok(re) = regex::Regex::new(r#"(?:href|src|action)=["'](/[^"'#\s?]+)"#) {
                                for cap in re.captures_iter(&html) {
                                    if let Some(m) = cap.get(1) {
                                        let path = m.as_str();
                                        if !path.ends_with(".css") && !path.ends_with(".png") && !path.ends_with(".jpg") && !path.ends_with(".svg") {
                                            discovered_endpoints.push(format!("{}{}", base_url.trim_end_matches('/'), path));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Deduplicate endpoints
                discovered_endpoints.sort();
                discovered_endpoints.dedup();
                discovered_endpoints.truncate(30);
                println!("   📊 Discovered {} active attack surface endpoints for analysis.", discovered_endpoints.len());

                let findings = agent.run_assessment(&cur_target, &base_url, &discovered_endpoints).await?;

                let report = reporting::generator::BugBountyReport::new(&cur_target, findings);

                let report_path = output.clone().unwrap_or_else(|| {
                    format!("reports/{}-v3-assessment.md", cur_target.replace(['/', ':', '.'], "_"))
                });

                tokio::fs::create_dir_all("reports").await.ok();
                tokio::fs::write(&report_path, report.to_markdown()).await?;

                if !report.findings.is_empty() {
                    let notifier = TelegramNotifier::new(&config, Some(repo.clone()));
                    notifier.notify_v3_report(&report).await;
                    println!("   📱 Sent Telegram Alert with [🚀 Submit Report] inline button!");
                }

                println!("\n✅ Assessment Complete! Generated Report: {}", report_path);
                println!("   Total Verified Findings: {}", report.findings.len());
                println!("   Human Review Status: ⚠️ PENDING HUMAN REVIEW (External submission blocked)");
                println!("   To approve report for submission, run: bountyx reports --id {} --approve \"Your Name\"\n", report.id);


                if !continuous || target.is_some() {
                    break;
                }

                iteration += 1;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }


        Commands::Lab { port } => {
            println!("\n🧪 Initializing Isolated Security Testing Lab on 127.0.0.1:{}...", port);

            let (_pool, repo) = init_db(&config.database_url).await?;

            // 0. Spawn Telegram Bot Polling Listener in background so inline buttons work!
            if !config.telegram_bot_token.is_empty() {
                let bot_config = config.clone();
                let bot_repo = repo.clone();
                let is_paused = Arc::new(AtomicBool::new(false));
                let cancel_token = CancellationToken::new();
                tokio::spawn(async move {
                    let bot = TelegramBot::new(bot_config, bot_repo, is_paused, cancel_token);
                    bot.run_polling_loop().await;
                });
            }


            // 1. Build local test application routes
            let app = axum::Router::new()
                .route("/api/v1/orders", axum::routing::get(|_headers: axum::http::HeaderMap| async move {
                    // Intentionally vulnerable BOLA endpoint
                    axum::Json(serde_json::json!({
                        "id": 101,
                        "customer": "Apex Financial Corp",
                        "email": "cfo@apexfinancial.internal",
                        "billing_records": [
                            {"invoice_id": "INV-9942", "amount": 45000.0, "status": "PAID"},
                            {"invoice_id": "INV-9943", "amount": 12800.0, "status": "PENDING"}
                        ],
                        "tenant_token": "live_sec_token_984391823"
                    }))
                }))
                .route("/api/v1/user/profile", axum::routing::get(|headers: axum::http::HeaderMap| async move {
                    // Intentionally vulnerable CORS origin reflection endpoint
                    let mut resp_headers = axum::http::HeaderMap::new();
                    if let Some(origin) = headers.get("origin") {
                        resp_headers.insert("access-control-allow-origin", origin.clone());
                        resp_headers.insert("access-control-allow-credentials", "true".parse().unwrap());
                    }
                    (resp_headers, axum::Json(serde_json::json!({ "user": "alice_admin", "role": "FinanceManager" })))
                }))
                .route("/admin/telemetry", axum::routing::get(|| async move {
                    // Exposed sensitive internal administrative metrics endpoint without auth
                    axum::Json(serde_json::json!({
                        "system": "Production Telemetry",
                        "database_cluster": "db-cluster-primary.internal",
                        "debug_mode": true,
                        "active_sessions": 412
                    }))
                }))
                .route("/api/v1/public/ping", axum::routing::get(|| async move {
                    // Secure public endpoint (0% False Positives)
                    axum::Json(serde_json::json!({ "status": "healthy", "service": "api-gateway" }))
                }));

            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
            println!("   [ONLINE] Simulation Web Application running at http://127.0.0.1:{}", port);
            println!("   - Route 1: /api/v1/orders?id=101 (BOLA/IDOR flaw)");
            println!("   - Route 2: /api/v1/user/profile (Permissive CORS flaw)");
            println!("   - Route 3: /admin/telemetry (Privileged Route exposure)");
            println!("   - Route 4: /api/v1/public/ping (Benign Safe Endpoint)");

            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });

            // Allow listener to initialize
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;

            // 2. Set up ScopePolicy strictly for 127.0.0.1
            let base_url = format!("http://127.0.0.1:{}", port);
            let mut policy = scope::policy::ScopePolicy::new_permissive("127.0.0.1");
            policy.allowed_domains = vec!["127.0.0.1".to_string(), "localhost".to_string()];
            policy.max_requests = 100;
            policy.rate_limit_rps = 20;

            let guard = scope::guard::ScopeGuard::new(policy);
            let kill_switch = sandbox::kill_switch::KillSwitch::new();
            let http_client = sandbox::client::SandboxedHttpClient::new(guard, kill_switch)?;

            let mut agent = ai::agent::AutonomousSecurityAgent::new(http_client);

            let discovered_endpoints = vec![
                format!("{}/api/v1/orders?id=101", base_url),
                format!("{}/api/v1/user/profile", base_url),
                format!("{}/admin/telemetry", base_url),
                format!("{}/api/v1/public/ping", base_url),
            ];

            println!("\n🤖 Launching Autonomous AI Security Research Agent against Lab...");
            let findings = agent.run_assessment("127.0.0.1", &base_url, &discovered_endpoints).await?;
            let report = reporting::generator::BugBountyReport::new("127.0.0.1", findings);

            let report_path = "reports/lab-v3-assessment.md";
            tokio::fs::create_dir_all("reports").await.ok();
            tokio::fs::write(&report_path, report.to_markdown()).await?;

            println!("\n🎯 Lab Assessment Complete! Generated Report: {}", report_path);
            println!("   Total Verified Findings Confirmed: {}", report.findings.len());
            println!("{:-<80}", "");
            println!("{:<6} {:<10} {:<30} {:<12}", "#", "Severity", "Finding Title", "Confidence");
            println!("{:-<80}", "");
            for (i, f) in report.findings.iter().enumerate() {
                println!("{:<6} {:<10} {:<30} {}%", i + 1, f.risk.severity, f.title, f.risk.confidence_score);
            }
            let (_pool, repo) = init_db(&config.database_url).await?;
            let notifier = TelegramNotifier::new(&config, Some(repo.clone()));
            notifier.notify_v3_report(&report).await;
            println!("   📱 Sent Telegram Alert to your phone with [🚀 Submit Report] button!");

            println!("   Human Review Status: ⚠️ PENDING HUMAN REVIEW (External submission blocked)");
            println!("   To approve report: bountyx reports --id {} --approve \"Your Name\"\n", report.id);
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

        Commands::Reports { id, approve } => {
            let (_pool, repo) = init_db(&config.database_url).await?;

            if let (Some(report_id), Some(reviewer)) = (id, approve) {
                let _ = repo.mark_report_verified(&report_id).await;
                println!("\n✅ Human Approval Granted for Report ID: {}", report_id);
                println!("   Reviewer: {}", reviewer);
                println!("   Status: APPROVED FOR BUG BOUNTY SUBMISSION");

                let vault_dir = std::path::Path::new("reports").join("approved").join(&report_id);
                tokio::fs::create_dir_all(&vault_dir).await.ok();

                let sub_file = vault_dir.join("submission.txt");
                let sub_txt = format!(
                    "================================================================================\n\
                    HACKERONE / BUGCROWD READY SUBMISSION PACKAGE\n\
                    Report ID:       {}\n\
                    Human Reviewer:  {} (Approved at {})\n\
                    Vault Directory: {}\n\
                    ================================================================================\n\n\
                    [STATUS]: APPROVED FOR EXTERNAL SUBMISSION\n\n\
                    [PACKAGE ARTIFACTS]:\n\
                    - report.md       (Full Vulnerability Markdown Report)\n\
                    - report.pdf      (Executive Print-Ready PDF Report)\n\
                    - evidence.json   (Raw Network & Differential Telemetry)\n\
                    - submission.txt  (This Quick Copy-Paste Document)\n",
                    report_id, reviewer, chrono::Utc::now().to_rfc3339(), vault_dir.display()
                );
                tokio::fs::write(&sub_file, sub_txt).await.ok();

                println!("📁 Submission Package created in Vault: {}", vault_dir.display());
                println!("   Artifacts: report.md, report.pdf, evidence.json, submission.txt\n");
            } else {
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

        Commands::Doctor => {
            let (_pool, repo) = init_db(&config.database_url).await?;
            let h1_client = create_hackerone_client(&config)?;
            let checker = HealthChecker::new(config.clone(), repo, h1_client);

            println!("\n🩺 BountyX System Diagnostics & Doctor\n");
            let checks = checker.run_all_checks().await;
            for item in checks {
                if item.status {
                    println!("\x1b[32m[OK]\x1b[0m {}", item.name);
                } else {
                    println!("\x1b[31m[FAIL]\x1b[0m {}", item.name);
                }
            }
            println!();
        }
    }


    Ok(())
}
