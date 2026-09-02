use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::Result;
use crate::hackerone::client::HackerOneClientTrait;
use crate::hackerone::models::NormalizedProgramScope;
use crate::monitor::diff::{ScopeDiff, ScopeDiffEngine};
use crate::pipeline::ReconQueue;
use crate::telegram::TelegramNotifier;
use crate::validation::Deduplicator;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct ScopeMonitorScheduler {
    config: AppConfig,
    repository: Repository,
    hackerone_client: Arc<dyn HackerOneClientTrait>,
    notifier: TelegramNotifier,
    recon_queue: ReconQueue,
    cancellation_token: CancellationToken,
}

impl ScopeMonitorScheduler {
    pub fn new(
        config: AppConfig,
        repository: Repository,
        hackerone_client: Arc<dyn HackerOneClientTrait>,
        notifier: TelegramNotifier,
        cancellation_token: CancellationToken,
    ) -> Self {
        let recon_queue = ReconQueue::new(repository.clone());
        Self {
            config,
            repository,
            hackerone_client,
            notifier,
            recon_queue,
            cancellation_token,
        }
    }

    pub async fn run_monitor_loop(&self) -> Result<()> {
        let interval = Duration::from_secs(self.config.scope_poll_interval_seconds);
        info!(
            "Scope Monitor started. Polling interval: {} seconds",
            self.config.scope_poll_interval_seconds
        );

        while !self.cancellation_token.is_cancelled() {
            info!("Starting scheduled scope synchronization cycle...");
            match self.sync_and_diff().await {
                Ok(diff) => {
                    info!(
                        "Scope sync complete. Discovered: {} new targets, Removed: {} targets. Total active targets: {}",
                        diff.new_targets.len(),
                        diff.removed_targets.len(),
                        diff.total_current_targets
                    );
                }
                Err(err) => {
                    error!("Error during scope synchronization cycle: {}", err);
                    self.notifier
                        .notify_error("Scope Monitor", "Scope Sync", &err.to_string())
                        .await;
                }
            }

            tokio::select! {
                _ = self.cancellation_token.cancelled() => {
                    info!("Scope Monitor stopped by cancellation signal.");
                    break;
                }
                _ = tokio::time::sleep(interval) => {}
            }
        }

        Ok(())
    }

    pub async fn sync_and_diff(&self) -> Result<ScopeDiff> {
        // Ensure data directory exists
        tokio::fs::create_dir_all(&self.config.data_dir).await?;

        // 1. Fetch current scope from HackerOne adapter
        let current_scopes = self.hackerone_client.fetch_all_in_scope_assets().await?;

        // 2. Load previous scope from database or file
        let current_json = serde_json::to_string_pretty(&current_scopes)?;
        let current_hash = Deduplicator::compute_scope_hash(&current_json);

        let previous_scopes: Vec<NormalizedProgramScope> = match self
            .repository
            .get_latest_scope_snapshot()
            .await?
        {
            Some(snap) => serde_json::from_str(&snap.raw_json).unwrap_or_default(),
            None => Vec::new(),
        };

        // 3. Compute Diff
        let diff = ScopeDiffEngine::compute_diff(&previous_scopes, &current_scopes);

        // 4. Update Database
        let mut total_assets_count: i64 = 0;
        for prog in &current_scopes {
            let prog_id = self
                .repository
                .upsert_program(
                    &prog.program.handle,
                    &prog.program.name,
                    prog.program.url.as_deref(),
                    &prog.program.submission_state,
                    prog.program.offers_bounties,
                )
                .await?;

            for asset in &prog.in_scope_assets {
                total_assets_count += 1;
                let is_bounty = asset.bounty_eligibility == crate::hackerone::models::BountyEligibility::Eligible;
                let _ = self
                    .repository
                    .upsert_asset(
                        &prog_id,
                        &asset.asset_identifier,
                        asset.asset_type.as_str(),
                        is_bounty,
                        true,
                        asset.max_severity.as_deref(),
                        asset.instruction.as_deref(),
                    )
                    .await;
            }

            for asset in &prog.out_of_scope_assets {
                let is_bounty = asset.bounty_eligibility == crate::hackerone::models::BountyEligibility::Eligible;
                let _ = self
                    .repository
                    .upsert_asset(
                        &prog_id,
                        &asset.asset_identifier,
                        asset.asset_type.as_str(),
                        is_bounty,
                        false,
                        asset.max_severity.as_deref(),
                        asset.instruction.as_deref(),
                    )
                    .await;
            }
        }

        // Save Snapshot
        self.repository
            .save_scope_snapshot(
                &current_hash,
                current_scopes.len() as i64,
                total_assets_count,
                &current_json,
            )
            .await?;

        // 5. Update local JSON cache files
        let current_file = self.config.data_dir.join("scope.current.json");
        let previous_file = self.config.data_dir.join("scope.previous.json");
        let targets_file = self.config.data_dir.join("targets.txt");

        // If current exists, move to previous
        if current_file.exists() {
            let _ = tokio::fs::copy(&current_file, &previous_file).await;
        }
        let _ = tokio::fs::write(&current_file, &current_json).await;

        // Write targets.txt
        let all_targets = crate::hackerone::ScopeResolver::extract_actionable_targets(&current_scopes);
        let targets_txt_content = all_targets
            .iter()
            .map(|(prog, t)| format!("{}\t{}", prog, t))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = tokio::fs::write(&targets_file, targets_txt_content).await;

        // 6. Handle New Targets: Validate with Scope Guard, Alert & Enqueue
        let in_scope_assets = self
            .repository
            .list_all_in_scope_identifiers()
            .await
            .unwrap_or_default();
        let scope_guard = crate::validation::ScopeGuard::from_rules(&in_scope_assets, &[]);

        // Group valid targets by program
        let mut program_targets: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

        for (prog_handle, target) in &diff.new_targets {
            if scope_guard.is_in_scope(target) {
                info!("🆕 NEW IN-SCOPE TARGET DETECTED: '{}' (Program: '{}')", target, prog_handle);

                let _ = self
                    .repository
                    .record_audit_event(
                        "NEW_IN_SCOPE_TARGET",
                        target,
                        "AUTHORIZED",
                        "New asset confirmed in-scope during sync",
                        Some("scope_sync"),
                        None,
                    )
                    .await;

                // Enqueue into recon pipeline
                let _ = self.recon_queue.enqueue_target(target, prog_handle).await;

                program_targets
                    .entry(prog_handle.clone())
                    .or_default()
                    .push(target.clone());
            } else {
                warn!("Blocked out-of-scope new target: '{}'", target);
                let _ = self
                    .repository
                    .record_audit_event(
                        "NEW_TARGET",
                        target,
                        "BLOCKED",
                        "Discovered asset not authorized by active scope rules",
                        Some("scope_sync"),
                        None,
                    )
                    .await;
            }
        }

        // Send Telegram Notifications (Batched per program to respect Telegram rate limits)
        for (prog_handle, targets) in program_targets {
            if targets.len() <= 3 {
                for t in &targets {
                    self.notifier.notify_new_target(&prog_handle, t).await;
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            } else {
                self.notifier
                    .notify_new_targets_summary(&prog_handle, targets.len(), &targets)
                    .await;
            }
        }

        Ok(diff)
    }


}
