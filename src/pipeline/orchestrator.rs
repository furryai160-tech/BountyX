use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::errors::Result;
use crate::pipeline::worker::PipelineWorker;
use crate::telegram::TelegramNotifier;
use crate::validation::ScopeGuard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct PipelineOrchestrator {
    config: AppConfig,
    repository: Repository,
    notifier: TelegramNotifier,
    is_paused: Arc<AtomicBool>,
    cancellation_token: CancellationToken,
}

impl PipelineOrchestrator {
    pub fn new(
        config: AppConfig,
        repository: Repository,
        notifier: TelegramNotifier,
        is_paused: Arc<AtomicBool>,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            config,
            repository,
            notifier,
            is_paused,
            cancellation_token,
        }
    }

    pub async fn run_worker_pool(&self) -> Result<()> {
        let max_workers = self.config.max_concurrent_jobs;
        let semaphore = Arc::new(Semaphore::new(max_workers));

        info!(
            "Pipeline Orchestrator started with {} concurrent worker slots.",
            max_workers
        );

        // Reset any leftover 'RUNNING' jobs from previous crashes
        let _ = self.repository.reset_running_jobs_to_queued().await;

        while !self.cancellation_token.is_cancelled() {
            // Check if paused via Telegram command
            if self.is_paused.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            // Acquire permit before claiming job
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    // All worker slots are busy, sleep briefly
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };

            // Try to claim next job from database
            let maybe_job = match self.repository.claim_next_recon_job().await {
                Ok(j) => j,
                Err(e) => {
                    error!("Database error claiming next job: {}", e);
                    drop(permit);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            if let Some(job) = maybe_job {
                // Build dynamic ScopeGuard for the current job program
                let in_scope_assets = self
                    .repository
                    .list_all_in_scope_identifiers()
                    .await
                    .unwrap_or_default();
                let scope_guard = Arc::new(ScopeGuard::from_rules(&in_scope_assets, &[]));

                let worker = PipelineWorker::new(
                    self.config.clone(),
                    self.repository.clone(),
                    self.notifier.clone(),
                );

                let cancel_token = self.cancellation_token.clone();

                // Spawn task in Tokio worker pool
                tokio::spawn(async move {
                    let job_id = job.id.clone();
                    let target = job.target.clone();

                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            warn!("Job '{}' cancelled during execution due to shutdown.", job_id);
                        }
                        res = worker.process_job(job, scope_guard) => {
                            if let Err(err) = res {
                                error!("Job '{}' on target '{}' failed: {}", job_id, target, err);
                            }
                        }
                    }

                    // Release semaphore permit
                    drop(permit);
                });
            } else {
                // No jobs in queue, drop permit and sleep
                drop(permit);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }

        info!("Pipeline Orchestrator stopped gracefully.");
        Ok(())
    }
}
