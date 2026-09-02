use crate::database::repository::Repository;
use crate::errors::Result;
use tracing::info;

pub struct ReconQueue {
    repository: Repository,
}

impl ReconQueue {
    pub fn new(repository: Repository) -> Self {
        Self { repository }
    }

    pub async fn enqueue_target(&self, target: &str, program_handle: &str) -> Result<String> {
        self.repository.enqueue_recon_job(target, program_handle).await
    }

    pub async fn recover_interrupted_jobs(&self) -> Result<u64> {
        let count = self.repository.reset_running_jobs_to_queued().await?;
        if count > 0 {
            info!("Recovered {} interrupted jobs back to QUEUED status.", count);
        }
        Ok(count)
    }
}
