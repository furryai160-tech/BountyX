use crate::errors::Result;
use crate::evidence::CollectedEvidence;
use crate::reporting::templates::ReportTemplate;
use chrono::Utc;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct MarkdownReportGenerator {
    reports_dir: PathBuf,
}

impl MarkdownReportGenerator {
    pub fn new<P: AsRef<Path>>(reports_dir: P) -> Self {
        Self {
            reports_dir: reports_dir.as_ref().to_path_buf(),
        }
    }

    pub async fn generate_report(
        &self,
        evidence: &CollectedEvidence,
        program_handle: &str,
    ) -> Result<(String, String)> {
        // Ensure reports directory exists
        tokio::fs::create_dir_all(&self.reports_dir).await?;

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let safe_template_id = evidence
            .template_id
            .replace('/', "_")
            .replace('\\', "_")
            .replace(':', "_");
        let safe_target = evidence
            .target
            .replace('/', "_")
            .replace(':', "_")
            .replace('.', "_");

        let filename = format!(
            "report_{}_{}_{}_{}.md",
            program_handle, safe_target, safe_template_id, timestamp
        );
        let file_path = self.reports_dir.join(&filename);

        let markdown_content = ReportTemplate::render_markdown(evidence, program_handle);

        tokio::fs::write(&file_path, &markdown_content).await?;

        info!("Draft vulnerability report saved to: {:?}", file_path);

        Ok((file_path.to_string_lossy().to_string(), markdown_content))
    }
}
