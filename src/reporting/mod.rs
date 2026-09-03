pub mod ai_writer;
pub mod cvss;
pub mod generator;
pub mod markdown;
pub mod pdf;
pub mod templates;
pub mod vault;

pub use ai_writer::{AntiHallucinationGate, EvidencePackage, FindingReportBlock, ReportDraft, SmartReportWriter, VerificationStatus};
pub use cvss::{Cvss31Engine, Cvss31Metrics};
pub use generator::BugBountyReport;
pub use markdown::MarkdownReportGenerator;
pub use pdf::PdfReportGenerator;
pub use templates::ReportTemplate;
pub use vault::SubmissionVault;
