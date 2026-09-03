pub mod ai_writer;
pub mod cvss;
pub mod generator;
pub mod markdown;
pub mod templates;

pub use ai_writer::{AntiHallucinationGate, EvidencePackage, FindingReportBlock, ReportDraft, SmartReportWriter, VerificationStatus};
pub use cvss::{Cvss31Engine, Cvss31Metrics};
pub use generator::BugBountyReport;
pub use markdown::MarkdownReportGenerator;
pub use templates::ReportTemplate;
