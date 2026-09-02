use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    Subfinder,
    Httpx,
    Endpoints,
    Nuclei,
    Completed,
}

impl PipelineStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            PipelineStage::Subfinder => "SUBFINDER",
            PipelineStage::Httpx => "HTTPX",
            PipelineStage::Endpoints => "ENDPOINTS",
            PipelineStage::Nuclei => "NUCLEI",
            PipelineStage::Completed => "COMPLETED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJob {
    pub id: String,
    pub target: String,
    pub program_handle: String,
    pub current_stage: PipelineStage,
}
