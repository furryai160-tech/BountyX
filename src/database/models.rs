use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProgramRecord {
    pub id: String,
    pub handle: String,
    pub name: String,
    pub url: Option<String>,
    pub submission_state: String,
    pub offers_bounties: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AssetRecord {
    pub id: String,
    pub program_id: String,
    pub identifier: String,
    pub asset_type: String,
    pub eligible_for_bounty: bool,
    pub in_scope: bool,
    pub max_severity: Option<String>,
    pub instruction: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_scanned: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ScopeSnapshotRecord {
    pub id: String,
    pub snapshot_hash: String,
    pub total_programs: i64,
    pub total_assets: i64,
    pub raw_json: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReconJobRecord {
    pub id: String,
    pub target: String,
    pub program_handle: String,
    pub stage: String,
    pub status: String,
    pub retry_count: i64,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SubdomainRecord {
    pub id: String,
    pub program_handle: String,
    pub parent_asset: String,
    pub subdomain: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HttpHostRecord {
    pub id: String,
    pub program_handle: String,
    pub url: String,
    pub host: String,
    pub port: i64,
    pub scheme: String,
    pub status_code: Option<i64>,
    pub title: Option<String>,
    pub content_length: Option<i64>,
    pub response_time_ms: Option<i64>,
    pub technologies_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EndpointRecord {
    pub id: String,
    pub program_handle: String,
    pub host_url: String,
    pub endpoint_url: String,
    pub method: String,
    pub parameters_json: Option<String>,
    pub source: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingRecord {
    pub id: String,
    pub program_handle: String,
    pub asset: String,
    pub url: String,
    pub template_id: String,
    pub template_name: String,
    pub severity: String,
    pub matched_at: String,
    pub matcher_name: Option<String>,
    pub description: Option<String>,
    pub fingerprint: String,
    pub confidence: String,
    pub status: String,
    pub raw_result_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EvidenceRecord {
    pub id: String,
    pub finding_id: String,
    pub request_raw: Option<String>,
    pub response_raw: Option<String>,
    pub curl_command: Option<String>,
    pub scanner_output_raw: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReportRecord {
    pub id: String,
    pub finding_id: String,
    pub title: String,
    pub file_path: String,
    pub markdown_content: String,
    pub human_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationRecord {
    pub id: String,
    pub message_type: String,
    pub content: String,
    pub sent_at: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ToolRunRecord {
    pub id: String,
    pub job_id: Option<String>,
    pub tool: String,
    pub target: String,
    pub command_args: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub exit_code: Option<i64>,
    pub status: String,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLogRecord {
    pub id: String,
    pub event_type: String,
    pub target: String,
    pub decision: String,
    pub reason: String,
    pub tool: Option<String>,
    pub metadata_json: Option<String>,
    pub timestamp: DateTime<Utc>,
}

