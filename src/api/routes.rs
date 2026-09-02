use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::hackerone::client::HackerOneClientTrait;
use crate::health::HealthChecker;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub repository: Repository,
    pub hackerone_client: Arc<dyn HackerOneClientTrait>,
    pub is_paused: Arc<AtomicBool>,
}

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub program: Option<String>,
}

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.get_stats().await {
        Ok(stats) => Json(json!({
            "ok": true,
            "is_paused": state.is_paused.load(Ordering::SeqCst),
            "max_workers": state.config.max_concurrent_jobs,
            "stats": stats
        })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_programs(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_programs().await {
        Ok(programs) => Json(json!({ "ok": true, "programs": programs })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_scope(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_in_scope_assets().await {
        Ok(assets) => Json(json!({ "ok": true, "assets": assets })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_findings(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_findings(None).await {
        Ok(findings) => Json(json!({ "ok": true, "findings": findings })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_finding_evidence(
    State(state): State<AppState>,
    Path(finding_id): Path<String>,
) -> impl IntoResponse {
    match state.repository.get_evidence_by_finding_id(&finding_id).await {
        Ok(evidence) => Json(json!({ "ok": true, "evidence": evidence })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}


pub async fn get_reports(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_reports().await {
        Ok(reports) => Json(json!({ "ok": true, "reports": reports })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_queue(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_jobs(100).await {
        Ok(jobs) => Json(json!({ "ok": true, "jobs": jobs })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let checker = HealthChecker::new(
        state.config.clone(),
        state.repository.clone(),
        state.hackerone_client.clone(),
    );
    let checks = checker.run_all_checks().await;
    Json(json!({ "ok": true, "checks": checks }))
}

pub async fn get_audit(State(state): State<AppState>) -> impl IntoResponse {
    match state.repository.list_audit_events(100).await {
        Ok(events) => Json(json!({ "ok": true, "events": events })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

pub async fn start_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    let target = payload.target.trim();
    if target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "Target cannot be empty" })),
        );
    }

    let program = payload.program.unwrap_or_else(|| "manual_web".to_string());
    match state.repository.enqueue_recon_job(target, &program).await {
        Ok(job_id) => {
            info!("Enqueued scan job '{}' for target '{}' via Web Dashboard", job_id, target);
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "job_id": job_id,
                    "target": target,
                    "program": program,
                    "message": "Scan job queued successfully"
                })),
            )
        }
        Err(e) => {
            warn!("Failed to enqueue scan job for '{}': {}", target, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": e.to_string() })),
            )
        }
    }
}

pub async fn pause_pipeline(State(state): State<AppState>) -> impl IntoResponse {
    state.is_paused.store(true, Ordering::SeqCst);
    info!("Automation pipeline paused via Web Dashboard");
    Json(json!({ "ok": true, "is_paused": true }))
}

pub async fn resume_pipeline(State(state): State<AppState>) -> impl IntoResponse {
    state.is_paused.store(false, Ordering::SeqCst);
    info!("Automation pipeline resumed via Web Dashboard");
    Json(json!({ "ok": true, "is_paused": false }))
}
