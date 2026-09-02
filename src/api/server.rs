use crate::api::routes::*;
use crate::config::AppConfig;
use crate::database::repository::Repository;
use crate::hackerone::client::HackerOneClientTrait;
use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info};

pub async fn start_api_server(
    config: AppConfig,
    repository: Repository,
    hackerone_client: Arc<dyn HackerOneClientTrait>,
    is_paused: Arc<AtomicBool>,
    cancel_token: CancellationToken,
) {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let state = AppState {
        config,
        repository,
        hackerone_client,
        is_paused,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/programs", get(get_programs))
        .route("/api/scope", get(get_scope))
        .route("/api/findings", get(get_findings))
        .route("/api/findings/:id/evidence", get(get_finding_evidence))
        .route("/api/reports", get(get_reports))
        .route("/api/queue", get(get_queue))
        .route("/api/health", get(get_health))
        .route("/api/audit", get(get_audit))
        .route("/api/scan", post(start_scan))
        .route("/api/control/pause", post(pause_pipeline))
        .route("/api/control/resume", post(resume_pipeline))
        .layer(cors)
        .with_state(state);

    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!("🌐 Web REST API Server listening on http://0.0.0.0:{}", port);
            let shutdown = async move {
                cancel_token.cancelled().await;
                info!("API server received shutdown signal.");
            };

            if let Err(e) = axum::serve(listener, app).with_graceful_shutdown(shutdown).await {
                error!("API server encountered an error: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to bind Web REST API listener to {}: {}", addr, e);
        }
    }
}
