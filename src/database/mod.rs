pub mod models;
pub mod repository;

use crate::errors::{BountyScopeError, Result};
use repository::Repository;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;
use tracing::info;

pub async fn init_db(database_url: &str) -> Result<(Pool<Sqlite>, Repository)> {
    // If using sqlite file, ensure parent directory exists
    if let Some(path_str) = database_url.strip_prefix("sqlite://") {
        let path = std::path::Path::new(path_str);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    let connection_options = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| BountyScopeError::Config(format!("Invalid database URL: {}", e)))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(60))
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(30)
        .acquire_timeout(std::time::Duration::from_secs(60))
        .connect_with(connection_options)
        .await?;

    info!("Running database schema migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(BountyScopeError::Migration)?;

    info!("Database initialized successfully with WAL mode.");
    let repo = Repository::new(pool.clone());
    Ok((pool, repo))
}
