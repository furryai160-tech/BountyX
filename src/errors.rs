use thiserror::Error;

#[derive(Error, Debug)]
pub enum BountyScopeError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Network/HTTP request failed: {0}")]
    Network(#[from] reqwest::Error),

    #[error("HackerOne API error ({status}): {message}")]
    HackerOneApi { status: u16, message: String },

    #[error("Scope validation blocked target: '{target}'. Reason: {reason}")]
    ScopeViolation { target: String, reason: String },

    #[error("Scope policy violation: {0}")]
    Scope(String),


    #[error("External process '{binary}' failed with code {code:?}: {stderr}")]
    ProcessExecution {
        binary: String,
        code: Option<i32>,
        stderr: String,
    },

    #[error("External process timeout after {timeout_secs}s: '{binary}'")]
    ProcessTimeout {
        binary: String,
        timeout_secs: u64,
    },

    #[error("Missing required binary in PATH: '{0}'")]
    MissingBinary(String),

    #[error("Telegram API error ({code:?}): {message}")]
    TelegramApi {
        code: Option<i32>,
        message: String,
    },

    #[error("Telegram unauthorized access attempt from chat_id: {0}")]
    TelegramUnauthorized(i64),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("IP/CIDR parsing error: {0}")]
    IpNetParse(#[from] ipnet::AddrParseError),

    #[error("Pipeline error: {0}")]
    Pipeline(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, BountyScopeError>;
