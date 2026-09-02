-- Migration: 20260830000000_add_tool_runs_and_audit.sql
-- Description: Add tool_runs and audit_logs tables for BountyScope V2

CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY,
    job_id TEXT,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    command_args TEXT NOT NULL,
    start_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME,
    exit_code INTEGER,
    status TEXT NOT NULL, -- RUNNING, SUCCESS, FAILED, TIMEOUT
    error TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tool_runs_tool ON tool_runs(tool);
CREATE INDEX IF NOT EXISTS idx_tool_runs_target ON tool_runs(target);
CREATE INDEX IF NOT EXISTS idx_tool_runs_status ON tool_runs(status);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL, -- SCOPE_EVALUATION, REDIRECT_CHECK, TOOL_INVOCATION, TELEGRAM_COMMAND, SYSTEM_STATE
    target TEXT NOT NULL,
    decision TEXT NOT NULL,   -- AUTHORIZED, BLOCKED, ALLOWED, REJECTED
    reason TEXT NOT NULL,
    tool TEXT,
    metadata_json TEXT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target);
CREATE INDEX IF NOT EXISTS idx_audit_logs_decision ON audit_logs(decision);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
