-- Initial SQLite Schema for BountyScope

PRAGMA foreign_keys = ON;

-- Programs table
CREATE TABLE IF NOT EXISTS programs (
    id TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    url TEXT,
    submission_state TEXT NOT NULL DEFAULT 'open',
    offers_bounties BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Assets table (Scope targets)
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    eligible_for_bounty BOOLEAN NOT NULL DEFAULT 0,
    in_scope BOOLEAN NOT NULL DEFAULT 1,
    max_severity TEXT,
    instruction TEXT,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scanned DATETIME,
    FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE,
    UNIQUE(program_id, identifier)
);
CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(identifier);
CREATE INDEX IF NOT EXISTS idx_assets_in_scope ON assets(in_scope);

-- Scope Snapshots for historical auditing
CREATE TABLE IF NOT EXISTS scope_snapshots (
    id TEXT PRIMARY KEY,
    snapshot_hash TEXT NOT NULL,
    total_programs INTEGER NOT NULL,
    total_assets INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Recon Pipeline Jobs
CREATE TABLE IF NOT EXISTS recon_jobs (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    program_handle TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'SUBFINDER',
    status TEXT NOT NULL DEFAULT 'QUEUED', -- QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    retry_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_recon_jobs_status ON recon_jobs(status);
CREATE INDEX IF NOT EXISTS idx_recon_jobs_target ON recon_jobs(target);

-- Subdomains discovered
CREATE TABLE IF NOT EXISTS subdomains (
    id TEXT PRIMARY KEY,
    program_handle TEXT NOT NULL,
    parent_asset TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_handle, subdomain)
);
CREATE INDEX IF NOT EXISTS idx_subdomains_subdomain ON subdomains(subdomain);

-- Live HTTP Hosts
CREATE TABLE IF NOT EXISTS http_hosts (
    id TEXT PRIMARY KEY,
    program_handle TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    content_length INTEGER,
    response_time_ms INTEGER,
    technologies_json TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_http_hosts_host ON http_hosts(host);

-- Discovered Endpoints & Parameters
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    program_handle TEXT NOT NULL,
    host_url TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    parameters_json TEXT,
    source TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(program_handle, endpoint_url)
);

-- Findings (Strictly POTENTIAL until verified by human)
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    program_handle TEXT NOT NULL,
    asset TEXT NOT NULL,
    url TEXT NOT NULL,
    template_id TEXT NOT NULL,
    template_name TEXT NOT NULL,
    severity TEXT NOT NULL, -- INFO, LOW, MEDIUM, HIGH, CRITICAL
    matched_at TEXT NOT NULL,
    matcher_name TEXT,
    description TEXT,
    fingerprint TEXT NOT NULL UNIQUE,
    confidence TEXT NOT NULL DEFAULT 'POTENTIAL',
    status TEXT NOT NULL DEFAULT 'REQUIRES_REVIEW', -- NEW, POTENTIAL, DUPLICATE, REQUIRES_REVIEW, CONFIRMED_BY_USER, REJECTED
    raw_result_json TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);

-- Evidence table
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    request_raw TEXT,
    response_raw TEXT,
    curl_command TEXT,
    scanner_output_raw TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

-- Markdown Reports
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT NOT NULL,
    markdown_content TEXT NOT NULL,
    human_verified BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

-- Notification log
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    message_type TEXT NOT NULL,
    content TEXT NOT NULL,
    sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'SENT'
);
