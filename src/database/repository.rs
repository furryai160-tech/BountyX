use crate::database::models::*;
use crate::errors::Result;
use chrono::Utc;
use sqlx::{Pool, Row, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct Repository {
    pool: Pool<Sqlite>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemStats {
    pub total_programs: i64,
    pub total_assets: i64,
    pub in_scope_assets: i64,
    pub queued_jobs: i64,
    pub running_jobs: i64,
    pub completed_jobs: i64,
    pub failed_jobs: i64,
    pub total_findings: i64,
    pub potential_findings: i64,
    pub total_reports: i64,
    pub verified_reports: i64,
}

impl Repository {
    pub fn new(pool: Pool<Sqlite>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    // -------------------------------------------------------------------------
    // Programs
    // -------------------------------------------------------------------------
    pub async fn upsert_program(
        &self,
        handle: &str,
        name: &str,
        url: Option<&str>,
        submission_state: &str,
        offers_bounties: bool,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let row = sqlx::query(
            r#"
            INSERT INTO programs (id, handle, name, url, submission_state, offers_bounties, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(handle) DO UPDATE SET
                name = excluded.name,
                url = excluded.url,
                submission_state = excluded.submission_state,
                offers_bounties = excluded.offers_bounties,
                updated_at = excluded.updated_at
            RETURNING id
            "#
        )
        .bind(&id)
        .bind(handle)
        .bind(name)
        .bind(url)
        .bind(submission_state)
        .bind(offers_bounties)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        let returned_id: String = row.get("id");
        Ok(returned_id)
    }

    pub async fn list_programs(&self) -> Result<Vec<ProgramRecord>> {
        let programs = sqlx::query_as::<_, ProgramRecord>(
            r#"
            SELECT id, handle, name, url, submission_state, offers_bounties, created_at, updated_at
            FROM programs
            ORDER BY handle ASC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(programs)
    }

    pub async fn get_program_by_handle(&self, handle: &str) -> Result<Option<ProgramRecord>> {
        let program = sqlx::query_as::<_, ProgramRecord>(
            r#"
            SELECT id, handle, name, url, submission_state, offers_bounties, created_at, updated_at
            FROM programs
            WHERE handle = ?1
            "#
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await?;

        Ok(program)
    }

    // -------------------------------------------------------------------------
    // Assets
    // -------------------------------------------------------------------------
    pub async fn upsert_asset(
        &self,
        program_id: &str,
        identifier: &str,
        asset_type: &str,
        eligible_for_bounty: bool,
        in_scope: bool,
        max_severity: Option<&str>,
        instruction: Option<&str>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let row = sqlx::query(
            r#"
            INSERT INTO assets (id, program_id, identifier, asset_type, eligible_for_bounty, in_scope, max_severity, instruction, first_seen, last_seen)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(program_id, identifier) DO UPDATE SET
                asset_type = excluded.asset_type,
                eligible_for_bounty = excluded.eligible_for_bounty,
                in_scope = excluded.in_scope,
                max_severity = excluded.max_severity,
                instruction = excluded.instruction,
                last_seen = excluded.last_seen
            RETURNING id
            "#
        )
        .bind(&id)
        .bind(program_id)
        .bind(identifier)
        .bind(asset_type)
        .bind(eligible_for_bounty)
        .bind(in_scope)
        .bind(max_severity)
        .bind(instruction)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        let returned_id: String = row.get("id");
        Ok(returned_id)
    }

    pub async fn list_in_scope_assets(&self) -> Result<Vec<AssetRecord>> {
        let assets = sqlx::query_as::<_, AssetRecord>(
            r#"
            SELECT id, program_id, identifier, asset_type, eligible_for_bounty, in_scope, max_severity, instruction, first_seen, last_seen, last_scanned
            FROM assets
            WHERE in_scope = 1
            ORDER BY identifier ASC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(assets)
    }

    pub async fn list_all_in_scope_identifiers(&self) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT identifier
            FROM assets
            WHERE in_scope = 1
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.get::<String, _>("identifier")).collect())
    }

    /// Verifies if a given hostname or target is strictly in-scope of an enrolled program.
    /// Returns Some(program_id) if authorized, or None if out-of-scope.
    pub async fn check_target_in_scope(&self, target_host: &str) -> Result<Option<String>> {
        let clean_host = target_host
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target_host)
            .split(':')
            .next()
            .unwrap_or(target_host)
            .to_lowercase();

        // 1. Allow local security lab
        if clean_host == "127.0.0.1" || clean_host == "localhost" {
            return Ok(Some("local-security-lab".to_string()));
        }

        // 2. Direct match or wildcard match (*.example.com)
        let row = sqlx::query(
            r#"
            SELECT program_id, identifier
            FROM assets
            WHERE in_scope = 1 AND (
                LOWER(identifier) = ?1
                OR (identifier LIKE '*.%' AND ?1 LIKE '%' || SUBSTR(identifier, 3))
            )
            LIMIT 1
            "#
        )
        .bind(&clean_host)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let prog: String = r.get("program_id");
            return Ok(Some(prog));
        }

        Ok(None)
    }

    pub async fn update_asset_last_scanned(&self, identifier: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE assets
            SET last_scanned = ?1
            WHERE identifier = ?2
            "#
        )
        .bind(now)
        .bind(identifier)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_next_unscanned_in_scope_target(&self) -> Result<Option<(String, String)>> {
        let row = sqlx::query(
            r#"
            SELECT p.handle, a.identifier
            FROM assets a
            JOIN programs p ON a.program_id = p.id
            WHERE a.in_scope = 1
              AND a.asset_type = 'URL'
              AND a.identifier NOT LIKE '*%'
              AND a.identifier NOT LIKE 'https://*%'
            ORDER BY 
              CASE WHEN a.last_scanned IS NULL THEN 0 ELSE 1 END ASC,
              a.eligible_for_bounty DESC,
              a.last_scanned ASC,
              a.first_seen ASC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| (r.get("handle"), r.get("identifier"))))
    }


    // -------------------------------------------------------------------------
    // Scope Snapshots
    // -------------------------------------------------------------------------
    pub async fn save_scope_snapshot(
        &self,
        snapshot_hash: &str,
        total_programs: i64,
        total_assets: i64,
        raw_json: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO scope_snapshots (id, snapshot_hash, total_programs, total_assets, raw_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#
        )
        .bind(&id)
        .bind(snapshot_hash)
        .bind(total_programs)
        .bind(total_assets)
        .bind(raw_json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn get_latest_scope_snapshot(&self) -> Result<Option<ScopeSnapshotRecord>> {
        let snapshot = sqlx::query_as::<_, ScopeSnapshotRecord>(
            r#"
            SELECT id, snapshot_hash, total_programs, total_assets, raw_json, created_at
            FROM scope_snapshots
            ORDER BY created_at DESC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(snapshot)
    }

    // -------------------------------------------------------------------------
    // Recon Jobs (Queue)
    // -------------------------------------------------------------------------
    pub async fn enqueue_recon_job(&self, target: &str, program_handle: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        // Check if job already queued or running
        let existing = sqlx::query(
            r#"
            SELECT id FROM recon_jobs
            WHERE target = ?1 AND status IN ('QUEUED', 'RUNNING')
            "#
        )
        .bind(target)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = existing {
            let existing_id: String = row.get("id");
            return Ok(existing_id);
        }

        sqlx::query(
            r#"
            INSERT INTO recon_jobs (id, target, program_handle, stage, status, retry_count, error_message, created_at, updated_at)
            VALUES (?1, ?2, ?3, 'SUBFINDER', 'QUEUED', 0, NULL, ?4, ?5)
            "#
        )
        .bind(&id)
        .bind(target)
        .bind(program_handle)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn claim_next_recon_job(&self) -> Result<Option<ReconJobRecord>> {
        let now = Utc::now();

        let job = sqlx::query_as::<_, ReconJobRecord>(
            r#"
            SELECT id, target, program_handle, stage, status, retry_count, error_message, created_at, updated_at
            FROM recon_jobs
            WHERE status = 'QUEUED'
            ORDER BY created_at ASC
            LIMIT 1
            "#
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(job) = job {
            sqlx::query(
                r#"
                UPDATE recon_jobs
                SET status = 'RUNNING', updated_at = ?1
                WHERE id = ?2
                "#
            )
            .bind(now)
            .bind(&job.id)
            .execute(&self.pool)
            .await?;

            return Ok(Some(job));
        }

        Ok(None)
    }

    pub async fn claim_recon_job_by_id(&self, job_id: &str) -> Result<Option<ReconJobRecord>> {
        let now = Utc::now();

        let job = sqlx::query_as::<_, ReconJobRecord>(
            r#"
            SELECT id, target, program_handle, stage, status, retry_count, error_message, created_at, updated_at
            FROM recon_jobs
            WHERE id = ?1
            "#
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(job) = job {
            sqlx::query(
                r#"
                UPDATE recon_jobs
                SET status = 'RUNNING', updated_at = ?1
                WHERE id = ?2
                "#
            )
            .bind(now)
            .bind(&job.id)
            .execute(&self.pool)
            .await?;

            return Ok(Some(job));
        }

        Ok(None)
    }


    pub async fn update_job_status(
        &self,
        job_id: &str,
        stage: &str,
        status: &str,
        error_message: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE recon_jobs
            SET stage = ?1, status = ?2, error_message = ?3, updated_at = ?4
            WHERE id = ?5
            "#
        )
        .bind(stage)
        .bind(status)
        .bind(error_message)
        .bind(now)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn reset_running_jobs_to_queued(&self) -> Result<u64> {
        let now = Utc::now();
        let res = sqlx::query(
            r#"
            UPDATE recon_jobs
            SET status = 'QUEUED', updated_at = ?1
            WHERE status = 'RUNNING'
            "#
        )
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected())
    }

    pub async fn list_jobs(&self, limit: i64) -> Result<Vec<ReconJobRecord>> {
        let jobs = sqlx::query_as::<_, ReconJobRecord>(
            r#"
            SELECT id, target, program_handle, stage, status, retry_count, error_message, created_at, updated_at
            FROM recon_jobs
            ORDER BY updated_at DESC
            LIMIT ?1
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(jobs)
    }

    // -------------------------------------------------------------------------
    // Subdomains
    // -------------------------------------------------------------------------
    pub async fn save_subdomain(
        &self,
        program_handle: &str,
        parent_asset: &str,
        subdomain: &str,
        source: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO subdomains (id, program_handle, parent_asset, subdomain, source, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(program_handle, subdomain) DO NOTHING
            "#
        )
        .bind(&id)
        .bind(program_handle)
        .bind(parent_asset)
        .bind(subdomain)
        .bind(source)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn list_subdomains_for_program(&self, program_handle: &str) -> Result<Vec<SubdomainRecord>> {
        let subdomains = sqlx::query_as::<_, SubdomainRecord>(
            r#"
            SELECT id, program_handle, parent_asset, subdomain, source, created_at
            FROM subdomains
            WHERE program_handle = ?1
            ORDER BY subdomain ASC
            "#
        )
        .bind(program_handle)
        .fetch_all(&self.pool)
        .await?;

        Ok(subdomains)
    }

    // -------------------------------------------------------------------------
    // HTTP Hosts
    // -------------------------------------------------------------------------
    pub async fn save_http_host(
        &self,
        program_handle: &str,
        url: &str,
        host: &str,
        port: i64,
        scheme: &str,
        status_code: Option<i64>,
        title: Option<&str>,
        content_length: Option<i64>,
        response_time_ms: Option<i64>,
        technologies_json: Option<&str>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO http_hosts (id, program_handle, url, host, port, scheme, status_code, title, content_length, response_time_ms, technologies_json, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(url) DO UPDATE SET
                status_code = excluded.status_code,
                title = excluded.title,
                content_length = excluded.content_length,
                response_time_ms = excluded.response_time_ms,
                technologies_json = excluded.technologies_json
            "#
        )
        .bind(&id)
        .bind(program_handle)
        .bind(url)
        .bind(host)
        .bind(port)
        .bind(scheme)
        .bind(status_code)
        .bind(title)
        .bind(content_length)
        .bind(response_time_ms)
        .bind(technologies_json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn list_http_hosts_for_program(&self, program_handle: &str) -> Result<Vec<HttpHostRecord>> {
        let hosts = sqlx::query_as::<_, HttpHostRecord>(
            r#"
            SELECT id, program_handle, url, host, port, scheme, status_code, title, content_length, response_time_ms, technologies_json, created_at
            FROM http_hosts
            WHERE program_handle = ?1
            ORDER BY url ASC
            "#
        )
        .bind(program_handle)
        .fetch_all(&self.pool)
        .await?;

        Ok(hosts)
    }

    pub async fn list_all_live_http_urls(&self) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT url
            FROM http_hosts
            ORDER BY url ASC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }


    // -------------------------------------------------------------------------
    // Endpoints
    // -------------------------------------------------------------------------
    pub async fn save_endpoint(
        &self,
        program_handle: &str,
        host_url: &str,
        endpoint_url: &str,
        method: &str,
        parameters_json: Option<&str>,
        source: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO endpoints (id, program_handle, host_url, endpoint_url, method, parameters_json, source, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(program_handle, endpoint_url) DO NOTHING
            "#
        )
        .bind(&id)
        .bind(program_handle)
        .bind(host_url)
        .bind(endpoint_url)
        .bind(method)
        .bind(parameters_json)
        .bind(source)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    // -------------------------------------------------------------------------
    // Findings & Deduplication
    // -------------------------------------------------------------------------
    pub async fn save_finding(
        &self,
        program_handle: &str,
        asset: &str,
        url: &str,
        template_id: &str,
        template_name: &str,
        severity: &str,
        matched_at: &str,
        matcher_name: Option<&str>,
        description: Option<&str>,
        fingerprint: &str,
        confidence: &str,
        status: &str,
        raw_result_json: &str,
    ) -> Result<(String, bool)> {
        let existing = sqlx::query(r#"SELECT id FROM findings WHERE fingerprint = ?1"#)
            .bind(fingerprint)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = existing {
            let existing_id: String = row.get("id");
            return Ok((existing_id, false));
        }

        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO findings (
                id, program_handle, asset, url, template_id, template_name,
                severity, matched_at, matcher_name, description, fingerprint,
                confidence, status, raw_result_json, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            "#
        )
        .bind(&id)
        .bind(program_handle)
        .bind(asset)
        .bind(url)
        .bind(template_id)
        .bind(template_name)
        .bind(severity)
        .bind(matched_at)
        .bind(matcher_name)
        .bind(description)
        .bind(fingerprint)
        .bind(confidence)
        .bind(status)
        .bind(raw_result_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok((id, true))
    }

    pub async fn list_findings(&self, status_filter: Option<&str>) -> Result<Vec<FindingRecord>> {
        let findings = match status_filter {
            Some(status) => {
                sqlx::query_as::<_, FindingRecord>(
                    r#"
                    SELECT id, program_handle, asset, url, template_id, template_name,
                           severity, matched_at, matcher_name, description, fingerprint,
                           confidence, status, raw_result_json, created_at, updated_at
                    FROM findings
                    WHERE status = ?1
                    ORDER BY created_at DESC
                    "#
                )
                .bind(status)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, FindingRecord>(
                    r#"
                    SELECT id, program_handle, asset, url, template_id, template_name,
                           severity, matched_at, matcher_name, description, fingerprint,
                           confidence, status, raw_result_json, created_at, updated_at
                    FROM findings
                    ORDER BY created_at DESC
                    "#
                )
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(findings)
    }

    pub async fn get_finding_by_id(&self, id: &str) -> Result<Option<FindingRecord>> {
        let finding = sqlx::query_as::<_, FindingRecord>(
            r#"
            SELECT id, program_handle, asset, url, template_id, template_name,
                   severity, matched_at, matcher_name, description, fingerprint,
                   confidence, status, raw_result_json, created_at, updated_at
            FROM findings
            WHERE id = ?1
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(finding)
    }

    // -------------------------------------------------------------------------
    // Evidence
    // -------------------------------------------------------------------------
    pub async fn save_evidence(
        &self,
        finding_id: &str,
        request_raw: Option<&str>,
        response_raw: Option<&str>,
        curl_command: Option<&str>,
        scanner_output_raw: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO evidence (id, finding_id, request_raw, response_raw, curl_command, scanner_output_raw, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#
        )
        .bind(&id)
        .bind(finding_id)
        .bind(request_raw)
        .bind(response_raw)
        .bind(curl_command)
        .bind(scanner_output_raw)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn get_evidence_by_finding_id(&self, finding_id: &str) -> Result<Option<EvidenceRecord>> {
        let evidence = sqlx::query_as::<_, EvidenceRecord>(
            r#"
            SELECT id, finding_id, request_raw, response_raw, curl_command, scanner_output_raw, created_at
            FROM evidence
            WHERE finding_id = ?1
            "#
        )
        .bind(finding_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(evidence)
    }

    // -------------------------------------------------------------------------
    // Reports
    // -------------------------------------------------------------------------
    pub async fn save_report(
        &self,
        finding_id: &str,
        title: &str,
        file_path: &str,
        markdown_content: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO reports (id, finding_id, title, file_path, markdown_content, human_verified, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)
            "#
        )
        .bind(&id)
        .bind(finding_id)
        .bind(title)
        .bind(file_path)
        .bind(markdown_content)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn list_reports(&self) -> Result<Vec<ReportRecord>> {
        let reports = sqlx::query_as::<_, ReportRecord>(
            r#"
            SELECT id, finding_id, title, file_path, markdown_content, human_verified, created_at, updated_at
            FROM reports
            ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(reports)
    }

    pub async fn mark_report_verified(&self, report_id: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE reports
            SET human_verified = 1, updated_at = ?1
            WHERE id = ?2 OR file_path LIKE ?3
            "#
        )
        .bind(now)
        .bind(report_id)
        .bind(format!("%{}%", report_id))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Notifications
    // -------------------------------------------------------------------------
    pub async fn log_notification(&self, message_type: &str, content: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO notifications (id, message_type, content, sent_at, status)
            VALUES (?1, ?2, ?3, ?4, 'SENT')
            "#
        )
        .bind(&id)
        .bind(message_type)
        .bind(content)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    // -------------------------------------------------------------------------
    // Stats
    // -------------------------------------------------------------------------
    pub async fn get_stats(&self) -> Result<SystemStats> {
        let total_programs = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM programs")
            .fetch_one(&self.pool)
            .await?;

        let total_assets = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM assets")
            .fetch_one(&self.pool)
            .await?;

        let in_scope_assets = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM assets WHERE in_scope = 1")
            .fetch_one(&self.pool)
            .await?;

        let queued_jobs = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recon_jobs WHERE status = 'QUEUED'")
            .fetch_one(&self.pool)
            .await?;

        let running_jobs = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recon_jobs WHERE status = 'RUNNING'")
            .fetch_one(&self.pool)
            .await?;

        let completed_jobs = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recon_jobs WHERE status = 'COMPLETED'")
            .fetch_one(&self.pool)
            .await?;

        let failed_jobs = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recon_jobs WHERE status = 'FAILED'")
            .fetch_one(&self.pool)
            .await?;

        let total_findings = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM findings")
            .fetch_one(&self.pool)
            .await?;

        let potential_findings = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM findings WHERE status IN ('NEW', 'POTENTIAL', 'REQUIRES_REVIEW')"
        )
        .fetch_one(&self.pool)
        .await?;

        let total_reports = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reports")
            .fetch_one(&self.pool)
            .await?;

        let verified_reports = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reports WHERE human_verified = 1")
            .fetch_one(&self.pool)
            .await?;

        Ok(SystemStats {
            total_programs,
            total_assets,
            in_scope_assets,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            total_findings,
            potential_findings,
            total_reports,
            verified_reports,
        })
    }

    // -------------------------------------------------------------------------
    // Tool Runs
    // -------------------------------------------------------------------------
    pub async fn record_tool_start(
        &self,
        job_id: Option<&str>,
        tool: &str,
        target: &str,
        command_args: &str,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO tool_runs (id, job_id, tool, target, command_args, start_time, status, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'RUNNING', ?7)
            "#
        )
        .bind(&id)
        .bind(job_id)
        .bind(tool)
        .bind(target)
        .bind(command_args)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn record_tool_finish(
        &self,
        run_id: &str,
        exit_code: Option<i32>,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now();
        let code_i64 = exit_code.map(|c| c as i64);

        sqlx::query(
            r#"
            UPDATE tool_runs
            SET end_time = ?1, exit_code = ?2, status = ?3, error = ?4
            WHERE id = ?5
            "#
        )
        .bind(now)
        .bind(code_i64)
        .bind(status)
        .bind(error)
        .bind(run_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_tool_runs(&self, limit: i64) -> Result<Vec<ToolRunRecord>> {
        let runs = sqlx::query_as::<_, ToolRunRecord>(
            r#"
            SELECT id, job_id, tool, target, command_args, start_time, end_time, exit_code, status, error, created_at
            FROM tool_runs
            ORDER BY created_at DESC
            LIMIT ?1
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(runs)
    }

    // -------------------------------------------------------------------------
    // Audit Logs
    // -------------------------------------------------------------------------
    pub async fn record_audit_event(
        &self,
        event_type: &str,
        target: &str,
        decision: &str,
        reason: &str,
        tool: Option<&str>,
        metadata_json: Option<&str>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO audit_logs (id, event_type, target, decision, reason, tool, metadata_json, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#
        )
        .bind(&id)
        .bind(event_type)
        .bind(target)
        .bind(decision)
        .bind(reason)
        .bind(tool)
        .bind(metadata_json)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn list_audit_events(&self, limit: i64) -> Result<Vec<AuditLogRecord>> {
        let events = sqlx::query_as::<_, AuditLogRecord>(
            r#"
            SELECT id, event_type, target, decision, reason, tool, metadata_json, timestamp
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT ?1
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(events)
    }

    // -------------------------------------------------------------------------
    // Telegram Phone & Chat Authentication
    // -------------------------------------------------------------------------
    pub async fn ensure_telegram_auth_table(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS telegram_authorized_users (
                chat_id INTEGER PRIMARY KEY,
                phone_number TEXT NOT NULL,
                authorized_at TIMESTAMP NOT NULL
            );
            "#
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_telegram_chat_authorized(&self, chat_id: i64) -> Result<bool> {
        let _ = self.ensure_telegram_auth_table().await;
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM telegram_authorized_users WHERE chat_id = ?1
            "#
        )
        .bind(chat_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0 > 0)
    }

    pub async fn authorize_telegram_chat(&self, chat_id: i64, phone: &str) -> Result<()> {
        let _ = self.ensure_telegram_auth_table().await;
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO telegram_authorized_users (chat_id, phone_number, authorized_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(chat_id) DO UPDATE SET
                phone_number = excluded.phone_number,
                authorized_at = excluded.authorized_at
            "#
        )
        .bind(chat_id)
        .bind(phone)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_authorized_telegram_chats(&self) -> Result<Vec<i64>> {
        let _ = self.ensure_telegram_auth_table().await;
        let rows: Vec<(i64,)> = sqlx::query_as(
            r#"
            SELECT chat_id FROM telegram_authorized_users
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}



