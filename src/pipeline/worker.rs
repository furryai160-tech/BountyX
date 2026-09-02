use crate::config::AppConfig;
use crate::database::models::ReconJobRecord;
use crate::database::repository::Repository;
use crate::errors::{BountyScopeError, Result};
use crate::evidence::{CollectedEvidence, EvidenceCollector};
use crate::mobile::MobileAnalyzer;
use crate::recon::JsMiner;
use crate::reporting::MarkdownReportGenerator;
use crate::sast::SastScanner;
use crate::scanner::{Bypass403Scanner, CorsScanner, GfFilter, OpenRedirectScanner, TakeoverScanner, TechRouter};
use crate::telegram::TelegramNotifier;
use crate::tools::{
    AlterxAdapter, AmassAdapter, ArjunAdapter, CrlfuzzAdapter, DalfoxAdapter, DnsxAdapter,
    FfufAdapter, GauAdapter, GitleaksAdapter, GospiderAdapter, HttpxAdapter, KatanaAdapter,
    KxssAdapter, NaabuAdapter, NucleiAdapter, ParamspiderAdapter, SecurityTool, SmugglerAdapter,
    SqlmapAdapter, SubfinderAdapter, ToolInput,
};
use crate::validation::{Deduplicator, ScopeGuard};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub struct PipelineWorker {
    config: AppConfig,
    repository: Repository,
    notifier: TelegramNotifier,
    // Phase 1 — Core
    subfinder: SubfinderAdapter,
    httpx: HttpxAdapter,
    katana: KatanaAdapter,
    gau: GauAdapter,
    nuclei: NucleiAdapter,
    dalfox: DalfoxAdapter,
    arjun: ArjunAdapter,
    ffuf: FfufAdapter,
    // Phase 3 — Elite
    sqlmap: SqlmapAdapter,
    naabu: NaabuAdapter,
    dnsx: DnsxAdapter,
    crlfuzz: CrlfuzzAdapter,
    // Phase 4 — Expansion
    kxss: KxssAdapter,
    amass: AmassAdapter,
    gitleaks: GitleaksAdapter,
    alterx: AlterxAdapter,
    gospider: GospiderAdapter,
    smuggler: SmugglerAdapter,
    paramspider: ParamspiderAdapter,
    // Native Rust Scanners
    report_generator: MarkdownReportGenerator,
    takeover_scanner: TakeoverScanner,
    js_miner: JsMiner,
    open_redirect_scanner: OpenRedirectScanner,
    cors_scanner: CorsScanner,
}

impl PipelineWorker {
    pub fn new(
        config: AppConfig,
        repository: Repository,
        notifier: TelegramNotifier,
    ) -> Self {
        let subfinder = SubfinderAdapter::new(
            &config.subfinder_path,
            config.process_timeout_seconds,
        )
        .with_repository(repository.clone());

        let httpx = HttpxAdapter::new(
            &config.httpx_path,
            config.process_timeout_seconds,
        )
        .with_custom_header(config.hackerone_verification_header.clone())
        .with_repository(repository.clone());

        let katana = KatanaAdapter::new(
            &config.katana_path,
            config.process_timeout_seconds,
        )
        .with_repository(repository.clone());

        let gau = GauAdapter::new(
            &config.gau_path,
            config.process_timeout_seconds,
        )
        .with_repository(repository.clone());

        let nuclei = NucleiAdapter::new(&config).with_repository(repository.clone());
        let dalfox = DalfoxAdapter::new(&config.dalfox_path, config.process_timeout_seconds)
            .with_repository(repository.clone());
        let arjun = ArjunAdapter::new(&config.arjun_path, config.process_timeout_seconds)
            .with_repository(repository.clone());
        let ffuf = FfufAdapter::new(&config.ffuf_path, config.process_timeout_seconds)
            .with_repository(repository.clone());

        let report_generator = MarkdownReportGenerator::new(&config.reports_dir);
        let takeover_scanner = TakeoverScanner::new();
        let js_miner = JsMiner::new();
        let open_redirect_scanner = OpenRedirectScanner::new();
        let cors_scanner = CorsScanner::new();

        let sqlmap = SqlmapAdapter::new(&config.sqlmap_path, config.process_timeout_seconds)
            .with_repository(repository.clone());
        let naabu = NaabuAdapter::new(&config.naabu_path, 120)
            .with_repository(repository.clone());
        let dnsx = DnsxAdapter::new(&config.dnsx_path, 180)
            .with_repository(repository.clone());
        let crlfuzz = CrlfuzzAdapter::new(&config.crlfuzz_path, 120)
            .with_repository(repository.clone());

        // Phase 4: Elite Expansion tools
        let kxss = KxssAdapter::new(&config.kxss_path, 120)
            .with_repository(repository.clone());
        let amass = AmassAdapter::new(&config.amass_path, config.process_timeout_seconds)
            .with_repository(repository.clone());
        let gitleaks = GitleaksAdapter::new(&config.gitleaks_path, 120)
            .with_repository(repository.clone());
        let alterx = AlterxAdapter::new(&config.alterx_path, 60)
            .with_repository(repository.clone());
        let gospider = GospiderAdapter::new(&config.gospider_path, config.process_timeout_seconds)
            .with_repository(repository.clone());
        let smuggler = SmugglerAdapter::new(&config.smuggler_path, 120)
            .with_repository(repository.clone());
        let paramspider = ParamspiderAdapter::new(&config.paramspider_path, 120)
            .with_repository(repository.clone());

        Self {
            config,
            repository,
            notifier,
            subfinder,
            httpx,
            katana,
            gau,
            nuclei,
            dalfox,
            arjun,
            ffuf,
            sqlmap,
            naabu,
            dnsx,
            crlfuzz,
            kxss,
            amass,
            gitleaks,
            alterx,
            gospider,
            smuggler,
            paramspider,
            report_generator,
            takeover_scanner,
            js_miner,
            open_redirect_scanner,
            cors_scanner,
        }
    }



    /// Execute a tool with stage-level retry and exponential backoff
    async fn run_stage_with_retry<T: SecurityTool>(
        &self,
        tool: &T,
        input: ToolInput,
    ) -> Result<crate::tools::ToolOutput> {
        let max_retries = self.config.retry_count.max(1);
        let mut attempt = 0;
        let mut last_err = None;

        while attempt < max_retries {
            attempt += 1;
            match tool.run(input.clone()).await {
                Ok(output) => return Ok(output),
                Err(err) => {
                    warn!(
                        "Tool '{}' attempt {}/{} failed for target '{}': {}",
                        tool.name(),
                        attempt,
                        max_retries,
                        input.target,
                        err
                    );
                    last_err = Some(err);
                    if attempt < max_retries {
                        let backoff_secs = 2u64.pow(attempt as u32 - 1).min(30);
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            BountyScopeError::Internal(format!("Stage '{}' failed after retries", tool.name()))
        }))
    }

    pub async fn process_job(
        &self,
        job: ReconJobRecord,
        scope_guard: Arc<ScopeGuard>,
    ) -> Result<()> {
        let target = job.target.clone();
        let program_handle = job.program_handle.clone();
        let job_id = job.id.clone();

        info!(
            "Worker started processing job '{}' on target: '{}' (Program: '{}')",
            job_id, target, program_handle
        );

        // ---------------------------------------------------------------------
        // BRANCH A: MOBILE APPLICATION STATIC ANALYSIS (Android / iOS)
        // ---------------------------------------------------------------------
        if target.starts_with("app:") {
            let app_ident = target.trim_start_matches("app:");
            self.repository
                .update_job_status(&job_id, "MOBILE_ANALYSIS", "RUNNING", None)
                .await?;

            info!("📱 Analyzing mobile application metadata for: {}", app_ident);
            let analysis_result = MobileAnalyzer::analyze_app_metadata(
                app_ident,
                "Android/iOS",
                app_ident,
                &scope_guard,
            )?;

            for secret in analysis_result.leaked_secrets {
                let fingerprint = Deduplicator::compute_finding_fingerprint(
                    &program_handle,
                    app_ident,
                    "mobile-secret-leak",
                    Some(&secret.secret_type),
                    &secret.matched_value,
                );

                let (finding_id, is_new) = self
                    .repository
                    .save_finding(
                        &program_handle,
                        app_ident,
                        app_ident,
                        "mobile-secret-leak",
                        &format!("Mobile Leak: {}", secret.secret_type),
                        &secret.confidence,
                        &secret.matched_value,
                        Some(&secret.secret_type),
                        Some(&secret.description),
                        &fingerprint,
                        "POTENTIAL",
                        "REQUIRES_REVIEW",
                        &serde_json::to_string(&secret).unwrap_or_default(),
                    )
                    .await?;

                if is_new {
                    info!("🚨 New Mobile Secret Leak detected in '{}'", app_ident);
                    let evidence = CollectedEvidence {
                        target: app_ident.to_string(),
                        matched_url: secret.matched_value.clone(),
                        template_id: "mobile-secret-leak".to_string(),
                        template_name: format!("Mobile Hardcoded Secret: {}", secret.secret_type),
                        severity: secret.confidence.clone(),
                        curl_command: None,
                        request: None,
                        response: None,
                        extracted_data: vec![secret.matched_value.clone()],
                        raw_scanner_output: format!(
                            "Secret Type: {}\nValue: {}\nDescription: {}",
                            secret.secret_type, secret.matched_value, secret.description
                        ),
                    };

                    if let Ok((report_path, report_content)) = self
                        .report_generator
                        .generate_report(&evidence, &program_handle)
                        .await
                    {
                        let title = format!("📱 Mobile Leak: {}", secret.secret_type);
                        let _ = self
                            .repository
                            .save_report(&finding_id, &title, &report_path, &report_content)
                            .await;

                        self.notifier
                            .notify_potential_finding(
                                &secret.confidence,
                                &program_handle,
                                app_ident,
                                &format!("Mobile Leak: {}", secret.secret_type),
                                &report_path,
                            )
                            .await;
                    }
                }
            }

            self.repository
                .update_job_status(&job_id, "COMPLETED", "COMPLETED", None)
                .await?;
            return Ok(());
        }

        // ---------------------------------------------------------------------
        // BRANCH B: SOURCE CODE & SAST ANALYSIS (Git / GitHub)
        // ---------------------------------------------------------------------
        if target.starts_with("git:") {
            let repo_url = target.trim_start_matches("git:");
            self.repository
                .update_job_status(&job_id, "SAST_SCAN", "RUNNING", None)
                .await?;

            info!("📦 Running SAST analysis for source code repository: {}", repo_url);
            let sast_findings = SastScanner::scan_content(repo_url, repo_url)?;

            for finding in sast_findings {
                let fingerprint = Deduplicator::compute_finding_fingerprint(
                    &program_handle,
                    repo_url,
                    &finding.rule_id,
                    None,
                    &finding.matched_secret,
                );

                let (finding_id, is_new) = self
                    .repository
                    .save_finding(
                        &program_handle,
                        repo_url,
                        repo_url,
                        &finding.rule_id,
                        &finding.title,
                        &finding.severity,
                        &finding.matched_secret,
                        None,
                        Some(&finding.remediation),
                        &fingerprint,
                        "POTENTIAL",
                        "REQUIRES_REVIEW",
                        &serde_json::to_string(&finding).unwrap_or_default(),
                    )
                    .await?;

                if is_new {
                    let evidence = CollectedEvidence {
                        target: repo_url.to_string(),
                        matched_url: repo_url.to_string(),
                        template_id: finding.rule_id.clone(),
                        template_name: finding.title.clone(),
                        severity: finding.severity.clone(),
                        curl_command: None,
                        request: None,
                        response: None,
                        extracted_data: vec![finding.matched_secret.clone()],
                        raw_scanner_output: format!(
                            "Rule: {}\nSecret: {}\nRemediation: {}",
                            finding.rule_id, finding.matched_secret, finding.remediation
                        ),
                    };

                    if let Ok((report_path, report_content)) = self
                        .report_generator
                        .generate_report(&evidence, &program_handle)
                        .await
                    {
                        let title = format!("📦 SAST Leak: {}", finding.title);
                        let _ = self
                            .repository
                            .save_report(&finding_id, &title, &report_path, &report_content)
                            .await;

                        self.notifier
                            .notify_potential_finding(
                                &finding.severity,
                                &program_handle,
                                repo_url,
                                &finding.title,
                                &report_path,
                            )
                            .await;
                    }
                }
            }

            self.repository
                .update_job_status(&job_id, "COMPLETED", "COMPLETED", None)
                .await?;
            return Ok(());
        }

        // ---------------------------------------------------------------------
        // BRANCH C: WEB & NETWORK ASSETS (Domains, URLs, CIDR, IPs)
        // ---------------------------------------------------------------------
        info!("🚀 [PIPELINE START] Target: '{}' | Program: '{}' | Slot Active", target, program_handle);

        // STEP 0: MANDATORY SCOPE GUARD PRE-CHECK WITH AUDIT
        if let Err(e) = scope_guard
            .validate_target_with_audit(&target, Some("pipeline_precheck"), Some(&self.repository))
            .await
        {
            warn!(
                "⛔ SECURITY BLOCK: Target '{}' failed Scope Guard gate. Aborting job.",
                target
            );
            self.repository
                .update_job_status(
                    &job_id,
                    "SCOPE_GUARD",
                    "FAILED",
                    Some("Target rejected by Scope Guard"),
                )
                .await?;
            return Err(e);
        }

        // STEP 1: SUBFINDER & AMASS (Subdomain Discovery)
        info!("  → [Stage 1/11] 🔎 Subdomain Discovery (subfinder)... Target: '{}'", target);
        self.repository
            .update_job_status(&job_id, "SUBFINDER", "RUNNING", None)
            .await?;


        let subfinder_input = ToolInput::single(&target).with_job_id(Some(&job_id));
        let discovered_subs = match self.run_stage_with_retry(&self.subfinder, subfinder_input).await {
            Ok(output) => {
                let parsed = self.subfinder.parse_subdomains(&output, &target);
                // Multi-stage Scope Guard: Filter discovered subdomains
                let mut valid_subs = Vec::new();
                for s in parsed {
                    if scope_guard.is_in_scope(&s.subdomain) {
                        valid_subs.push(s);
                    }
                }
                valid_subs
            }
            Err(e) => {
                warn!("Subfinder stage failed for target '{}': {}", target, e);
                self.notifier.notify_tool_error("subfinder", &target, &e.to_string()).await;
                Vec::new()
            }
        };

        for sub in &discovered_subs {
            let _ = self
                .repository
                .save_subdomain(
                    &program_handle,
                    &sub.parent_asset,
                    &sub.subdomain,
                    &sub.source,
                )
                .await;
        }

        let mut targets_to_probe = vec![target.clone()];
        for sub in discovered_subs {
            targets_to_probe.push(sub.subdomain);
        }
        let targets_to_probe = Deduplicator::deduplicate_strings(&targets_to_probe);
        let targets_to_probe = scope_guard.filter_in_scope(&targets_to_probe);

        // ---------------------------------------------------------------------
        // STEP 1.5: SUBDOMAIN TAKEOVER RADAR
        // ---------------------------------------------------------------------
        let takeovers = self.takeover_scanner.scan_subdomains(&targets_to_probe).await;
        for t_finding in takeovers {
            let fingerprint = Deduplicator::compute_finding_fingerprint(
                &program_handle,
                &t_finding.target,
                "subdomain-takeover",
                Some(&t_finding.service),
                &t_finding.verified_url,
            );

            let (finding_id, is_new) = self
                .repository
                .save_finding(
                    &program_handle,
                    &t_finding.target,
                    &t_finding.verified_url,
                    "subdomain-takeover",
                    &format!("Subdomain Takeover: {}", t_finding.service),
                    &t_finding.severity,
                    &t_finding.verified_url,
                    Some(&t_finding.service),
                    Some(&t_finding.description),
                    &fingerprint,
                    "POTENTIAL",
                    "REQUIRES_REVIEW",
                    &serde_json::to_string(&t_finding).unwrap_or_default(),
                )
                .await?;

            if is_new {
                info!("🚨 NEW SUBDOMAIN TAKEOVER FOUND: '{}' -> {}", t_finding.target, t_finding.service);
                let evidence = CollectedEvidence {
                    target: t_finding.target.clone(),
                    matched_url: t_finding.verified_url.clone(),
                    template_id: "subdomain-takeover".to_string(),
                    template_name: format!("Subdomain Takeover: {}", t_finding.service),
                    severity: t_finding.severity.clone(),
                    curl_command: Some(format!("curl -ik -s '{}'", t_finding.verified_url)),
                    request: None,
                    response: Some(format!("Matched dangling fingerprint: {}", t_finding.matched_fingerprint)),
                    extracted_data: vec![t_finding.service.clone(), t_finding.matched_fingerprint.clone()],
                    raw_scanner_output: t_finding.description.clone(),
                };

                if let Ok((report_path, report_content)) = self
                    .report_generator
                    .generate_report(&evidence, &program_handle)
                    .await
                {
                    let title = format!("🚨 Subdomain Takeover: {}", t_finding.service);
                    let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                    self.notifier.notify_potential_finding(&t_finding.severity, &program_handle, &t_finding.verified_url, &title, &report_path).await;
                }
            }
        }

        // STEP 2: HTTPX (Live Web Probing)
        self.repository
            .update_job_status(&job_id, "HTTPX", "RUNNING", None)
            .await?;

        // STEP 1.6: NAABU — Port Scanner
        // Discovers unexpected open ports that reveal hidden services.
        // Redis (6379), MongoDB (27017), Elasticsearch (9200) without auth = P1 instant.
        // Runs against each unique host (not full URL) in parallel.
        self.repository
            .update_job_status(&job_id, "PORT_SCAN", "RUNNING", None)
            .await?;

        for probe_host in targets_to_probe.iter().take(20) {
            let naabu_input = ToolInput::single(probe_host).with_job_id(Some(&job_id));
            match self.run_stage_with_retry(&self.naabu, naabu_input).await {
                Ok(naabu_output) => {
                    let port_findings = self.naabu.parse_findings(&naabu_output);
                    for pf in port_findings {
                        // Only alert on high-value / unexpected ports
                        let is_high_value = matches!(pf.port,
                            2375 | 2376 | 3000 | 4848 | 5601 | 6379 |
                            8161 | 8888 | 9000 | 9200 | 9300 | 27017);

                        let severity = if is_high_value { "HIGH" } else { "INFO" };
                        let fingerprint = Deduplicator::compute_finding_fingerprint(
                            &program_handle,
                            &pf.host,
                            "open-port",
                            Some(&pf.service),
                            &format!("{}:{}", pf.host, pf.port),
                        );

                        let (finding_id, is_new) = self.repository
                            .save_finding(
                                &program_handle,
                                &pf.host,
                                &format!("{}:{}", pf.host, pf.port),
                                "open-port",
                                &format!("Open Port {}/{} — {}", pf.port, pf.protocol, pf.service),
                                severity,
                                &format!("{}:{}", pf.host, pf.port),
                                Some(&pf.service),
                                Some(&format!("Open port {}/{} on host '{}'. Service: {}. \
                                    Verify that authentication is required and the service \
                                    is intentionally internet-exposed.",
                                    pf.port, pf.protocol, pf.host, pf.service)),
                                &fingerprint,
                                "POTENTIAL",
                                "REQUIRES_REVIEW",
                                &serde_json::to_string(&pf).unwrap_or_default(),
                            ).await?;

                        if is_new && is_high_value {
                            info!("🔌 HIGH-VALUE PORT [{}/{}] on '{}' → {}",
                                pf.port, pf.protocol, pf.host, pf.service);
                            let evidence = CollectedEvidence {
                                target: pf.host.clone(),
                                matched_url: format!("{}:{}", pf.host, pf.port),
                                template_id: "open-port".to_string(),
                                template_name: format!("Open Port: {} ({})", pf.port, pf.service),
                                severity: severity.to_string(),
                                curl_command: Some(format!("nc -zvw3 {} {}", pf.host, pf.port)),
                                request: None,
                                response: None,
                                extracted_data: vec![format!("{}:{}", pf.host, pf.port)],
                                raw_scanner_output: format!("Host: {}\nPort: {}\nProtocol: {}\nService: {}",
                                    pf.host, pf.port, pf.protocol, pf.service),
                            };
                            if let Ok((report_path, report_content)) = self.report_generator
                                .generate_report(&evidence, &program_handle).await
                            {
                                let title = format!("🔌 Open Port {}: {} on {}", pf.port, pf.service, pf.host);
                                let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                                self.notifier.notify_potential_finding(severity, &program_handle,
                                    &format!("{}:{}", pf.host, pf.port), &title, &report_path).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("naabu port scan failed for '{}': {}", probe_host, e);
                }
            }
        }



        let httpx_input = ToolInput::multiple(&targets_to_probe).with_job_id(Some(&job_id));
        let live_hosts = match self.run_stage_with_retry(&self.httpx, httpx_input).await {
            Ok(output) => {
                let probed = self.httpx.parse_results(&output);
                // Multi-stage Scope Guard: Filter live host targets
                let mut valid_hosts = Vec::new();
                for h in probed {
                    if scope_guard.is_in_scope(&h.url) {
                        valid_hosts.push(h);
                    }
                }
                valid_hosts
            }
            Err(e) => {
                warn!("HTTPX stage failed for target '{}': {}", target, e);
                self.notifier.notify_tool_error("httpx", &target, &e.to_string()).await;
                Vec::new()
            }
        };

        let mut live_urls = Vec::new();
        for host in &live_hosts {
            live_urls.push(host.url.clone());
            let techs_json = serde_json::to_string(&host.technologies).ok();

            let _ = self
                .repository
                .save_http_host(
                    &program_handle,
                    &host.url,
                    &host.host,
                    host.port as i64,
                    &host.scheme,
                    host.status_code.map(|s| s as i64),
                    host.title.as_deref(),
                    host.content_length.map(|l| l as i64),
                    host.response_time_ms.map(|t| t as i64),
                    techs_json.as_deref(),
                )
                .await;
        }

        if live_urls.is_empty() && scope_guard.is_in_scope(&target) {
            live_urls.push(format!("https://{}", ScopeGuard::normalize_target(&target)));
        }

        // STEP 3: KATANA & GAU (Endpoint & URL Discovery)
        self.repository
            .update_job_status(&job_id, "ENDPOINTS", "RUNNING", None)
            .await?;

        let mut endpoints = Vec::new();

        if !live_urls.is_empty() {
            let katana_input = ToolInput::multiple(&live_urls).with_job_id(Some(&job_id));
            if let Ok(output) = self.run_stage_with_retry(&self.katana, katana_input).await {
                let katana_urls = self.katana.parse_urls(&output);
                let in_scope_katana = scope_guard.filter_in_scope(&katana_urls);
                endpoints.extend(in_scope_katana);
            }
        }

        let gau_input = ToolInput::single(&target).with_job_id(Some(&job_id));
        if let Ok(output) = self.run_stage_with_retry(&self.gau, gau_input).await {
            let gau_urls = self.gau.parse_urls(&output);
            let in_scope_gau = scope_guard.filter_in_scope(&gau_urls);
            endpoints.extend(in_scope_gau);
        }

        let all_endpoints = Deduplicator::deduplicate_strings(&endpoints);
        for ep in &all_endpoints {
            let _ = self
                .repository
                .save_endpoint(
                    &program_handle,
                    &target,
                    ep,
                    "GET",
                    None,
                    "crawler",
                )
                .await;
        }

        // ---------------------------------------------------------------------
        // STEP 3.5: JS INTELLIGENCE & SECRETS/ENDPOINTS MINING
        // ---------------------------------------------------------------------
        let js_urls = JsMiner::filter_js_urls(&all_endpoints);
        let in_scope_js = scope_guard.filter_in_scope(&js_urls);
        if !in_scope_js.is_empty() {
            info!("Mined {} JS files for '{}'. Starting static secret and endpoint analysis...", in_scope_js.len(), target);
            let js_results = self.js_miner.mine_all(&in_scope_js, 15).await;
            for res in js_results {
                // Feed discovered API endpoints back into endpoints table
                for new_ep in res.discovered_endpoints {
                    let full_ep_url = if new_ep.starts_with("http") {
                        new_ep
                    } else {
                        format!("https://{}{}", ScopeGuard::normalize_target(&target), if new_ep.starts_with('/') { new_ep } else { format!("/{}", new_ep) })
                    };

                    if scope_guard.is_in_scope(&full_ep_url) {
                        let _ = self.repository.save_endpoint(&program_handle, &target, &full_ep_url, "GET", None, "js_miner").await;
                        endpoints.push(full_ep_url);
                    }
                }

                // Process leaked secrets found in JavaScript
                for secret in res.leaked_secrets {
                    let fingerprint = Deduplicator::compute_finding_fingerprint(
                        &program_handle,
                        &target,
                        "js-secret-leak",
                        Some(&secret.secret_type),
                        &secret.matched_value,
                    );

                    let (finding_id, is_new) = self
                        .repository
                        .save_finding(
                            &program_handle,
                            &target,
                            &res.js_url,
                            "js-secret-leak",
                            &format!("JS Leak: {}", secret.secret_type),
                            &secret.confidence,
                            &secret.matched_value,
                            Some(&secret.secret_type),
                            Some(&secret.description),
                            &fingerprint,
                            "POTENTIAL",
                            "REQUIRES_REVIEW",
                            &serde_json::to_string(&secret).unwrap_or_default(),
                        )
                        .await?;

                    if is_new {
                        info!("🚨 NEW JAVASCRIPT SECRET LEAK: '{}' in '{}'", secret.secret_type, res.js_url);
                        let evidence = CollectedEvidence {
                            target: target.clone(),
                            matched_url: res.js_url.clone(),
                            template_id: "js-secret-leak".to_string(),
                            template_name: format!("JS Hardcoded Secret: {}", secret.secret_type),
                            severity: secret.confidence.clone(),
                            curl_command: Some(format!("curl -ik -s '{}'", res.js_url)),
                            request: None,
                            response: None,
                            extracted_data: vec![secret.matched_value.clone()],
                            raw_scanner_output: format!("Type: {}\nValue: {}\nSource JS: {}", secret.secret_type, secret.matched_value, res.js_url),
                        };

                        if let Ok((report_path, report_content)) = self.report_generator.generate_report(&evidence, &program_handle).await {
                            let title = format!("🔑 JS Secret: {}", secret.secret_type);
                            let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                            self.notifier.notify_potential_finding(&secret.confidence, &program_handle, &res.js_url, &title, &report_path).await;
                        }
                    }
                }
            }
        }

        let mut scan_targets = live_urls.clone();
        scan_targets.extend(endpoints.clone().into_iter().take(50));
        let scan_targets = Deduplicator::deduplicate_strings(&scan_targets);
        let scan_targets = scope_guard.filter_in_scope(&scan_targets);

        // ---------------------------------------------------------------------
        // STEP 4.1: OPEN REDIRECT SCANNER (Pure Rust, no external binary)
        // Tests all discovered endpoints for open redirect vulnerabilities.
        // Chains well with OAuth/SSRF for P1 bounties.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "OPEN_REDIRECT", "RUNNING", None)
            .await?;

        let redirect_findings = self.open_redirect_scanner.scan_urls(&scan_targets, 20).await;
        for rf in redirect_findings {
            let fingerprint = Deduplicator::compute_finding_fingerprint(
                &program_handle,
                &target,
                "open-redirect",
                Some(&rf.vulnerable_param),
                &rf.original_url,
            );

            let (finding_id, is_new) = self
                .repository
                .save_finding(
                    &program_handle,
                    &target,
                    &rf.original_url,
                    "open-redirect",
                    &format!("Open Redirect via param '{}'", rf.vulnerable_param),
                    &rf.severity,
                    &rf.redirected_to,
                    Some(&rf.vulnerable_param),
                    Some(&rf.description),
                    &fingerprint,
                    "POTENTIAL",
                    "REQUIRES_REVIEW",
                    &serde_json::to_string(&rf).unwrap_or_default(),
                )
                .await?;

            if is_new {
                info!("🔀 Open Redirect: '{}' param='{}' -> '{}'", rf.original_url, rf.vulnerable_param, rf.redirected_to);
                let evidence = CollectedEvidence {
                    target: target.clone(),
                    matched_url: rf.original_url.clone(),
                    template_id: "open-redirect".to_string(),
                    template_name: format!("Open Redirect: {}", rf.vulnerable_param),
                    severity: rf.severity.clone(),
                    curl_command: Some(format!("curl -ik -s '{}' --max-redirs 0", rf.original_url)),
                    request: None,
                    response: Some(format!("Location: {}", rf.redirected_to)),
                    extracted_data: vec![rf.redirected_to.clone()],
                    raw_scanner_output: rf.description.clone(),
                };

                if let Ok((report_path, report_content)) = self.report_generator.generate_report(&evidence, &program_handle).await {
                    let title = format!("🔀 Open Redirect: {}", rf.vulnerable_param);
                    let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                    self.notifier.notify_potential_finding(&rf.severity, &program_handle, &rf.original_url, &title, &report_path).await;
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.2: ARJUN — Hidden Parameter Discovery
        // Discovers hidden query parameters that are invisible to normal crawlers.
        // These parameters are high-value attack surface for SSRF, SQLi, XSS.
        // We run on a sample of live hosts only (max 10) to avoid rate limiting.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "PARAM_DISCOVERY", "RUNNING", None)
            .await?;

        let arjun_targets: Vec<String> = live_urls.iter().take(10).cloned().collect();
        if !arjun_targets.is_empty() {
            let arjun_input = ToolInput::multiple(&arjun_targets).with_job_id(Some(&job_id));
            if let Ok(arjun_output) = self.run_stage_with_retry(&self.arjun, arjun_input).await {
                let arjun_results = self.arjun.parse_results(&arjun_output);
                let mut discovered_param_urls: Vec<String> = Vec::new();

                for result in &arjun_results {
                    info!("🔍 Arjun found {} hidden params at '{}': [{}]",
                        result.params.len(), result.url, result.params.join(", "));

                    // Build test URLs with discovered params appended — feed into next scan stages
                    for param in &result.params {
                        let test_url = if result.url.contains('?') {
                            format!("{}&{}=FUZZ", result.url, param)
                        } else {
                            format!("{}?{}=FUZZ", result.url, param)
                        };

                        if scope_guard.is_in_scope(&result.url) {
                            let _ = self.repository.save_endpoint(
                                &program_handle,
                                &target,
                                &test_url,
                                &result.method,
                                None,
                                "arjun",
                            ).await;
                            discovered_param_urls.push(result.url.clone());
                        }
                    }
                }

                // Feed newly discovered parameterized URLs into Open Redirect scanner
                if !discovered_param_urls.is_empty() {
                    let extra_redirects = self.open_redirect_scanner.scan_urls(&discovered_param_urls, 10).await;
                    info!("Arjun-seeded Open Redirect scan found {} additional findings.", extra_redirects.len());
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.3: DALFOX — XSS Hunter
        // Runs XSS injection via dalfox in pipe mode across all discovered
        // parameterized endpoints. Confirms reflected and DOM-based XSS.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "XSS_SCAN", "RUNNING", None)
            .await?;

        // Only test URLs with parameters (contains '?') — XSS needs parameters
        let xss_targets: Vec<String> = scan_targets
            .iter()
            .filter(|u| u.contains('?') && u.contains('='))
            .cloned()
            .take(100) // cap at 100 to avoid timeout
            .collect();

        if !xss_targets.is_empty() {
            info!("💉 Running dalfox XSS scan on {} parameterized endpoints...", xss_targets.len());
            let dalfox_input = ToolInput::multiple(&xss_targets).with_job_id(Some(&job_id));

            match self.run_stage_with_retry(&self.dalfox, dalfox_input).await {
                Ok(dalfox_output) => {
                    let xss_findings = self.dalfox.parse_findings(&dalfox_output);
                    info!("dalfox scan completed. Found {} XSS candidates.", xss_findings.len());

                    for xf in xss_findings {
                        if !scope_guard.is_in_scope(&xf.url) {
                            continue;
                        }

                        let fingerprint = Deduplicator::compute_finding_fingerprint(
                            &program_handle,
                            &target,
                            "xss",
                            xf.param.as_deref(),
                            &xf.url,
                        );

                        let (finding_id, is_new) = self
                            .repository
                            .save_finding(
                                &program_handle,
                                &target,
                                &xf.url,
                                "xss",
                                &format!("Cross-Site Scripting (XSS) — {} via param '{}'",
                                    if xf.vuln_type == "V" { "Verified" } else { "Reflected" },
                                    xf.param.as_deref().unwrap_or("unknown")),
                                &xf.severity,
                                &xf.url,
                                xf.param.as_deref(),
                                Some(&xf.raw),
                                &fingerprint,
                                "POTENTIAL",
                                "REQUIRES_REVIEW",
                                &serde_json::to_string(&xf).unwrap_or_default(),
                            )
                            .await?;

                        if is_new {
                            info!("🚨 XSS FOUND [{}] at '{}' param='{:?}'", xf.vuln_type, xf.url, xf.param);
                            let evidence = CollectedEvidence {
                                target: target.clone(),
                                matched_url: xf.url.clone(),
                                template_id: "xss".to_string(),
                                template_name: format!("XSS [{}] — {}", xf.vuln_type,
                                    xf.param.as_deref().unwrap_or("unknown")),
                                severity: xf.severity.clone(),
                                curl_command: Some(format!("curl -ik -s '{}'", xf.url)),
                                request: None,
                                response: None,
                                extracted_data: vec![xf.payload.clone()],
                                raw_scanner_output: xf.raw.clone(),
                            };

                            if let Ok((report_path, report_content)) = self.report_generator.generate_report(&evidence, &program_handle).await {
                                let title = format!("💉 XSS [{}]: {}", xf.vuln_type,
                                    xf.param.as_deref().unwrap_or("unknown param"));
                                let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                                self.notifier.notify_potential_finding(&xf.severity, &program_handle, &xf.url, &title, &report_path).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("dalfox XSS scan failed for '{}': {} (dalfox may not be installed)", target, e);
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.35: GF FILTER + SQLMAP — Intelligent SQL Injection Detection
        // GF classifies all collected URLs by vulnerability pattern, then
        // sqlmap runs ONLY on URLs that match SQL injection patterns.
        // This is 10x faster than blind sqlmap on all URLs.
        // Detection-only mode: NEVER dumps data, NEVER executes OS commands.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "SQLI_SCAN", "RUNNING", None)
            .await?;

        // Use gf to intelligently filter SQLi-candidate URLs
        let all_urls_for_gf: Vec<String> = scan_targets
            .iter()
            .filter(|u| u.contains('?') && u.contains('='))
            .cloned()
            .collect();

        let sqli_targets = GfFilter::sqli_targets(&all_urls_for_gf);
        info!("🎯 gf filter: {} SQLi-candidate URLs from {} total parameterized URLs.",
            sqli_targets.len(), all_urls_for_gf.len());

        // Run sqlmap on each candidate (max 15 to stay within time budget)
        for sqli_url in sqli_targets.into_iter().take(15) {
            if !scope_guard.is_in_scope(&sqli_url) { continue; }
            let sqlmap_input = ToolInput::single(&sqli_url).with_job_id(Some(&job_id));
            match self.run_stage_with_retry(&self.sqlmap, sqlmap_input).await {
                Ok(sqlmap_output) => {
                    let sql_findings = self.sqlmap.parse_findings(&sqlmap_output, &sqli_url);
                    for sf in sql_findings {
                        let fingerprint = Deduplicator::compute_finding_fingerprint(
                            &program_handle,
                            &target,
                            "sql-injection",
                            Some(&sf.parameter),
                            &sf.url,
                        );

                        let (finding_id, is_new) = self.repository
                            .save_finding(
                                &program_handle,
                                &target,
                                &sf.url,
                                "sql-injection",
                                &format!("SQL Injection ({}) — param '{}' on {}",
                                    sf.injection_type, sf.parameter, sf.dbms),
                                &sf.severity,
                                &sf.payload,
                                Some(&sf.parameter),
                                Some(&format!("SQL Injection confirmed via '{}' technique. \
                                    DBMS: {}. Vulnerable param: '{}'. Payload: '{}'.",
                                    sf.injection_type, sf.dbms, sf.parameter, sf.payload)),
                                &fingerprint,
                                "CONFIRMED",
                                "REPORT_READY",
                                &serde_json::to_string(&sf).unwrap_or_default(),
                            ).await?;

                        if is_new {
                            info!("🚨💉 SQL INJECTION CONFIRMED [{}] at '{}' param='{}' dbms='{}'",
                                sf.severity, sf.url, sf.parameter, sf.dbms);
                            let evidence = CollectedEvidence {
                                target: target.clone(),
                                matched_url: sf.url.clone(),
                                template_id: "sql-injection".to_string(),
                                template_name: format!("SQLi [{}] — param '{}'",
                                    sf.injection_type, sf.parameter),
                                severity: sf.severity.clone(),
                                curl_command: Some(format!("sqlmap -u '{}' -p '{}' --batch --level=2 --risk=1",
                                    sf.url, sf.parameter)),
                                request: None,
                                response: None,
                                extracted_data: vec![
                                    format!("param: {}", sf.parameter),
                                    format!("type: {}", sf.injection_type),
                                    format!("dbms: {}", sf.dbms),
                                    format!("payload: {}", sf.payload),
                                ],
                                raw_scanner_output: format!("URL: {}\nParam: {}\nType: {}\nDBMS: {}\nPayload: {}",
                                    sf.url, sf.parameter, sf.injection_type, sf.dbms, sf.payload),
                            };
                            if let Ok((report_path, report_content)) = self.report_generator
                                .generate_report(&evidence, &program_handle).await
                            {
                                let title = format!("🚨 SQLi [{}]: param '{}'", sf.injection_type, sf.parameter);
                                let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                                self.notifier.notify_potential_finding(
                                    &sf.severity, &program_handle, &sf.url, &title, &report_path
                                ).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("sqlmap scan failed for '{}': {}", sqli_url, e);
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.4: CORS SCANNER (Pure Rust — no external binary)
        // Tests all live hosts for CORS misconfigurations.
        // CRITICAL severity = reflected origin + credentials = direct data theft.
        // Chains with OAuth flows for very impactful P1/P2 findings.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "CORS_SCAN", "RUNNING", None)
            .await?;

        let cors_findings = self.cors_scanner.scan_urls(&live_urls, 15).await;
        for cf in cors_findings {
            if !scope_guard.is_in_scope(&cf.url) {
                continue;
            }

            let fingerprint = Deduplicator::compute_finding_fingerprint(
                &program_handle,
                &target,
                "cors-misconfiguration",
                Some(&cf.tested_origin),
                &cf.url,
            );

            let (finding_id, is_new) = self
                .repository
                .save_finding(
                    &program_handle,
                    &target,
                    &cf.url,
                    "cors-misconfiguration",
                    &format!("CORS Misconfiguration — {} Origin Reflected (credentials={})",
                        cf.tested_origin, cf.credentials_allowed),
                    &cf.severity,
                    &cf.reflected_origin,
                    Some(&cf.tested_origin),
                    Some(&cf.description),
                    &fingerprint,
                    "POTENTIAL",
                    "REQUIRES_REVIEW",
                    &serde_json::to_string(&cf).unwrap_or_default(),
                )
                .await?;

            if is_new {
                info!("🌐 CORS [{}] at '{}' — Origin: '{}' → ACAO: '{}' (creds={})",
                    cf.severity, cf.url, cf.tested_origin, cf.reflected_origin, cf.credentials_allowed);

                let evidence = CollectedEvidence {
                    target: target.clone(),
                    matched_url: cf.url.clone(),
                    template_id: "cors-misconfiguration".to_string(),
                    template_name: format!("CORS {} — Reflected Origin", cf.severity),
                    severity: cf.severity.clone(),
                    curl_command: Some(format!(
                        "curl -ik -s '{}' -H 'Origin: {}'",
                        cf.url, cf.tested_origin
                    )),
                    request: Some(format!("Origin: {}", cf.tested_origin)),
                    response: Some(format!(
                        "Access-Control-Allow-Origin: {}\nAccess-Control-Allow-Credentials: {}",
                        cf.reflected_origin, cf.credentials_allowed
                    )),
                    extracted_data: vec![
                        cf.reflected_origin.clone(),
                        format!("credentials={}", cf.credentials_allowed),
                    ],
                    raw_scanner_output: cf.description.clone(),
                };

                if let Ok((report_path, report_content)) = self.report_generator.generate_report(&evidence, &program_handle).await {
                    let title = format!("🌐 CORS [{}]: {}", cf.severity,
                        if cf.credentials_allowed { "Reflected + Credentials" } else { "Reflected Origin" });
                    let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                    self.notifier.notify_potential_finding(&cf.severity, &program_handle, &cf.url, &title, &report_path).await;
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.45: CRLFUZZ — CRLF Injection Scanner
        // HTTP Response Splitting, Header Injection, Cookie Injection.
        // Runs on live URLs (max 30) for efficient coverage.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "CRLF_SCAN", "RUNNING", None)
            .await?;

        let crlf_targets: Vec<String> = live_urls.iter().take(30).cloned().collect();
        for crlf_url in &crlf_targets {
            if !scope_guard.is_in_scope(crlf_url) { continue; }
            let crlf_input = ToolInput::single(crlf_url).with_job_id(Some(&job_id));
            match self.run_stage_with_retry(&self.crlfuzz, crlf_input).await {
                Ok(crlf_output) => {
                    let crlf_findings = self.crlfuzz.parse_findings(&crlf_output);
                    for crf in crlf_findings {
                        let fingerprint = Deduplicator::compute_finding_fingerprint(
                            &program_handle,
                            &target,
                            "crlf-injection",
                            None,
                            &crf.url,
                        );

                        let (finding_id, is_new) = self.repository
                            .save_finding(
                                &program_handle,
                                &target,
                                &crf.url,
                                "crlf-injection",
                                &format!("CRLF Injection — HTTP Response Splitting"),
                                &crf.severity,
                                &crf.payload,
                                None,
                                Some(&crf.description),
                                &fingerprint,
                                "POTENTIAL",
                                "REQUIRES_REVIEW",
                                &serde_json::to_string(&crf).unwrap_or_default(),
                            ).await?;

                        if is_new {
                            info!("🔀 CRLF INJECTION at '{}'", crf.url);
                            let evidence = CollectedEvidence {
                                target: target.clone(),
                                matched_url: crf.url.clone(),
                                template_id: "crlf-injection".to_string(),
                                template_name: "CRLF Injection — HTTP Response Splitting".to_string(),
                                severity: crf.severity.clone(),
                                curl_command: Some(format!("curl -ik -s '{}'", crf.url)),
                                request: None,
                                response: Some("Injected CRLF sequence reflected in HTTP response headers".to_string()),
                                extracted_data: vec![crf.payload.clone()],
                                raw_scanner_output: crf.description.clone(),
                            };
                            if let Ok((report_path, report_content)) = self.report_generator
                                .generate_report(&evidence, &program_handle).await
                            {
                                let title = format!("🔀 CRLF Injection: HTTP Response Splitting");
                                let _ = self.repository.save_report(&finding_id, &title, &report_path, &report_content).await;
                                self.notifier.notify_potential_finding(
                                    &crf.severity, &program_handle, &crf.url, &title, &report_path
                                ).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("crlfuzz scan failed for '{}': {}", crlf_url, e);
                }
            }
        }

        // ---------------------------------------------------------------------
        // STEP 4.5: FFUF — Directory & Path Fuzzing
        // Discovers hidden paths, admin panels, API endpoints, backup files.
        // Runs against live hosts (up to 5 to stay within time budget).
        // Discovered paths are saved as endpoints and fed into Nuclei.
        // ---------------------------------------------------------------------
        self.repository
            .update_job_status(&job_id, "DIRECTORY_FUZZ", "RUNNING", None)
            .await?;

        // Limit to 5 live hosts to avoid excessive scan time
        let ffuf_targets: Vec<String> = live_urls.iter().take(5).cloned().collect();
        let mut ffuf_discovered: Vec<String> = Vec::new();

        for ffuf_url in &ffuf_targets {
            let ffuf_input = ToolInput::single(ffuf_url).with_job_id(Some(&job_id));
            match self.run_stage_with_retry(&self.ffuf, ffuf_input).await {
                Ok(ffuf_output) => {
                    let ffuf_results = self.ffuf.parse_results(&ffuf_output);
                    if !ffuf_results.is_empty() {
                        info!("🗂️ ffuf found {} paths at '{}'", ffuf_results.len(), ffuf_url);
                    }

                    for fr in ffuf_results {
                        if fr.url.is_empty() || !scope_guard.is_in_scope(&fr.url) {
                            continue;
                        }

                        // Save discovered path as an endpoint for further scanning
                        let status_json = format!("{{\"status\":{}}}", fr.status);
                        let _ = self.repository.save_endpoint(
                            &program_handle,
                            &target,
                            &fr.url,
                            "GET",
                            Some(status_json.as_str()),
                            "ffuf",
                        ).await;

                        // Flag interesting status codes immediately
                        let is_interesting = matches!(fr.status, 200 | 201 | 204 | 401 | 403 | 500);
                        if is_interesting {
                            info!("  → [{}] {} ({} bytes) — input: '{}'",
                                fr.status, fr.url, fr.length, fr.input);
                            ffuf_discovered.push(fr.url.clone());
                        }
                    }
                }
                Err(e) => {
                    warn!("ffuf directory fuzz failed for '{}': {}", ffuf_url, e);
                }
            }
        }

        // Feed ffuf-discovered URLs into scan_targets for Nuclei to analyze
        let mut scan_targets = scan_targets;
        scan_targets.extend(ffuf_discovered);
        let scan_targets = Deduplicator::deduplicate_strings(&scan_targets);
        let scan_targets = scope_guard.filter_in_scope(&scan_targets);

        // STEP 5: NUCLEI (Surgical Tech-Aware Vulnerability Scanning)
        self.repository
            .update_job_status(&job_id, "NUCLEI", "RUNNING", None)
            .await?;


        // Collect all detected technologies across live hosts for surgical routing
        let all_detected_techs: Vec<String> = live_hosts
            .iter()
            .flat_map(|h| h.technologies.clone())
            .collect();
        let surgical_tags = TechRouter::format_tags_arg(&all_detected_techs);

        let nuclei_scanner = if !surgical_tags.is_empty() {
            info!("🎯 Applied Surgical Nuclei tags based on detected technologies: [{}]", surgical_tags);
            self.nuclei.clone().with_tags(Some(surgical_tags))
        } else {
            self.nuclei.clone()
        };

        let nuclei_input = ToolInput::multiple(&scan_targets).with_job_id(Some(&job_id));
        let findings = match self.run_stage_with_retry(&nuclei_scanner, nuclei_input).await {

            Ok(output) => {
                let parsed = self.nuclei.parse_findings(&output);
                // Multi-stage Scope Guard: Filter findings
                let mut valid_findings = Vec::new();
                for f in parsed {
                    if scope_guard.is_in_scope(&f.matched_at) || scope_guard.is_in_scope(&f.host) {
                        valid_findings.push(f);
                    } else {
                        warn!("Dropped Nuclei finding for out-of-scope host: '{}'", f.matched_at);
                    }
                }
                valid_findings
            }
            Err(e) => {
                warn!("Nuclei scan stage failed for target '{}': {}", target, e);
                self.notifier.notify_tool_error("nuclei", &target, &e.to_string()).await;
                Vec::new()
            }
        };

        // STEP 5: FINDING TRIAGE, DEDUPLICATION, EVIDENCE & REPORT DRAFTING
        for finding in findings {
            let fingerprint = Deduplicator::compute_finding_fingerprint(
                &program_handle,
                &target,
                &finding.template_id,
                finding.matcher_name.as_deref(),
                &finding.matched_at,
            );

            let (finding_id, is_new) = self
                .repository
                .save_finding(
                    &program_handle,
                    &target,
                    &finding.matched_at,
                    &finding.template_id,
                    &finding.template_name,
                    finding.severity.as_str(),
                    &finding.matched_at,
                    finding.matcher_name.as_deref(),
                    finding.description.as_deref(),
                    &fingerprint,
                    "POTENTIAL",
                    "REQUIRES_REVIEW",
                    &finding.raw_json,
                )
                .await?;

            if is_new {
                info!(
                    "🚨 New potential finding recorded: '{}' on '{}' (Severity: {})",
                    finding.template_name, finding.matched_at, finding.severity
                );

                let evidence = EvidenceCollector::from_nuclei_finding(&target, &finding);
                let _ = self
                    .repository
                    .save_evidence(
                        &finding_id,
                        evidence.request.as_deref(),
                        evidence.response.as_deref(),
                        evidence.curl_command.as_deref(),
                        &evidence.raw_scanner_output,
                    )
                    .await;

                if let Ok((report_path, report_content)) = self
                    .report_generator
                    .generate_report(&evidence, &program_handle)
                    .await
                {
                    let title = format!("{}: {}", finding.severity, finding.template_name);
                    let _ = self
                        .repository
                        .save_report(&finding_id, &title, &report_path, &report_content)
                        .await;

                    self.notifier
                        .notify_potential_finding(
                            finding.severity.as_str(),
                            &program_handle,
                            &finding.matched_at,
                            &finding.template_name,
                            &report_path,
                        )
                        .await;
                }
            }
        }

        self.repository
            .update_job_status(&job_id, "COMPLETED", "COMPLETED", None)
            .await?;
        self.repository.update_asset_last_scanned(&target).await?;

        info!("Job '{}' for target '{}' completed successfully.", job_id, target);
        Ok(())
    }
}
