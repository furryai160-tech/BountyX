use crate::config::AppConfig;
use crate::errors::{BountyScopeError, Result};
use crate::hackerone::models::*;
use async_trait::async_trait;
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::{Client, StatusCode};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};


#[async_trait]
pub trait HackerOneClientTrait: Send + Sync {
    async fn fetch_programs(&self) -> Result<Vec<HackerOneProgram>>;
    async fn fetch_program_scopes(&self, handle: &str) -> Result<(Vec<HackerOneScopeAsset>, Vec<HackerOneScopeAsset>)>;
    async fn fetch_all_in_scope_assets(&self) -> Result<Vec<NormalizedProgramScope>>;
    async fn test_connection(&self) -> Result<bool>;
}

/// Official HackerOne REST Hacker API client adapter
pub struct HackerOneRestClient {
    client: Client,
    base_url: String,
    username: String,
    api_token: String,
    retry_count: u32,
    sync_concurrency: usize,
}

impl HackerOneRestClient {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("BountyScope-Automation-Engine/0.1.0"),
        );

        let client = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .default_headers(headers)
            .build()?;

        Ok(Self {
            client,
            base_url: "https://api.hackerone.com/v1/hackers".to_string(),
            username: config.hackerone_username.clone(),
            api_token: config.hackerone_api_token.clone(),
            retry_count: config.retry_count,
            sync_concurrency: config.h1_sync_concurrency,
        })
    }


    async fn send_request_with_retry(&self, url: &str) -> Result<reqwest::Response> {
        let mut attempt = 0;
        let mut delay = Duration::from_millis(500);

        loop {
            attempt += 1;
            let req = self
                .client
                .get(url)
                .basic_auth(&self.username, Some(&self.api_token));

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(resp);
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let wait_time = if let Some(retry_after) = resp.headers().get("Retry-After") {
                            retry_after
                                .to_str()
                                .ok()
                                .and_then(|s| s.parse::<u64>().ok())
                                .map(Duration::from_secs)
                                .unwrap_or(delay)
                        } else {
                            delay
                        };

                        warn!(
                            "HackerOne API rate limit encountered (429). Backing off for {:?} (Attempt {}/{})",
                            wait_time, attempt, self.retry_count
                        );

                        if attempt >= self.retry_count {
                            return Err(BountyScopeError::HackerOneApi {
                                status: status.as_u16(),
                                message: "Rate limit exceeded after maximum retries".to_string(),
                            });
                        }

                        tokio::time::sleep(wait_time).await;
                        delay *= 2;
                        continue;
                    }

                    if status.is_server_error() && attempt < self.retry_count {
                        warn!(
                            "HackerOne API server error ({}). Retrying in {:?} (Attempt {}/{})",
                            status, delay, attempt, self.retry_count
                        );
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                        continue;
                    }

                    let err_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                    return Err(BountyScopeError::HackerOneApi {
                        status: status.as_u16(),
                        message: err_text,
                    });
                }
                Err(err) => {
                    if attempt >= self.retry_count {
                        return Err(BountyScopeError::Network(err));
                    }
                    warn!(
                        "HackerOne network error: {}. Retrying in {:?} (Attempt {}/{})",
                        err, delay, attempt, self.retry_count
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }
}

#[async_trait]
impl HackerOneClientTrait for HackerOneRestClient {
    async fn test_connection(&self) -> Result<bool> {
        let url = format!("{}/programs?page[size]=1", self.base_url);
        match self.send_request_with_retry(&url).await {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!("HackerOne connection test failed: {}", e);
                Ok(false)
            }
        }
    }

    async fn fetch_programs(&self) -> Result<Vec<HackerOneProgram>> {
        let mut programs = Vec::new();
        let mut page = 1;
        let page_size = 100;

        loop {
            let url = format!("{}/programs?page[number]={}&page[size]={}", self.base_url, page, page_size);
            debug!("Fetching HackerOne programs page {}", page);

            let resp = self.send_request_with_retry(&url).await?;
            let body: H1ProgramsResponse = resp.json().await.map_err(|e| {
                BountyScopeError::HackerOneApi {
                    status: 200,
                    message: format!("Failed to parse HackerOne programs response: {}", e),
                }
            })?;

            if let Some(items) = body.data {
                if items.is_empty() {
                    break;
                }

                for item in items {
                    let scope_mode = item
                        .attributes
                        .scope_mode
                        .as_deref()
                        .and_then(|s| ProgramScopeMode::from_str(s).ok())
                        .unwrap_or(ProgramScopeMode::Closed);

                    programs.push(HackerOneProgram {
                        id: item.id,
                        handle: item.attributes.handle,
                        name: item.attributes.name,
                        url: item.attributes.url,
                        submission_state: item.attributes.submission_state.unwrap_or_else(|| "open".to_string()),
                        offers_bounties: item.attributes.offers_bounties.unwrap_or(false),
                        scope_mode,
                    });
                }

                if body.links.as_ref().and_then(|l| l.next.as_ref()).is_none() {
                    break;
                }
                page += 1;
            } else {
                break;
            }
        }

        info!("Fetched {} programs from HackerOne", programs.len());
        Ok(programs)
    }

    async fn fetch_program_scopes(&self, handle: &str) -> Result<(Vec<HackerOneScopeAsset>, Vec<HackerOneScopeAsset>)> {
        let mut in_scope = Vec::new();
        let mut out_of_scope = Vec::new();
        let mut page = 1;
        let page_size = 100;

        loop {
            let url = format!(
                "{}/programs/{}/structured_scopes?page[number]={}&page[size]={}",
                self.base_url, handle, page, page_size
            );

            let resp = match self.send_request_with_retry(&url).await {
                Ok(r) => r,
                Err(err) => {
                    warn!("Failed to fetch scope for program '{}': {}", handle, err);
                    return Ok((in_scope, out_of_scope));
                }
            };

            let body: H1ScopesResponse = match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to parse scope JSON for program '{}': {}", handle, e);
                    break;
                }
            };

            if let Some(items) = body.data {
                if items.is_empty() {
                    break;
                }

                for item in items {
                    let identifier = item.attributes.asset_identifier;
                    let asset_type = AssetType::from_raw(&item.attributes.asset_type, &identifier);
                    let is_in_scope = item.attributes.eligible_for_submission.unwrap_or(true);
                    let is_bounty = item.attributes.eligible_for_bounty.unwrap_or(false);

                    let asset = HackerOneScopeAsset {
                        id: item.id,
                        asset_identifier: identifier,
                        asset_type,
                        scope_status: if is_in_scope {
                            AssetScopeStatus::InScope
                        } else {
                            AssetScopeStatus::OutOfScope
                        },
                        bounty_eligibility: if is_bounty {
                            BountyEligibility::Eligible
                        } else {
                            BountyEligibility::NotEligible
                        },
                        instruction: item.attributes.instruction,
                        max_severity: item.attributes.max_severity,
                    };

                    if is_in_scope {
                        in_scope.push(asset);
                    } else {
                        out_of_scope.push(asset);
                    }
                }

                if body.links.as_ref().and_then(|l| l.next.as_ref()).is_none() {
                    break;
                }
                page += 1;
            } else {
                break;
            }
        }

        Ok((in_scope, out_of_scope))
    }

    async fn fetch_all_in_scope_assets(&self) -> Result<Vec<NormalizedProgramScope>> {
        let mut programs = self.fetch_programs().await?;
        // Prioritize bounty programs first
        programs.sort_by(|a, b| b.offers_bounties.cmp(&a.offers_bounties));

        let total = programs.len();
        let concurrency = self.sync_concurrency.max(1);

        info!(
            "Starting Concurrent Scope Sync across {} programs using {} workers (Bounties first)...",
            total, concurrency
        );

        let completed = Arc::new(AtomicUsize::new(0));
        let semaphore = Arc::new(Semaphore::new(concurrency));

        let tasks = programs.into_iter().map(|prog| {
            let completed = completed.clone();
            let semaphore = semaphore.clone();
            async move {
                let _permit = semaphore.acquire().await.ok();
                let handle = prog.handle.clone();
                let is_bounty = if prog.offers_bounties { "💰 [Bounty]" } else { "📋 [VDP]" };

                let (in_scope, out_of_scope) = self.fetch_program_scopes(&handle).await.unwrap_or_default();
                let in_count = in_scope.len();
                let count = completed.fetch_add(1, Ordering::SeqCst) + 1;
                let pct = (count as f64 / total as f64) * 100.0;

                info!(
                    "[{}/{} ({:.1}%)] Synced '{}' {} -> {} in-scope assets",
                    count, total, pct, handle, is_bounty, in_count
                );

                // Polite delay per slot to smooth rate limits
                tokio::time::sleep(Duration::from_millis(150)).await;

                NormalizedProgramScope {
                    program: prog,
                    in_scope_assets: in_scope,
                    out_of_scope_assets: out_of_scope,
                }
            }
        });

        let results: Vec<NormalizedProgramScope> = futures::stream::iter(tasks)
            .buffer_unordered(concurrency)
            .collect()
            .await;

        info!("Scope synchronization completed for all {} programs.", total);
        Ok(results)
    }

}

/// Mock HackerOne Client for offline testing, local demo, and unit tests
pub struct MockHackerOneClient {
    programs: Vec<NormalizedProgramScope>,
}

impl MockHackerOneClient {
    pub fn new() -> Self {
        let demo_programs = vec![
            NormalizedProgramScope {
                program: HackerOneProgram {
                    id: "prog_demo_1".to_string(),
                    handle: "demo_security".to_string(),
                    name: "Demo Security Bounty".to_string(),
                    url: Some("https://hackerone.com/demo_security".to_string()),
                    submission_state: "open".to_string(),
                    offers_bounties: true,
                    scope_mode: ProgramScopeMode::Closed,
                },
                in_scope_assets: vec![
                    HackerOneScopeAsset {
                        id: "asset_1".to_string(),
                        asset_identifier: "*.example.com".to_string(),
                        asset_type: AssetType::Wildcard,
                        scope_status: AssetScopeStatus::InScope,
                        bounty_eligibility: BountyEligibility::Eligible,
                        instruction: Some("All subdomains of example.com".to_string()),
                        max_severity: Some("critical".to_string()),
                    },
                    HackerOneScopeAsset {
                        id: "asset_2".to_string(),
                        asset_identifier: "api.demo-target.com".to_string(),
                        asset_type: AssetType::Domain,
                        scope_status: AssetScopeStatus::InScope,
                        bounty_eligibility: BountyEligibility::Eligible,
                        instruction: Some("REST API Target".to_string()),
                        max_severity: Some("high".to_string()),
                    },
                    HackerOneScopeAsset {
                        id: "asset_4".to_string(),
                        asset_identifier: "https://auth.demo-target.com/v1".to_string(),
                        asset_type: AssetType::Url,
                        scope_status: AssetScopeStatus::InScope,
                        bounty_eligibility: BountyEligibility::NotEligible,
                        instruction: Some("Authentication endpoints (VDP)".to_string()),
                        max_severity: Some("medium".to_string()),
                    },
                ],
                out_of_scope_assets: vec![
                    HackerOneScopeAsset {
                        id: "asset_3".to_string(),
                        asset_identifier: "blog.example.com".to_string(),
                        asset_type: AssetType::Domain,
                        scope_status: AssetScopeStatus::OutOfScope,
                        bounty_eligibility: BountyEligibility::NotEligible,
                        instruction: Some("Third party hosted blog".to_string()),
                        max_severity: None,
                    },
                ],
            },
        ];

        Self {
            programs: demo_programs,
        }
    }
}

#[async_trait]
impl HackerOneClientTrait for MockHackerOneClient {
    async fn test_connection(&self) -> Result<bool> {
        Ok(true)
    }

    async fn fetch_programs(&self) -> Result<Vec<HackerOneProgram>> {
        Ok(self.programs.iter().map(|p| p.program.clone()).collect())
    }

    async fn fetch_program_scopes(&self, handle: &str) -> Result<(Vec<HackerOneScopeAsset>, Vec<HackerOneScopeAsset>)> {
        if let Some(prog) = self.programs.iter().find(|p| p.program.handle == handle) {
            Ok((prog.in_scope_assets.clone(), prog.out_of_scope_assets.clone()))
        } else {
            Ok((Vec::new(), Vec::new()))
        }
    }

    async fn fetch_all_in_scope_assets(&self) -> Result<Vec<NormalizedProgramScope>> {
        Ok(self.programs.clone())
    }
}

/// Factory function to construct the appropriate HackerOne client
pub fn create_hackerone_client(config: &AppConfig) -> Result<Arc<dyn HackerOneClientTrait>> {
    if config.hackerone_adapter == "mock" || (!config.is_hackerone_configured() && config.hackerone_adapter != "api") {
        info!("Using Mock HackerOne Client Adapter (Offline Mode)");
        Ok(Arc::new(MockHackerOneClient::new()))
    } else {
        info!("Using Official HackerOne REST API Client Adapter");
        Ok(Arc::new(HackerOneRestClient::new(config)?))
    }
}
