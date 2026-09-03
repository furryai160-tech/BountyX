use crate::ai::planner::SecurityHypothesis;
use crate::errors::{BountyScopeError, Result};
use crate::sandbox::client::{SandboxedHttpClient, SandboxedResponse};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use std::str::FromStr;

pub enum AgentTool {
    InspectEndpoint { url: String, method: String },
    TestHypothesis { hypothesis: SecurityHypothesis },
}

pub struct ToolRouter;

impl ToolRouter {
    pub async fn execute_tool(
        http_client: &SandboxedHttpClient,
        tool: AgentTool,
    ) -> Result<SandboxedResponse> {
        match tool {
            AgentTool::InspectEndpoint { url, method } => {
                let m = Method::from_str(&method).unwrap_or(Method::GET);
                http_client.request(m, &url, None, None).await
            }
            AgentTool::TestHypothesis { hypothesis } => {
                let m = Method::from_str(&hypothesis.method).unwrap_or(Method::GET);
                let mut headers = HeaderMap::new();

                if hypothesis.category.contains("CORS") {
                    headers.insert(
                        HeaderName::from_str("origin").unwrap(),
                        HeaderValue::from_str("https://bountyx-test.com").unwrap(),
                    );
                }

                http_client.request(m, &hypothesis.target_url, Some(headers), None).await
            }
        }
    }
}
