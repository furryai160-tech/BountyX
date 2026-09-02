use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramScopeMode {
    Closed,
    Open,
}

impl ProgramScopeMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProgramScopeMode::Closed => "CLOSED",
            ProgramScopeMode::Open => "OPEN",
        }
    }
}

impl fmt::Display for ProgramScopeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ProgramScopeMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_uppercase().as_str() {
            "OPEN" => Ok(ProgramScopeMode::Open),
            _ => Ok(ProgramScopeMode::Closed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetScopeStatus {
    InScope,
    OutOfScope,
}

impl AssetScopeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetScopeStatus::InScope => "IN_SCOPE",
            AssetScopeStatus::OutOfScope => "OUT_OF_SCOPE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BountyEligibility {
    Eligible,
    NotEligible,
}

impl BountyEligibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            BountyEligibility::Eligible => "BOUNTY_ELIGIBLE",
            BountyEligibility::NotEligible => "NOT_BOUNTY_ELIGIBLE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Domain,
    Wildcard,
    Url,
    Cidr,
    IpAddress,
    GooglePlayApp,
    AppleStoreApp,
    SourceCode,
    Executable,
    Other(String),
}

impl AssetType {
    pub fn as_str(&self) -> &str {
        match self {
            AssetType::Domain => "DOMAIN",
            AssetType::Wildcard => "WILDCARD",
            AssetType::Url => "URL",
            AssetType::Cidr => "CIDR",
            AssetType::IpAddress => "IP_ADDRESS",
            AssetType::GooglePlayApp => "GOOGLE_PLAY_APP_ID",
            AssetType::AppleStoreApp => "APPLE_STORE_APP_ID",
            AssetType::SourceCode => "SOURCE_CODE",
            AssetType::Executable => "EXECUTABLE",
            AssetType::Other(s) => s.as_str(),
        }
    }

    pub fn from_raw(s: &str, identifier: &str) -> Self {
        let clean = s.trim().to_uppercase();
        match clean.as_str() {
            "DOMAIN" => {
                if identifier.trim().starts_with("*.") || identifier.trim().starts_with('.') {
                    AssetType::Wildcard
                } else {
                    AssetType::Domain
                }
            }
            "WILDCARD" => AssetType::Wildcard,
            "URL" => AssetType::Url,
            "CIDR" => AssetType::Cidr,
            "IP_ADDRESS" | "IP" => AssetType::IpAddress,
            "GOOGLE_PLAY_APP_ID" | "ANDROID" => AssetType::GooglePlayApp,
            "APPLE_STORE_APP_ID" | "IOS" => AssetType::AppleStoreApp,
            "SOURCE_CODE" | "GIT" | "GITHUB" => AssetType::SourceCode,
            "EXECUTABLE" | "BINARY" => AssetType::Executable,
            _ => {
                let ident = identifier.trim();
                if ident.starts_with("*.") || ident.starts_with('.') {
                    AssetType::Wildcard
                } else if ident.starts_with("http://") || ident.starts_with("https://") {
                    if ident.contains("github.com") || ident.contains("gitlab.com") {
                        AssetType::SourceCode
                    } else {
                        AssetType::Url
                    }
                } else if ident.contains('/') && ident.parse::<ipnet::IpNet>().is_ok() {
                    AssetType::Cidr
                } else if ident.parse::<std::net::IpAddr>().is_ok() {
                    AssetType::IpAddress
                } else if ident.contains('.') && !ident.contains(' ') {
                    AssetType::Domain
                } else {
                    AssetType::Other(clean)
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HackerOneProgram {
    pub id: String,
    pub handle: String,
    pub name: String,
    pub url: Option<String>,
    pub submission_state: String,
    pub offers_bounties: bool,
    pub scope_mode: ProgramScopeMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HackerOneScopeAsset {
    pub id: String,
    pub asset_identifier: String,
    pub asset_type: AssetType,
    pub scope_status: AssetScopeStatus,
    pub bounty_eligibility: BountyEligibility,
    pub instruction: Option<String>,
    pub max_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedProgramScope {
    pub program: HackerOneProgram,
    pub in_scope_assets: Vec<HackerOneScopeAsset>,
    pub out_of_scope_assets: Vec<HackerOneScopeAsset>,
}

// HackerOne API dynamic serialization models
#[derive(Debug, Clone, Deserialize)]
pub struct H1PaginationLinks {
    pub next: Option<String>,
    pub prev: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ProgramAttributes {
    pub handle: String,
    pub name: String,
    pub submission_state: Option<String>,
    pub offers_bounties: Option<bool>,
    pub url: Option<String>,
    pub scope_mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ProgramData {
    pub id: String,
    pub attributes: H1ProgramAttributes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ProgramsResponse {
    pub data: Option<Vec<H1ProgramData>>,
    pub links: Option<H1PaginationLinks>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ScopeAttributes {
    pub asset_identifier: String,
    pub asset_type: String,
    pub eligible_for_bounty: Option<bool>,
    pub eligible_for_submission: Option<bool>,
    pub instruction: Option<String>,
    pub max_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ScopeData {
    pub id: String,
    pub attributes: H1ScopeAttributes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct H1ScopesResponse {
    pub data: Option<Vec<H1ScopeData>>,
    pub links: Option<H1PaginationLinks>,
}
