use crate::hackerone::models::{
    AssetScopeStatus, AssetType, HackerOneScopeAsset, NormalizedProgramScope, ProgramScopeMode,
};
use crate::validation::ScopeGuard;
use tracing::{debug, info, warn};

pub struct ScopeResolver;

impl ScopeResolver {
    /// Extracts actionable targets from normalized program scopes.
    /// Follows the conservative policy: only explicitly authorized in-scope assets pass.
    pub fn extract_actionable_targets(
        program_scopes: &[NormalizedProgramScope],
    ) -> Vec<(String, String)> {
        let mut targets = Vec::new();

        for prog in program_scopes {
            if prog.program.scope_mode == ProgramScopeMode::Open {
                debug!(
                    "Program '{}' is OPEN scope mode. Enforcing conservative explicit asset policy.",
                    prog.program.handle
                );
            }

            for asset in &prog.in_scope_assets {
                if asset.scope_status != AssetScopeStatus::InScope {
                    continue;
                }

                let identifier = asset.asset_identifier.trim();
                match &asset.asset_type {
                    AssetType::Domain
                    | AssetType::Wildcard
                    | AssetType::Url
                    | AssetType::Cidr
                    | AssetType::IpAddress => {
                        let normalized = ScopeGuard::normalize_target(identifier);
                        if !normalized.is_empty() {
                            targets.push((prog.program.handle.clone(), normalized));
                        }
                    }
                    AssetType::GooglePlayApp | AssetType::AppleStoreApp => {
                        info!(
                            "📱 Registering In-Scope Mobile Application: '{}' [{}] for program '{}'",
                            identifier,
                            asset.asset_type.as_str(),
                            prog.program.handle
                        );
                        targets.push((prog.program.handle.clone(), format!("app:{}", identifier)));
                    }
                    AssetType::SourceCode => {
                        info!(
                            "📦 Registering In-Scope Source Code Repository: '{}' for program '{}'",
                            identifier,
                            prog.program.handle
                        );
                        targets.push((prog.program.handle.clone(), format!("git:{}", identifier)));
                    }
                    AssetType::Executable => {
                        info!(
                            "⚙️ Registering In-Scope Executable/Binary: '{}' for program '{}'",
                            identifier,
                            prog.program.handle
                        );
                        targets.push((prog.program.handle.clone(), format!("bin:{}", identifier)));
                    }
                    AssetType::Other(other_type) => {
                        if identifier.contains('.') && !identifier.contains(' ') {
                            let normalized = ScopeGuard::normalize_target(identifier);
                            if !normalized.is_empty() {
                                targets.push((prog.program.handle.clone(), normalized));
                            }
                        } else {
                            debug!(
                                "Asset type '{}' with value '{}' in program '{}'",
                                other_type, identifier, prog.program.handle
                            );
                        }
                    }
                }
            }
        }

        targets
    }

    /// Validates if an asset is network scannable or mobile/source analyzable
    pub fn is_network_scannable(asset: &HackerOneScopeAsset) -> bool {
        if asset.scope_status != AssetScopeStatus::InScope {
            return false;
        }

        matches!(
            asset.asset_type,
            AssetType::Domain
                | AssetType::Wildcard
                | AssetType::Url
                | AssetType::Cidr
                | AssetType::IpAddress
                | AssetType::GooglePlayApp
                | AssetType::AppleStoreApp
                | AssetType::SourceCode
                | AssetType::Executable
        ) || (asset.asset_identifier.contains('.') && !asset.asset_identifier.contains(' '))
    }
}
