use bountyscope::hackerone::models::{
    AssetScopeStatus, AssetType, BountyEligibility, HackerOneProgram, HackerOneScopeAsset,
    NormalizedProgramScope, ProgramScopeMode,
};
use bountyscope::monitor::diff::ScopeDiffEngine;

#[test]
fn test_scope_diff_detection() {
    let prog1 = HackerOneProgram {
        id: "p1".to_string(),
        handle: "target_corp".to_string(),
        name: "Target Corp".to_string(),
        url: None,
        submission_state: "open".to_string(),
        offers_bounties: true,
        scope_mode: ProgramScopeMode::Closed,
    };

    let prev_scopes = vec![NormalizedProgramScope {
        program: prog1.clone(),
        in_scope_assets: vec![
            HackerOneScopeAsset {
                id: "a1".to_string(),
                asset_identifier: "api.target.com".to_string(),
                asset_type: AssetType::Domain,
                scope_status: AssetScopeStatus::InScope,
                bounty_eligibility: BountyEligibility::Eligible,
                instruction: None,
                max_severity: None,
            },
            HackerOneScopeAsset {
                id: "a2".to_string(),
                asset_identifier: "old.target.com".to_string(),
                asset_type: AssetType::Domain,
                scope_status: AssetScopeStatus::InScope,
                bounty_eligibility: BountyEligibility::Eligible,
                instruction: None,
                max_severity: None,
            },
        ],
        out_of_scope_assets: vec![],
    }];

    let curr_scopes = vec![NormalizedProgramScope {
        program: prog1.clone(),
        in_scope_assets: vec![
            HackerOneScopeAsset {
                id: "a1".to_string(),
                asset_identifier: "api.target.com".to_string(),
                asset_type: AssetType::Domain,
                scope_status: AssetScopeStatus::InScope,
                bounty_eligibility: BountyEligibility::Eligible,
                instruction: None,
                max_severity: None,
            },
            HackerOneScopeAsset {
                id: "a3".to_string(),
                asset_identifier: "new-api.target.com".to_string(),
                asset_type: AssetType::Domain,
                scope_status: AssetScopeStatus::InScope,
                bounty_eligibility: BountyEligibility::Eligible,
                instruction: None,
                max_severity: None,
            },
        ],
        out_of_scope_assets: vec![],
    }];

    let diff = ScopeDiffEngine::compute_diff(&prev_scopes, &curr_scopes);

    assert_eq!(diff.new_targets.len(), 1);
    assert_eq!(diff.new_targets[0].1, "new-api.target.com");

    assert_eq!(diff.removed_targets.len(), 1);
    assert_eq!(diff.removed_targets[0].1, "old.target.com");
}
