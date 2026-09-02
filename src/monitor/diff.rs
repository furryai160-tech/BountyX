use crate::hackerone::models::NormalizedProgramScope;
use crate::hackerone::scope::ScopeResolver;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDiff {
    pub new_targets: Vec<(String, String)>,     // (program_handle, normalized_target)
    pub removed_targets: Vec<(String, String)>, // (program_handle, normalized_target)
    pub total_current_targets: usize,
    pub total_previous_targets: usize,
}

pub struct ScopeDiffEngine;

impl ScopeDiffEngine {
    pub fn compute_diff(
        previous_scopes: &[NormalizedProgramScope],
        current_scopes: &[NormalizedProgramScope],
    ) -> ScopeDiff {
        let prev_targets = ScopeResolver::extract_actionable_targets(previous_scopes);
        let curr_targets = ScopeResolver::extract_actionable_targets(current_scopes);

        let prev_set: HashSet<(String, String)> = prev_targets.into_iter().collect();
        let curr_set: HashSet<(String, String)> = curr_targets.into_iter().collect();

        let mut new_targets: Vec<(String, String)> = curr_set.difference(&prev_set).cloned().collect();
        let mut removed_targets: Vec<(String, String)> = prev_set.difference(&curr_set).cloned().collect();

        new_targets.sort();
        removed_targets.sort();

        ScopeDiff {
            total_current_targets: curr_set.len(),
            total_previous_targets: prev_set.len(),
            new_targets,
            removed_targets,
        }
    }
}
