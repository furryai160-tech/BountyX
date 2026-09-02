pub mod dedup;
pub mod scope_guard;

pub use dedup::Deduplicator;
pub use scope_guard::{ScopeGuard, ScopeRule};
