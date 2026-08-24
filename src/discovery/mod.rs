//! Bounded local discovery orchestration.
//!
//! Discovery adapters report observed facts; application services normalize
//! and persist those facts using Pico's generic domain types.

pub mod agents;

use std::path::Path;

use crate::shared::PicoError;

/// A minimal, provider-neutral fact establishing that an actor was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedActor {
    pub provider: &'static str,
    pub source_type: &'static str,
    pub source_locator: String,
}

/// Results from the bounded set of discovery adapters enabled by this release.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub actors: Vec<ObservedActor>,
    pub problems: Vec<String>,
}

/// Runs the single supported actor adapter. This is intentionally not a
/// plugin registry: Sprint 002 has one explicit adapter only.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    agents::opencode::discover(workspace, home)
}
