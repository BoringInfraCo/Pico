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

/// OpenCode's normalized policy result for Bash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionAction {
    Allow,
    Ask,
    Deny,
    Unknown,
}

impl PermissionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Ask => "ASK",
            Self::Deny => "DENY",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Whether the normalized policy applies to every Bash command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityScope {
    Unrestricted,
    Bounded,
}

impl CapabilityScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unrestricted => "UNRESTRICTED",
            Self::Bounded => "BOUNDED",
        }
    }
}

/// A provider-neutral fact about an actor's Bash policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedBashCapability {
    pub permission: PermissionAction,
    pub scope: CapabilityScope,
    pub runtime_mode: &'static str,
    pub source_locator: String,
}

/// Results from the bounded set of discovery adapters enabled by this release.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub actors: Vec<ObservedActor>,
    pub bash_capabilities: Vec<ObservedBashCapability>,
    pub problems: Vec<String>,
}

/// Runs the single supported actor adapter. This is intentionally not a
/// plugin registry: Sprint 002 has one explicit adapter only.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    agents::opencode::discover(workspace, home)
}
