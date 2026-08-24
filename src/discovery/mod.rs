//! Bounded local discovery orchestration.
//!
//! Discovery adapters report observed facts; application services normalize
//! and persist those facts using Pico's generic domain types.

pub mod agents;
pub mod mcp;

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

/// Transport declared for an OpenCode MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransport {
    Stdio,
    Http,
    Unknown,
}

impl McpTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdio => "STDIO",
            Self::Http => "HTTP",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Safe, normalized MCP server facts emitted by the OpenCode adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMcpServer {
    pub name: String,
    pub transport: McpTransport,
    pub enabled: bool,
    pub source_locator: String,
    pub safe_identity: Option<String>,
    pub safe_endpoint: Option<String>,
    pub safe_command: Option<String>,
    pub environment_keys: Vec<String>,
    pub tool_declaration: Option<String>,
    pub toolset_declaration: Option<String>,
}

/// A GitHub MCP surface normalized by the GitHub adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGithubSurface {
    pub server: ObservedMcpServer,
    pub tools: Vec<ObservedGithubTool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedGithubTool {
    pub name: String,
    pub discovery_tier: &'static str,
    pub permission: PermissionAction,
    pub permission_pattern: String,
    pub content_class: &'static str,
    pub trust: &'static str,
    pub influence_strength: &'static str,
}

/// Results from the bounded set of discovery adapters enabled by this release.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub actors: Vec<ObservedActor>,
    pub bash_capabilities: Vec<ObservedBashCapability>,
    pub mcp_servers: Vec<ObservedMcpServer>,
    pub github_surfaces: Vec<ObservedGithubSurface>,
    pub problems: Vec<String>,
}

/// Runs the single supported actor adapter. This is intentionally not a
/// plugin registry: Sprint 002 has one explicit adapter only.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    agents::opencode::discover(workspace, home)
}
