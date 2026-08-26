//! Bounded local discovery orchestration.
//!
//! Discovery adapters report observed facts; application services normalize
//! and persist those facts using Pico's generic domain types.

pub mod agents;
pub mod cloudflare;
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

/// The single effective Bash execution posture derived from a resolved
/// permission action plus sandbox configuration. This is what the analysis
/// boundary layer consumes, not the raw `PermissionAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum EffectiveBashPermission {
    /// Bash runs automatically with no approval step (resolved allow).
    #[default]
    AutoAllow,
    /// Bash may run but only after an explicit human approval gate.
    ApprovalGated,
    /// Bash execution is denied outright.
    Denied,
    /// Bash runs inside an isolating sandbox.
    Sandboxed,
    /// The resolved policy was neither fully allow/ask/deny (e.g. a mixed or
    /// bounded pattern); no concrete effective state is invented here.
    Unknown,
}

impl EffectiveBashPermission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AutoAllow => "AUTO_ALLOW",
            Self::ApprovalGated => "APPROVAL_GATED",
            Self::Denied => "DENIED",
            Self::Sandboxed => "SANDBOXED",
            Self::Unknown => "UNKNOWN",
        }
    }
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
    pub effective_state: EffectiveBashPermission,
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

/// Whether the scanner has authoritative evidence that the actor's Bash
/// environment is the environment in which the credential was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentReachability {
    Proven,
    Unknown,
}

impl EnvironmentReachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Safe normalized Cloudflare credential facts. The raw value is intentionally
/// absent from this type and is never part of DiscoveryResult.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCredential {
    pub provider: &'static str,
    pub credential_type: &'static str,
    pub source_type: &'static str,
    pub source_locator: String,
    pub fingerprint: String,
    pub environment: EnvironmentReachability,
}

/// Results from the bounded set of discovery adapters enabled by this release.
#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub actors: Vec<ObservedActor>,
    pub bash_capabilities: Vec<ObservedBashCapability>,
    pub mcp_servers: Vec<ObservedMcpServer>,
    pub github_surfaces: Vec<ObservedGithubSurface>,
    pub credentials: Vec<ObservedCredential>,
    /// Safe, normalized result from the bounded Cloudflare provider adapter.
    /// Raw credentials and provider response bodies never enter this value.
    pub cloudflare: Option<cloudflare::ProviderResult>,
    pub problems: Vec<String>,
}

/// Runs the single supported actor adapter. This is intentionally not a
/// plugin registry: Sprint 002 has one explicit adapter only.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    agents::opencode::discover(workspace, home)
}

/// Bounded discovery entrypoint used by deterministic fixtures. The optional
/// environment pairs are consumed transiently and never returned to callers.
pub fn discover_with_environment(
    workspace: &Path,
    home: Option<&Path>,
    environment: Option<&[(&str, &str)]>,
    reachability: EnvironmentReachability,
) -> Result<DiscoveryResult, PicoError> {
    agents::opencode::discover_with_environment(workspace, home, environment, reachability)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::tempdir;

    use crate::discovery::cloudflare::{Client, GetResponse, GetTransport, ProviderResult};
    use crate::discovery::{discover, DiscoveryResult};
    use crate::domain::evidence::source_locator_is_safe;

    /// Secret sentinels that must never appear as a `source_locator`.
    const SENTINELS: [&str; 2] = ["TEST_SECRET_SHOULD_NOT_PERSIST", "synthetic-token"];

    fn check_discovery(result: &DiscoveryResult) {
        for actor in &result.actors {
            assert!(
                source_locator_is_safe(&actor.source_locator, &SENTINELS),
                "actor source_locator leaked: {}",
                actor.source_locator
            );
        }
        for capability in &result.bash_capabilities {
            assert!(source_locator_is_safe(
                &capability.source_locator,
                &SENTINELS
            ));
        }
        for server in &result.mcp_servers {
            assert!(source_locator_is_safe(&server.source_locator, &SENTINELS));
        }
        for credential in &result.credentials {
            assert!(source_locator_is_safe(
                &credential.source_locator,
                &SENTINELS
            ));
            assert!(source_locator_is_safe(&credential.fingerprint, &SENTINELS));
        }
        if let Some(cloudflare) = &result.cloudflare {
            check_cloudflare(cloudflare);
        }
    }

    fn check_cloudflare(result: &ProviderResult) {
        for account in &result.accounts {
            assert!(
                source_locator_is_safe(&account.source_locator, &SENTINELS),
                "cloudflare account source_locator leaked: {}",
                account.source_locator
            );
        }
        for worker in &result.workers {
            assert!(
                source_locator_is_safe(&worker.source_locator, &SENTINELS),
                "cloudflare worker source_locator leaked: {}",
                worker.source_locator
            );
        }
        for authority in &result.authorities {
            assert!(source_locator_is_safe(
                &authority.source_locator,
                &SENTINELS
            ));
        }
    }

    #[test]
    fn adapter_conformance_emits_provenance_without_secrets() {
        // OpenCode adapter via the filesystem seam.
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("opencode.json"),
            r#"{"permission":{"bash":"allow"},"mcp":{"servers":{"local":{"type":"stdio","command":"ghcr.io/github/github-mcp-server"}}}}"#,
        )
        .unwrap();
        let opencode = discover(dir.path(), None).unwrap();
        check_discovery(&opencode);

        // Cloudflare adapter via a fixture transport seam (no network). The
        // token passed to inspect is a secret sentinel; it must not surface in
        // any emitted source_locator.
        struct FixtureTransport(HashMap<String, GetResponse>);
        impl GetTransport for FixtureTransport {
            fn get(&mut self, path: &str, _token: &str) -> Result<GetResponse, String> {
                self.0
                    .get(path)
                    .cloned()
                    .ok_or_else(|| "fixture response missing".to_string())
            }
        }
        let body = |content: &str| GetResponse {
            status: 200,
            body: content.to_string(),
            redirected_to: None,
        };
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            body(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            body(r#"{"result":{"policies":[]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            body(r#"{"result":[]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            body(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            body(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport(responses));
        let cloudflare = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        check_cloudflare(&cloudflare);

        // (a) Evidence::new rejects an empty source_locator.
        assert!(crate::domain::Evidence::new(
            "scan_1",
            crate::domain::EvidenceClass::Direct,
            "src",
            "",
            "subj",
            "obs",
            crate::domain::Sensitivity::Internal
        )
        .is_err());

        // (b) The helper rejects secret-like and empty values, accepts safe ones.
        assert!(!source_locator_is_safe("", &SENTINELS));
        assert!(!source_locator_is_safe(
            "TEST_SECRET_SHOULD_NOT_PERSIST",
            &SENTINELS
        ));
        assert!(!source_locator_is_safe("synthetic-token", &SENTINELS));
        assert!(source_locator_is_safe("project:opencode.json", &SENTINELS));
        assert!(source_locator_is_safe("/accounts", &SENTINELS));
    }
}
