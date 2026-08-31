//! `pico scan` application service (SPRINT-001.md §12).

use std::path::Path;

use crate::analysis::{
    analyze_with_scan_status, AnalysisLimits, AnalysisResult, AnalysisStatus, CandidateDisposition,
};
use crate::discovery;
use crate::domain::{
    relationship_snapshot_metadata, resource_snapshot_metadata, Evidence, EvidenceClass,
    Observation, Relationship, RelationshipState, Resource, Scan, ScanStatus, Sensitivity,
    GRAPH_SNAPSHOT_VERSION,
};
use crate::findings::diagnostics::{ProviderDiagnostic, ScanDiagnostics};
use crate::findings::{
    eligibility_diagnostics, generate_with_scan_status, FindingGenerationStatus, FindingLimits,
    FindingResult,
};
use crate::graph::{project, ProjectionInput, SecurityGraph};
use crate::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    EvidenceRepo, FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord, FindingRecord,
    FindingRemediationRecord, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo,
    ScanAnalysisRecord, ScanAnalysisRepo, ScanDiagnosticsRepo, ScanRepo,
};
use crate::shared::{PicoError, PICO_VERSION};
use chrono::Utc;

/// One discovered agent's effective Bash posture for scan-summary surfacing (S023 / F-U1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBashPosture {
    pub provider: String,
    pub effective_state: String,
}

/// Structured result of a scan, rendered by the CLI.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resource_count: u64,
    pub agent_count: u64,
    pub relationship_count: u64,
    pub evidence_count: u64,
    pub finding_count: u64,
    pub findings: Option<FindingResult>,
    pub finding_class: Option<String>,
    pub finding_severity: Option<String>,
    pub finding_confidence: Option<String>,
    pub bash_permission: Option<String>,
    /// Per-agent effective Bash postures (S020 vocabulary: AUTO_ALLOW /
    /// APPROVAL_GATED / DENIED / SANDBOXED / UNKNOWN). Empty when no Bash
    /// capability was observed. Populated from every discovered capability
    /// that has a matching actor — not just the first.
    pub agent_bash_postures: Vec<AgentBashPosture>,
    pub github_mcp_observed: bool,
    pub influence_strength: Option<String>,
    pub cloudflare_credential_observed: bool,
    pub credential_reachability: Option<String>,
    pub cloudflare_credential_status: Option<String>,
    pub cloudflare_account_count: u64,
    pub cloudflare_worker_count: u64,
    pub worker_mutation_authority: Option<String>,
    pub authority_resolution: Option<String>,
    pub graph: Option<SecurityGraph>,
    pub analysis: Option<AnalysisResult>,
    pub graph_projection_status: String,
    pub graph_node_count: u64,
    pub graph_edge_count: u64,
    pub state_eligible_edge_count: u64,
    pub non_eligible_edge_count: u64,
    pub analysis_status: String,
    pub analysis_disposition: String,
    pub influence_path_count: u64,
    pub authority_path_count: u64,
    pub active_attack_path_count: u64,
    pub blocked_attack_path_count: u64,
    pub unresolved_candidate_count: u64,
    /// Structured, machine-readable diagnostics for the scan (per-provider
    /// status, suppression reasons, and confidence-reduction notes). A rendered
    /// projection of the same facts also lives on `findings.diagnostics`.
    pub diagnostics_detail: Option<ScanDiagnostics>,
    /// Per-GitHub-credential authority facts observed by this scan (SPRINT-021
    /// R6/R7). One entry per GitHub credential, carrying only safe normalized
    /// classification facts (credential type, resolution tier, permission
    /// state, and unknown-reason codes). Empty when no GitHub credential was
    /// observed so the golden path renders nothing.
    pub github_credentials: Vec<crate::application::GitHubCredentialView>,
}

/// Runs bounded local discovery in an initialized workspace.
pub struct ScanService;

/// Reachability asserted by the operator-facing entry point. The shipped CLI
/// scans a real workspace, where the project-root dotenv contract
/// (SPRINT-005) is the bounded proof that Bash can reach the credential; the
/// adapter's own Bash allow/unrestricted gate remains the only other condition
/// on live introspection. Fixture seams pass their reachability explicitly and
/// are unaffected by this constant.
const OPERATOR_REACHABILITY: discovery::EnvironmentReachability =
    discovery::EnvironmentReachability::Proven;

impl ScanService {
    pub fn run(workspace: &Path) -> Result<ScanResult, PicoError> {
        Self::run_with_home_and_environment(
            workspace,
            std::env::var_os("HOME").as_deref().map(Path::new),
            None,
            OPERATOR_REACHABILITY,
        )
    }

    /// Runs discovery with an explicit home directory, primarily enabling
    /// deterministic local-fixture tests without inspecting a real user home.
    pub fn run_with_home(workspace: &Path, home: Option<&Path>) -> Result<ScanResult, PicoError> {
        Self::run_with_home_and_environment(
            workspace,
            home,
            None,
            discovery::EnvironmentReachability::Unknown,
        )
    }

    /// Runs discovery with a controlled synthetic execution environment. This
    /// is used by fixtures to prove inheritance without reading process-global
    /// secrets or claiming that Pico's own environment is OpenCode's.
    pub fn run_with_home_and_environment(
        workspace: &Path,
        home: Option<&Path>,
        environment: Option<&[(&str, &str)]>,
        environment_reachability: discovery::EnvironmentReachability,
    ) -> Result<ScanResult, PicoError> {
        Self::run_with_home_and_environment_and_provider(
            workspace,
            home,
            environment,
            environment_reachability,
            None,
        )
    }

    /// Deterministic provider seam used by controlled fixtures. Production
    /// scans use the bounded Cloudflare adapter emitted by local discovery;
    /// tests may inject a safe normalized provider result produced by a fake
    /// transport without introducing network access or raw credentials.
    pub fn run_with_home_and_environment_and_provider(
        workspace: &Path,
        home: Option<&Path>,
        environment: Option<&[(&str, &str)]>,
        environment_reachability: discovery::EnvironmentReachability,
        provider_result: Option<discovery::cloudflare::ProviderResult>,
    ) -> Result<ScanResult, PicoError> {
        Self::run_with_home_and_environment_and_providers(
            workspace,
            home,
            environment,
            environment_reachability,
            provider_result,
            None,
        )
    }

    /// Deterministic GitHub authority seam used by controlled fixtures. The
    /// injected result is safe, normalized, and offline-safe; tests produce it
    /// through a fixture transport without any network access.
    pub fn run_with_home_and_environment_and_github(
        workspace: &Path,
        home: Option<&Path>,
        environment: Option<&[(&str, &str)]>,
        environment_reachability: discovery::EnvironmentReachability,
        github_result: Option<discovery::github::GitHubAuthorityResult>,
    ) -> Result<ScanResult, PicoError> {
        Self::run_with_home_and_environment_and_providers(
            workspace,
            home,
            environment,
            environment_reachability,
            None,
            github_result,
        )
    }

    /// Combined provider seam: injects optional Cloudflare and GitHub provider
    /// results after discovery so fixtures can exercise either authority path
    /// without network access.
    pub fn run_with_home_and_environment_and_providers(
        workspace: &Path,
        home: Option<&Path>,
        environment: Option<&[(&str, &str)]>,
        environment_reachability: discovery::EnvironmentReachability,
        provider_result: Option<discovery::cloudflare::ProviderResult>,
        github_result: Option<discovery::github::GitHubAuthorityResult>,
    ) -> Result<ScanResult, PicoError> {
        let mut db = Database::open_existing(&workspace.join(".pico").join("pico.db"))?;
        db.migrate()?;

        let scan_repo = ScanRepo::new(db.connection());
        let mut scan = Scan::start(PICO_VERSION)?;
        // Every scan created after the graph snapshot contract exists declares
        // the version needed for safe scan-scoped projection. The graph layer
        // can distinguish an intentionally empty scan from legacy state.
        scan.metadata = Some(serde_json::json!({
            "graph_snapshot_version": GRAPH_SNAPSHOT_VERSION,
        }));
        scan_repo.insert(&scan)?;

        let mut discovered = discovery::discover_with_environment(
            workspace,
            home,
            environment,
            environment_reachability,
        )?;
        if provider_result.is_some() {
            discovered.cloudflare = provider_result;
        }
        if github_result.is_some() {
            discovered.github = github_result;
        }
        let resource_repo = ResourceRepo::new(db.connection());
        let evidence_repo = EvidenceRepo::new(db.connection());
        let observation_repo = ObservationRepo::new(db.connection());
        let mut actor_resources: std::collections::BTreeMap<String, Resource> = Default::default();
        for actor in discovered.actors {
            let provider = actor.provider;
            let agent_key = format!("agent:{provider}");
            let mut resource = match resource_repo.get_by_canonical_key(&agent_key)? {
                Some(resource) => resource,
                None => {
                    Resource::new(&agent_key, "agent", provider, &agent_display_name(provider))?
                }
            };
            resource.last_observed_at = chrono::Utc::now();
            resource_repo.upsert(&resource)?;
            evidence_repo.insert(&Evidence::new(
                &scan.id,
                EvidenceClass::Direct,
                actor.source_type,
                &actor.source_locator,
                &agent_key,
                &format!("supported {provider} configuration observed"),
                Sensitivity::Internal,
            )?)?;
            // Every actor resource is observed so it enters this scan's graph,
            // including multiple actors that share one `agent:<provider>` key.
            observe_resource(
                &observation_repo,
                &scan.id,
                &resource,
                &format!("{provider}_adapter"),
            )?;
            actor_resources.insert(provider.to_string(), resource);
        }

        let relationship_repo = RelationshipRepo::new(db.connection());
        let mut bash_permission = None;
        let mut agent_bash_postures = Vec::new();
        let mut bash_resource = None;
        let mut bash_observed = false;
        for capability in discovered.bash_capabilities.iter() {
            let Some(actor) = actor_resources.get(capability.provider) else {
                continue;
            };
            let agent_key = format!("agent:{}", capability.provider);
            let mut bash = match resource_repo.get_by_canonical_key("shell:bash")? {
                Some(resource) => resource,
                None => Resource::new("shell:bash", "shell", "local", "Bash")?,
            };
            bash.last_observed_at = chrono::Utc::now();
            bash.metadata = Some(serde_json::json!({"capability": "EXECUTE"}));
            resource_repo.upsert(&bash)?;
            bash_resource = Some(bash.clone());

            let relationship_key = format!("{agent_key}|can_execute|shell:bash");
            let (state, boundary_kind) = match capability.effective_state {
                discovery::EffectiveBashPermission::AutoAllow => (RelationshipState::Derived, None),
                discovery::EffectiveBashPermission::Sandboxed => {
                    (RelationshipState::Derived, Some("SANDBOX".to_string()))
                }
                discovery::EffectiveBashPermission::ApprovalGated => {
                    (RelationshipState::Unknown, None)
                }
                discovery::EffectiveBashPermission::Denied => (RelationshipState::Blocked, None),
                discovery::EffectiveBashPermission::Unknown => (RelationshipState::Unknown, None),
            };
            let mut relationship = match relationship_repo
                .get_by_canonical_key(&relationship_key)?
            {
                Some(relationship) => relationship,
                None => {
                    Relationship::new(&relationship_key, &actor.id, &bash.id, "can_execute", state)?
                }
            };
            relationship.state = state;
            relationship.last_observed_at = chrono::Utc::now();
            let mut capability_metadata = serde_json::json!({
                "effective_permission": capability.permission.as_str(),
                "effective_state": capability.effective_state.as_str(),
                "scope": capability.scope.as_str(),
                "runtime_mode": capability.runtime_mode,
            });
            // Sandboxed Bash is surfaced as a Sandbox boundary so the analysis
            // layer can interrupt without misclassifying it as a HardDeny.
            if let Some(kind) = boundary_kind {
                if let serde_json::Value::Object(fields) = &mut capability_metadata {
                    fields.insert("boundary_kind".to_string(), serde_json::Value::String(kind));
                }
            }
            relationship.metadata = Some(capability_metadata.clone());
            relationship_repo.upsert(&relationship)?;

            let mut evidence = Evidence::new(
                &scan.id,
                EvidenceClass::Derived,
                &format!("{}_effective_permission", capability.provider),
                &capability.source_locator,
                &relationship_key,
                &format!(
                    "effective Bash permission: {}; scope: {}; runtime mode: {}",
                    capability.permission.as_str(),
                    capability.scope.as_str(),
                    capability.runtime_mode
                ),
                Sensitivity::Internal,
            )?;
            evidence.metadata = Some(capability_metadata.clone());
            evidence_repo.insert(&evidence)?;
            relationship_repo.link_evidence(&relationship.id, &evidence.id)?;

            // The shell:bash resource is shared by every agent capability, so it is
            // observed once (with the first capability's posture); per-agent
            // effective states live on the per-agent can_execute edges.
            if !bash_observed {
                let mut bash_observation = Observation::new(
                    &scan.id,
                    "resource",
                    &bash.id,
                    "present",
                    &format!("{}_adapter", capability.provider),
                )?;
                let mut snapshot = resource_snapshot_metadata(&bash);
                if let serde_json::Value::Object(fields) = &mut snapshot {
                    fields.insert("capability".to_string(), capability_metadata.clone());
                }
                bash_observation.metadata = Some(snapshot);
                observation_repo.insert(&bash_observation)?;
                bash_observed = true;
            }

            let mut relationship_observation = Observation::new(
                &scan.id,
                "relationship",
                &relationship.id,
                "effective_permission",
                &format!("{}_adapter", capability.provider),
            )?;
            relationship_observation.metadata = Some(relationship_snapshot_metadata(&relationship));
            observation_repo.insert(&relationship_observation)?;
            if bash_permission.is_none() {
                bash_permission = Some(capability.permission.as_str().to_string());
            }
            agent_bash_postures.push(AgentBashPosture {
                provider: capability.provider.to_string(),
                effective_state: capability.effective_state.as_str().to_string(),
            });
        }

        let mut github_mcp_observed = false;
        let mut influence_strength = None;
        let mut observed_mcp_servers: std::collections::BTreeSet<String> = Default::default();
        for surface in &discovered.github_surfaces {
            let Some(actor) = actor_resources.get(surface.server.provider) else {
                continue;
            };
            let provider = surface.server.provider;
            let agent_key = format!("agent:{provider}");
            github_mcp_observed = true;
            let server_key = "mcp:github:official".to_string();
            let mut server_resource = match resource_repo.get_by_canonical_key(&server_key)? {
                Some(resource) => resource,
                None => Resource::new(&server_key, "mcp_server", "github", "GitHub MCP")?,
            };
            server_resource.last_observed_at = chrono::Utc::now();
            server_resource.metadata = Some(serde_json::json!({
                "transport": surface.server.transport.as_str(),
                "enabled": surface.server.enabled,
                "identity": surface.server.safe_identity,
                "endpoint": surface.server.safe_endpoint,
                "environment_keys": surface.server.environment_keys,
                "discovery": format!("{provider}_v2_static"),
            }));
            resource_repo.upsert(&server_resource)?;
            if observed_mcp_servers.insert(server_key.clone()) {
                observe_resource(
                    &observation_repo,
                    &scan.id,
                    &server_resource,
                    "github_mcp_adapter",
                )?;
            }
            evidence_for_subject(
                &evidence_repo,
                &scan.id,
                EvidenceClass::Direct,
                &format!("{provider}_mcp_config"),
                &surface.server.source_locator,
                &server_key,
                if surface.server.enabled {
                    "supported GitHub MCP server configured and enabled"
                } else {
                    "supported GitHub MCP server configured but disabled"
                },
                serde_json::json!({
                    "transport": surface.server.transport.as_str(),
                    "identity": surface.server.safe_identity,
                    "endpoint": surface.server.safe_endpoint,
                    "environment_keys": surface.server.environment_keys,
                }),
            )?;
            let configured_explanation = if surface.server.enabled {
                format!(
                    "{} is configured with the supported GitHub MCP server",
                    agent_display_name(provider)
                )
            } else {
                format!(
                    "{} has a supported GitHub MCP server configured but disabled",
                    agent_display_name(provider)
                )
            };
            persist_influence_relationship(
                &relationship_repo,
                &evidence_repo,
                &observation_repo,
                &scan.id,
                actor,
                &server_resource,
                &format!("{agent_key}|configured_with|{server_key}"),
                "configured_with",
                if surface.server.enabled {
                    RelationshipState::Derived
                } else {
                    RelationshipState::Blocked
                },
                serde_json::json!({"enabled": surface.server.enabled, "transport": surface.server.transport.as_str()}),
                &configured_explanation,
                &surface.server.source_locator,
            )?;

            if !surface.server.enabled {
                continue;
            }

            for tool in &surface.tools {
                let tool_key = format!("{server_key}:tool:{}", tool.name);
                let mut tool_resource = match resource_repo.get_by_canonical_key(&tool_key)? {
                    Some(resource) => resource,
                    None => Resource::new(&tool_key, "mcp_tool", "github", &tool.name)?,
                };
                tool_resource.last_observed_at = chrono::Utc::now();
                // Mutable tools are consequential sinks: the mutation
                // authority path must terminate at the tool so the boundary
                // layer can surface the `can_mutate` edge. Set here (before
                // the resource observation is recorded) so projection sees
                // the Sink role.
                let is_mutable = tool.influence_strength == "AGENT_MUTABLE";
                tool_resource.metadata = Some(serde_json::json!({
                    "content_class": tool.content_class,
                    "trust": tool.trust,
                    "influence_strength": tool.influence_strength,
                    "discovery_tier": tool.discovery_tier,
                    "permission": tool.permission.as_str(),
                    "permission_pattern": tool.permission_pattern,
                    "consequential_sink": is_mutable,
                }));
                resource_repo.upsert(&tool_resource)?;
                observe_resource(
                    &observation_repo,
                    &scan.id,
                    &tool_resource,
                    "github_mcp_adapter",
                )?;
                evidence_for_subject(
                    &evidence_repo,
                    &scan.id,
                    if tool.discovery_tier == "DECLARED" {
                        EvidenceClass::Declared
                    } else {
                        EvidenceClass::Derived
                    },
                    "github_mcp_tool_contract",
                    &surface.server.source_locator,
                    &tool_key,
                    &format!("GitHub MCP exposes relevant retrieval tool {}", tool.name),
                    serde_json::json!({
                        "tool": tool.name,
                        "discovery_tier": tool.discovery_tier,
                        "content_class": tool.content_class,
                    }),
                )?;
                persist_influence_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    &server_resource,
                    &tool_resource,
                    &format!("{server_key}|exposes|{tool_key}"),
                    "exposes",
                    RelationshipState::Derived,
                    serde_json::json!({"discovery_tier": tool.discovery_tier}),
                    &format!("GitHub MCP exposes {}", tool.name),
                    &surface.server.source_locator,
                )?;
                let call_state = match tool.permission {
                    discovery::PermissionAction::Allow | discovery::PermissionAction::Ask => {
                        RelationshipState::Derived
                    }
                    discovery::PermissionAction::Deny => RelationshipState::Blocked,
                    discovery::PermissionAction::Unknown => RelationshipState::Unknown,
                };
                persist_influence_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    actor,
                    &tool_resource,
                    &format!("{agent_key}|can_call|{tool_key}"),
                    "can_call",
                    call_state,
                    serde_json::json!({
                        "permission": tool.permission.as_str(),
                        "permission_pattern": tool.permission_pattern,
                        "runtime_mode": "UNKNOWN",
                    }),
                    &format!(
                        "{} MCP permission for {} is {}",
                        agent_display_name(provider),
                        tool.name,
                        tool.permission.as_str()
                    ),
                    &surface.server.source_locator,
                )?;

                // Mutable tools carry an additional `can_mutate` capability
                // edge (in addition to the read `can_call` influence edge).
                // The tool resource is already marked a consequential sink so
                // the mutation authority path terminates and the boundary
                // layer can surface the edge as a mutation boundary. Reads
                // remain influence-only.
                if tool.influence_strength == "AGENT_MUTABLE" {
                    let can_mutate_key = format!("{agent_key}|can_mutate|{tool_key}");
                    persist_influence_relationship(
                        &relationship_repo,
                        &evidence_repo,
                        &observation_repo,
                        &scan.id,
                        actor,
                        &tool_resource,
                        &can_mutate_key,
                        "can_mutate",
                        RelationshipState::Derived,
                        serde_json::json!({
                            "influence_strength": tool.influence_strength,
                            "content_class": tool.content_class,
                            "trust": tool.trust,
                        }),
                        &format!(
                            "{} MCP permission for {} permits GitHub mutation",
                            agent_display_name(provider),
                            tool.name
                        ),
                        &surface.server.source_locator,
                    )?;
                }
                let content_key = format!("source:{}", tool.content_class);
                let content_name = match tool.content_class {
                    "github:public:issue-content" => "Public GitHub issue content",
                    "github:public:pull-request-content" => "Public GitHub pull-request content",
                    _ => "GitHub repository content",
                };
                let mut content_resource = match resource_repo.get_by_canonical_key(&content_key)? {
                    Some(resource) => resource,
                    None => Resource::new(&content_key, "external_source", "github", content_name)?,
                };
                content_resource.last_observed_at = chrono::Utc::now();
                content_resource.metadata = Some(serde_json::json!({
                    "trust": tool.trust,
                    "influence_strength": tool.influence_strength,
                    "content_class": tool.content_class,
                }));
                resource_repo.upsert(&content_resource)?;
                observe_resource(
                    &observation_repo,
                    &scan.id,
                    &content_resource,
                    "github_mcp_adapter",
                )?;
                influence_strength = Some(tool.influence_strength.to_string());
                persist_influence_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    &tool_resource,
                    &content_resource,
                    &format!("{tool_key}|can_retrieve|{content_key}"),
                    "can_retrieve",
                    RelationshipState::Derived,
                    serde_json::json!({
                        "trust": tool.trust,
                        "influence_strength": tool.influence_strength,
                    }),
                    &format!(
                        "{} can retrieve externally controlled GitHub content",
                        tool.name
                    ),
                    &surface.server.source_locator,
                )?;
            }
        }

        let mut cloudflare_credential_observed = false;
        let mut github_credential_observed = false;
        let mut github_credentials: Vec<crate::application::GitHubCredentialView> = Vec::new();
        let mut credential_reachability = None;
        let mut cloudflare_credential_status = None;
        let mut cloudflare_account_count = 0;
        let mut cloudflare_worker_count = 0;
        let mut worker_mutation_authority = None;
        let mut authority_resolution = None;
        for credential in &discovered.credentials {
            if credential.provider == "cloudflare" {
                cloudflare_credential_observed = true;
            }
            let credential_key = format!(
                "credential:{}:{}",
                credential.provider, credential.fingerprint
            );
            let credential_name = if credential.provider == "github" {
                "GitHub Token"
            } else {
                "Cloudflare API Token"
            };
            let fingerprint_version = if credential.provider == "github" {
                "sha256:pico-github-token-v1"
            } else {
                "sha256:pico-credential-v1"
            };
            let mut resource = match resource_repo.get_by_canonical_key(&credential_key)? {
                Some(resource) => resource,
                None => Resource::new(
                    &credential_key,
                    "credential",
                    credential.provider,
                    credential_name,
                )?,
            };
            resource.last_observed_at = chrono::Utc::now();
            let resource_metadata = serde_json::json!({
                "credential_type": credential.credential_type,
                "source_type": credential.source_type,
                "source_locator": credential.source_locator,
                "presence": "PRESENT",
                "validity": "UNKNOWN",
                "authority_resolution": "UNKNOWN",
                "environment_reachability": credential.environment.as_str(),
                "secret_stored": false,
                "fingerprint_version": fingerprint_version,
            });
            validate_secret_safe(&resource_metadata)?;
            resource.metadata = Some(resource_metadata);
            resource_repo.upsert(&resource)?;
            observe_resource(
                &observation_repo,
                &scan.id,
                &resource,
                &format!("{}_credential_adapter", credential.provider),
            )?;
            let reference_metadata = serde_json::json!({
                "provider": credential.provider,
                "credential_type": credential.credential_type,
                "source_type": credential.source_type,
                "source_locator": credential.source_locator,
                "presence": "PRESENT",
                "secret_stored": false,
            });
            validate_secret_safe(&reference_metadata)?;
            evidence_for_subject(
                &evidence_repo,
                &scan.id,
                EvidenceClass::Direct,
                &format!("{}_credential_reference", credential.provider),
                &credential.source_locator,
                &credential_key,
                &format!(
                    "supported {} credential reference is present",
                    credential.provider
                ),
                reference_metadata,
            )?;

            if let Some(bash) = bash_resource.as_ref() {
                let (state, reachability) =
                    match (credential.environment, discovered.bash_capabilities.first()) {
                        (discovery::EnvironmentReachability::Proven, Some(capability))
                            if capability.permission == discovery::PermissionAction::Allow
                                && capability.scope == discovery::CapabilityScope::Unrestricted =>
                        {
                            (RelationshipState::Derived, "REACHABLE")
                        }
                        (discovery::EnvironmentReachability::Proven, Some(capability))
                            if capability.permission == discovery::PermissionAction::Allow =>
                        {
                            (RelationshipState::Unknown, "UNKNOWN")
                        }
                        (discovery::EnvironmentReachability::Proven, Some(capability))
                            if capability.permission == discovery::PermissionAction::Ask
                                && capability.scope == discovery::CapabilityScope::Unrestricted =>
                        {
                            (RelationshipState::Derived, "APPROVAL_GATED")
                        }
                        (discovery::EnvironmentReachability::Proven, Some(capability))
                            if capability.permission == discovery::PermissionAction::Deny =>
                        {
                            (RelationshipState::Blocked, "BLOCKED")
                        }
                        _ => (RelationshipState::Unknown, "UNKNOWN"),
                    };
                credential_reachability = Some(reachability.to_string());
                let relationship_key = format!("shell:bash|can_access|{}", credential_key);
                let relationship_metadata = serde_json::json!({
                    "reachability": reachability,
                    "effective_bash_permission": discovered
                        .bash_capabilities
                        .first()
                        .map(|capability| capability.permission.as_str())
                        .unwrap_or("UNKNOWN"),
                    "environment_reachability": credential.environment.as_str(),
                    "runtime_mode": "UNKNOWN",
                    "validity": "UNKNOWN",
                    "authority_resolution": "UNKNOWN",
                });
                validate_secret_safe(&relationship_metadata)?;
                persist_credential_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    bash,
                    &resource,
                    &relationship_key,
                    state,
                    relationship_metadata,
                    &format!("Bash credential reachability is {reachability}"),
                    &credential.source_locator,
                    credential.provider,
                )?;
            } else {
                credential_reachability = Some("UNKNOWN".to_string());
            }

            // The provider adapter is invoked upstream of ScanService and
            // emits only safe normalized facts. Persist those facts here once
            // local reachability has been established; this keeps provider
            // parsing and credential handling out of the application layer.
            let provider_result = discovered
                .cloudflare
                .as_ref()
                .filter(|result| {
                    result.credential_fingerprint == credential.fingerprint
                        && matches!(credential_reachability.as_deref(), Some("REACHABLE"))
                })
                .cloned();
            if let Some(provider_result) = provider_result {
                if !provider_result.problems.is_empty() {
                    discovered
                        .problems
                        .extend(provider_result.problems.iter().cloned());
                }
                let summary = persist_cloudflare_provider_result(
                    &provider_result,
                    &credential_key,
                    &resource,
                    &scan.id,
                    &resource_repo,
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                )?;
                cloudflare_credential_status = summary.credential_status;
                cloudflare_account_count = summary.account_count;
                cloudflare_worker_count = summary.worker_count;
                worker_mutation_authority = summary.worker_mutation_authority;
                authority_resolution = summary.authority_resolution;
            }

            // GitHub repository mutation authority (SPRINT-021). Purely
            // additive: builds a provider-scoped repository resource and emits
            // `can_mutate` ONLY when write authority is evidenced (EXACT or
            // SCOPED); otherwise a read `can_access` edge. No cross-provider
            // leakage and no duplicate edges with the Cloudflare branch.
            if credential.provider == "github" {
                github_credential_observed = true;
                let github_result = discovered
                    .github
                    .as_ref()
                    .filter(|result| result.credential_fingerprint == credential.fingerprint);
                if let Some(result) = github_result {
                    if !result.problems.is_empty() {
                        discovered.problems.extend(result.problems.iter().cloned());
                    }
                }
                let repo_key = "github:repository";
                let mut repo_resource = match resource_repo.get_by_canonical_key(repo_key)? {
                    Some(resource) => resource,
                    None => Resource::new(repo_key, "repository", "github", "GitHub Repository")?,
                };
                repo_resource.last_observed_at = chrono::Utc::now();
                repo_resource.metadata = Some(serde_json::json!({
                    "provider": "github",
                    "authority_resolution": github_result
                        .map(|result| result.resolution.as_str())
                        .unwrap_or(
                            discovery::cloudflare::AuthorityResolution::Unknown.as_str(),
                        ),
                }));
                validate_secret_safe(repo_resource.metadata.as_ref().expect("metadata set"))?;
                resource_repo.upsert(&repo_resource)?;
                observe_resource(
                    &observation_repo,
                    &scan.id,
                    &repo_resource,
                    "github_credential_adapter",
                )?;

                let (state, resolution, permission_state, unknown_reasons, credential_type) =
                    match github_result {
                        Some(result) => (
                            result.state,
                            result.resolution,
                            result.permission_state.clone(),
                            result.unknown_reasons.clone(),
                            result
                                .credential_type
                                .clone()
                                .unwrap_or_else(|| credential.credential_type.to_string()),
                        ),
                        None => {
                            let offline = discovery::github::GitHubAuthorityResult::offline(
                                &credential.fingerprint,
                                Some(credential.credential_type),
                            );
                            (
                                offline.state,
                                offline.resolution,
                                offline.permission_state,
                                offline.unknown_reasons,
                                credential.credential_type.to_string(),
                            )
                        }
                    };
                let can_mutate = matches!(
                    resolution,
                    discovery::cloudflare::AuthorityResolution::Exact
                        | discovery::cloudflare::AuthorityResolution::Scoped
                );
                let kind = if can_mutate {
                    "can_mutate"
                } else {
                    "can_access"
                };
                github_credentials.push(crate::application::GitHubCredentialView {
                    credential_type: credential_type.clone(),
                    authority_resolution: resolution.as_str().to_string(),
                    permission_state: permission_state.clone(),
                    unknown_reasons: unknown_reasons.clone(),
                });
                let relationship_key = format!("{credential_key}|{kind}|{repo_key}");
                let metadata = serde_json::json!({
                    "provider": "github",
                    "credential_type": credential_type,
                    "authority_resolution": resolution.as_str(),
                    "permission_state": permission_state,
                    "unknown_reasons": unknown_reasons,
                });
                persist_github_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    &resource,
                    &repo_resource,
                    &relationship_key,
                    kind,
                    state,
                    metadata,
                    if can_mutate {
                        "GitHub credential scope evidence resolved repository mutation authority"
                    } else {
                        "GitHub credential carries read access to repositories"
                    },
                    github_result
                        .map(|result| result.source_locator.as_str())
                        .unwrap_or("github:scope_probe:offline"),
                )?;
            }
        }

        let resources = resource_repo.list()?;
        let relationships = relationship_repo.list()?;
        let observations = observation_repo.list_for_scan(&scan.id)?;
        let evidence = evidence_repo.list()?;
        let relationship_evidence = relationship_repo.evidence_links()?;
        let graph = match project(ProjectionInput {
            scan_id: &scan.id,
            snapshot_version: GRAPH_SNAPSHOT_VERSION as u32,
            resources: &resources,
            relationships: &relationships,
            observations: &observations,
            evidence: &evidence,
            relationship_evidence: &relationship_evidence,
        }) {
            Ok(graph) => graph,
            Err(error) => {
                let failed = scan.fail()?;
                scan_repo.update(&failed)?;
                return Err(PicoError::scan(format!("graph projection failed: {error}")));
            }
        };
        let graph_projection_status = if graph.nodes.is_empty() {
            "EMPTY".to_string()
        } else {
            "PROJECTED".to_string()
        };
        let graph_node_count = graph.nodes.len() as u64;
        let graph_edge_count = graph.edges.len() as u64;
        let state_eligible_edge_count = graph
            .edges
            .iter()
            .filter(|edge| edge.usability.is_traversable())
            .count() as u64;
        let non_eligible_edge_count = graph_edge_count - state_eligible_edge_count;

        let discovery_status = if discovered.problems.is_empty() {
            ScanStatus::Complete
        } else {
            ScanStatus::Partial
        };
        let analysis =
            analyze_with_scan_status(&graph, &AnalysisLimits::default(), discovery_status);
        if let Err(error) = persist_analysis_results(db.connection(), &analysis) {
            let failed = scan.fail()?;
            scan_repo.update(&failed)?;
            return Err(error);
        }
        if analysis.status == AnalysisStatus::Failed {
            let failed = scan.fail()?;
            scan_repo.update(&failed)?;
            return Err(PicoError::scan(
                "deterministic analysis failed integrity validation",
            ));
        }

        let desired_status =
            if analysis.status == AnalysisStatus::Limited || !discovered.problems.is_empty() {
                ScanStatus::Partial
            } else {
                ScanStatus::Complete
            };
        let findings =
            generate_with_scan_status(&graph, &analysis, desired_status, &FindingLimits::default());
        if findings.status == FindingGenerationStatus::Failed {
            let failed = scan.fail()?;
            scan_repo.update(&failed)?;
            return Err(PicoError::scan(
                "deterministic Finding generation failed integrity validation",
            ));
        }
        if let Err(error) = persist_finding_results(db.connection(), &findings) {
            let failed = scan.fail()?;
            scan_repo.update(&failed)?;
            return Err(error);
        }
        let completed = if desired_status == ScanStatus::Partial
            || findings.status == FindingGenerationStatus::Limited
        {
            scan.partial()?
        } else {
            scan.complete()?
        };
        scan_repo.update(&completed)?;

        let provider_statuses = build_provider_statuses(
            &discovered.problems,
            actor_resources
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            discovered.cloudflare.as_ref(),
            discovered.github.as_ref(),
            github_credential_observed,
        );
        let partial_reason = provider_statuses
            .iter()
            .find(|status| !status.reachable)
            .map(|status| status.name.clone());
        let (suppressed, reduced_confidence) =
            eligibility_diagnostics(&graph, &analysis, desired_status, &findings.findings);
        let diagnostics_detail = ScanDiagnostics {
            provider_statuses,
            scan_status: desired_status.as_str().to_string(),
            partial_reason,
            suppressed,
            reduced_confidence,
        };

        persist_scan_diagnostics(db.connection(), &completed.id, &diagnostics_detail)?;

        let resource_count = resource_repo.count()?;
        let relationship_count = relationship_repo.count()?;
        let evidence_count = evidence_repo.count()?;

        Ok(ScanResult {
            scan_id: completed.id,
            status: completed.status,
            started_at: completed.started_at,
            completed_at: completed.completed_at,
            resource_count,
            agent_count: actor_resources.len() as u64,
            relationship_count,
            evidence_count,
            finding_count: findings.findings.len() as u64,
            finding_class: findings
                .findings
                .first()
                .map(|finding| finding.finding_class.as_str().to_string()),
            finding_severity: findings
                .findings
                .first()
                .map(|finding| finding.severity.as_str().to_string()),
            finding_confidence: findings
                .findings
                .first()
                .map(|finding| finding.confidence.as_str().to_string()),
            findings: Some(findings),
            bash_permission,
            agent_bash_postures,
            github_mcp_observed,
            influence_strength,
            cloudflare_credential_observed,
            credential_reachability,
            cloudflare_credential_status,
            cloudflare_account_count,
            cloudflare_worker_count,
            worker_mutation_authority,
            authority_resolution,
            graph: Some(graph),
            analysis: Some(analysis.clone()),
            graph_projection_status,
            graph_node_count,
            graph_edge_count,
            state_eligible_edge_count,
            non_eligible_edge_count,
            analysis_status: analysis.status.as_str().to_string(),
            analysis_disposition: match analysis.candidate_disposition {
                CandidateDisposition::Active => "ACTIVE_PRESENT",
                CandidateDisposition::Blocked => "BLOCKED_ONLY",
                CandidateDisposition::Unresolved => "UNRESOLVED_PRESENT",
                CandidateDisposition::None => "NONE",
            }
            .to_string(),
            influence_path_count: analysis.influence_paths.len() as u64,
            authority_path_count: analysis.authority_paths.len() as u64,
            active_attack_path_count: analysis
                .attack_paths
                .iter()
                .filter(|path| path.disposition == CandidateDisposition::Active)
                .count() as u64,
            blocked_attack_path_count: analysis
                .attack_paths
                .iter()
                .filter(|path| path.disposition == CandidateDisposition::Blocked)
                .count() as u64,
            unresolved_candidate_count: analysis.unresolved_candidate_count as u64,
            diagnostics_detail: Some(diagnostics_detail),
            github_credentials,
        })
    }
}

/// Human-readable agent name for an adapter provider. The OpenCode golden path
/// keeps its exact "OpenCode" display name.
fn agent_display_name(provider: &str) -> String {
    match provider {
        "opencode" => "OpenCode".to_string(),
        "claude" => "Claude Code".to_string(),
        other => other.to_string(),
    }
}

/// Persist the structured, machine-readable scan diagnostics (SPRINT-019).
///
/// The diagnostics are a scan-scoped projection over already-sanitized discovery
/// facts; `validate_secret_safe` is applied defensively so a secret-shaped value
/// can never be written into the diagnostics blob.
fn persist_scan_diagnostics(
    connection: &rusqlite::Connection,
    scan_id: &str,
    detail: &ScanDiagnostics,
) -> Result<(), PicoError> {
    let value = serde_json::to_value(detail).map_err(|error| {
        PicoError::scan(format!("scan diagnostics serialization failed: {error}"))
    })?;
    validate_secret_safe(&value)?;
    let text = serde_json::to_string(&value)
        .map_err(|error| PicoError::scan(format!("scan diagnostics encoding failed: {error}")))?;
    ScanDiagnosticsRepo::new(connection).upsert(scan_id, &text)?;
    Ok(())
}

fn persist_finding_results(
    connection: &rusqlite::Connection,
    results: &FindingResult,
) -> Result<(), PicoError> {
    let repo = FindingRepo::new(connection);
    for finding in &results.findings {
        repo.insert(&FindingRecord {
            id: finding.id.clone(),
            scan_id: finding.scan_id.clone(),
            fingerprint: finding.fingerprint.clone(),
            finding_version: finding.finding_version.to_string(),
            finding_class: finding.finding_class.as_str().to_string(),
            title: finding.title.clone(),
            summary: finding.summary.clone(),
            severity: finding.severity.as_str().to_string(),
            confidence: finding.confidence.as_str().to_string(),
            status: finding.status.as_str().to_string(),
            metadata: None,
            created_at: finding.created_at,
        })?;
        for (position, attack_path_id) in finding.attack_path_ids.iter().enumerate() {
            repo.insert_path(&FindingPathRecord {
                finding_id: finding.id.clone(),
                attack_path_id: attack_path_id.clone(),
                position: position as u32,
            })?;
        }
        let production_evidence = finding
            .reasons
            .iter()
            .filter(|reason| reason.code.as_str() == "PRODUCTION_MUTATION_AUTHORITY")
            .flat_map(|reason| reason.evidence_ids.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        for (position, evidence_id) in finding.evidence_ids.iter().enumerate() {
            repo.insert_evidence(&FindingEvidenceRecord {
                finding_id: finding.id.clone(),
                evidence_id: evidence_id.clone(),
                position: position as u32,
                support_role: if production_evidence.contains(evidence_id) {
                    "SINK_CLASSIFICATION".to_string()
                } else {
                    "SUPPORTING".to_string()
                },
            })?;
        }
        for (position, reason) in finding.reasons.iter().enumerate() {
            repo.insert_reason(&FindingReasonRecord {
                finding_id: finding.id.clone(),
                position: position as u32,
                reason_code: reason.code.as_str().to_string(),
                resource_ids: reason.resource_ids.clone(),
                relationship_ids: reason.relationship_ids.clone(),
                attack_path_ids: finding.attack_path_ids.clone(),
                evidence_ids: reason.evidence_ids.clone(),
            })?;
        }
        for (position, remediation) in finding.remediations.iter().enumerate() {
            repo.insert_remediation(&FindingRemediationRecord {
                finding_id: finding.id.clone(),
                position: position as u32,
                rule_id: remediation.rule_id.clone(),
                title: remediation.title.clone(),
                description: remediation.description.clone(),
                security_effect: remediation.security_effect.clone(),
                cut_phase: remediation.cut_phase.clone(),
                target_resource_ids: remediation.target_resource_ids.clone(),
                target_relationship_ids: remediation.target_relationship_ids.clone(),
            })?;
        }
    }
    Ok(())
}

/// Reconstruct per-provider reachability diagnostics from a `DiscoveryResult`.
///
/// Each discovered agent adapter reports its problems on the aggregate
/// `DiscoveryResult::problems` field, prefixed with the exact source locator
/// that produced them; the Cloudflare provider adapter keeps its own sanitized
/// `problems` list on `ProviderResult`. Cloudflare problems are merged into the
/// aggregate only when the credential is reachable, so each agent's problems are
/// reconstructed by matching the locator prefix. A `ProviderDiagnostic` is
/// emitted for every provider that produced a discovered actor or an
/// attributable problem; Cloudflare is appended whenever a provider result was
/// observed. All lists are already sanitized by the discovery layer.
fn build_provider_statuses(
    problems: &[String],
    actor_providers: &[&str],
    cloudflare: Option<&discovery::cloudflare::ProviderResult>,
    github: Option<&discovery::github::GitHubAuthorityResult>,
    github_observed: bool,
) -> Vec<ProviderDiagnostic> {
    let cloudflare_problems: Vec<String> = cloudflare
        .map(|result| result.problems.clone())
        .unwrap_or_default();
    let github_problems: Vec<String> = github
        .map(|result| result.problems.clone())
        .unwrap_or_default();
    let mut providers: std::collections::BTreeSet<&str> = actor_providers.iter().copied().collect();
    for problem in problems {
        if !cloudflare_problems.contains(problem) && !github_problems.contains(problem) {
            if let Some(provider) = problem_provider(problem) {
                providers.insert(provider);
            }
        }
    }
    let mut statuses = Vec::new();
    for provider in providers {
        let provider_problems: Vec<String> = problems
            .iter()
            .filter(|problem| {
                !cloudflare_problems.contains(problem)
                    && !github_problems.contains(problem)
                    && problem_belongs_to(problem, provider)
            })
            .cloned()
            .collect();
        statuses.push(ProviderDiagnostic {
            name: provider.to_string(),
            reachable: provider_problems.is_empty(),
            problems: provider_problems,
        });
    }
    if let Some(cloudflare) = cloudflare {
        statuses.push(ProviderDiagnostic {
            name: "cloudflare".to_string(),
            reachable: cloudflare.problems.is_empty(),
            problems: cloudflare.problems.clone(),
        });
    }
    if github_observed {
        statuses.push(ProviderDiagnostic {
            name: "github".to_string(),
            reachable: github_problems.is_empty(),
            problems: github_problems,
        });
    }
    statuses
}

/// Attribute a discovery problem to the agent provider that produced it. Every
/// adapter prefixes its problems with the exact source locator, so the prefix
/// is the stable attribution key.
fn problem_provider(problem: &str) -> Option<&'static str> {
    if problem.starts_with("user:opencode")
        || problem.starts_with("project:opencode")
        || problem.starts_with("project:.opencode")
    {
        Some("opencode")
    } else if problem.starts_with("user:.claude")
        || problem.starts_with("project:.claude")
        || problem.starts_with("project:.mcp.json")
    {
        Some("claude")
    } else {
        None
    }
}

fn problem_belongs_to(problem: &str, provider: &str) -> bool {
    match provider {
        "opencode" => {
            problem.starts_with("user:opencode")
                || problem.starts_with("project:opencode")
                || problem.starts_with("project:.opencode")
        }
        "claude" => {
            problem.starts_with("user:.claude")
                || problem.starts_with("project:.claude")
                || problem.starts_with("project:.mcp.json")
        }
        _ => true,
    }
}

fn persist_analysis_results(
    connection: &rusqlite::Connection,
    analysis: &AnalysisResult,
) -> Result<(), PicoError> {
    let active_count = analysis
        .attack_paths
        .iter()
        .filter(|path| path.disposition == CandidateDisposition::Active)
        .count() as u64;
    let blocked_count = analysis
        .attack_paths
        .iter()
        .filter(|path| path.disposition == CandidateDisposition::Blocked)
        .count() as u64;
    let overall = if analysis.status != AnalysisStatus::Complete {
        None
    } else {
        Some(
            match analysis.candidate_disposition {
                CandidateDisposition::Active => "ACTIVE_PRESENT",
                CandidateDisposition::Blocked => "BLOCKED_ONLY",
                CandidateDisposition::Unresolved => "UNRESOLVED_PRESENT",
                CandidateDisposition::None => "NONE",
            }
            .to_string(),
        )
    };
    let summary = ScanAnalysisRecord {
        scan_id: analysis.scan_id.clone(),
        analysis_version: analysis.analysis_version.to_string(),
        status: analysis.status.as_str().to_string(),
        overall_disposition: overall,
        influence_path_count: analysis.influence_paths.len() as u64,
        authority_path_count: analysis.authority_paths.len() as u64,
        active_path_count: active_count,
        blocked_path_count: blocked_count,
        unresolved_candidate_count: analysis.unresolved_candidate_count as u64,
        limit_reasons: None,
        diagnostics: Some(serde_json::json!(analysis.diagnostics)),
        created_at: Utc::now(),
    };
    ScanAnalysisRepo::new(connection).upsert(&summary)?;

    if analysis.status != AnalysisStatus::Complete {
        return Ok(());
    }
    let paths = AttackPathRepo::new(connection);
    for path in &analysis.attack_paths {
        let boundary_metadata =
            serde_json::to_value(&path.boundary_evaluations).map_err(|error| {
                PicoError::scan(format!("analysis boundary serialization failed: {error}"))
            })?;
        paths.insert(&AttackPathRecord {
            id: path.id.clone(),
            scan_id: path.scan_id.clone(),
            fingerprint: path.fingerprint.clone(),
            analysis_version: path.analysis_version.to_string(),
            source_resource_id: path.source_resource_id.clone(),
            actor_resource_id: path.actor_resource_id.clone(),
            sink_resource_id: path.sink_resource_id.clone(),
            disposition: path.disposition.as_str().to_string(),
            source_trust: path.source_trust.as_str().to_string(),
            influence_strength: path.influence_strength.as_str().to_string(),
            capability: path.capability.as_str().to_string(),
            authority_resolution: path.authority_resolution.as_str().to_string(),
            sink_impact: path.sink_impact.as_str().to_string(),
            boundary_metadata: Some(boundary_metadata),
            created_at: Utc::now(),
        })?;
        for (position, edge) in path
            .influence_edges
            .iter()
            .chain(path.authority_edges.iter())
            .enumerate()
        {
            paths.insert_edge(&AttackPathEdgeRecord {
                attack_path_id: path.id.clone(),
                relationship_id: edge.relationship_id.clone(),
                position: position as u32,
                phase: edge.phase.as_str().to_string(),
                traversal: edge.traversal.as_str().to_string(),
            })?;
        }
        let boundary_evidence = path
            .boundary_evaluations
            .iter()
            .flat_map(|boundary| boundary.evidence_ids.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        for (position, evidence_id) in path.evidence_ids.iter().enumerate() {
            paths.insert_evidence(&AttackPathEvidenceRecord {
                attack_path_id: path.id.clone(),
                evidence_id: evidence_id.clone(),
                position: position as u32,
                support_role: if boundary_evidence.contains(evidence_id) {
                    "BOUNDARY".to_string()
                } else {
                    "EDGE".to_string()
                },
            })?;
        }
    }
    Ok(())
}

/// Safe summary emitted by persistence of one normalized Cloudflare result.
#[derive(Debug, Default)]
struct CloudflarePersistenceSummary {
    credential_status: Option<String>,
    account_count: u64,
    worker_count: u64,
    worker_mutation_authority: Option<String>,
    authority_resolution: Option<String>,
}

/// Accept only the bounded normalized sink classifications that the provider
/// seam is allowed to carry. Missing or unsupported values remain UNKNOWN;
/// Worker names and account metadata never participate in classification.
fn normalize_sink_impact(value: Option<&str>) -> &'static str {
    match value {
        Some("PRODUCTION") => "PRODUCTION",
        Some("STAGING") => "STAGING",
        Some("LOCAL_DEV") => "LOCAL_DEV",
        Some("UNKNOWN") => "UNKNOWN",
        _ => "UNKNOWN",
    }
}

/// Persist a normalized provider result into Pico's generic Resource,
/// Relationship, Evidence, and Observation contracts. This function accepts
/// no raw provider response and never constructs an authorization header.
#[allow(clippy::too_many_arguments)]
fn persist_cloudflare_provider_result(
    result: &discovery::cloudflare::ProviderResult,
    credential_key: &str,
    credential: &Resource,
    scan_id: &str,
    resources: &ResourceRepo<'_>,
    relationships: &RelationshipRepo<'_>,
    evidence: &EvidenceRepo<'_>,
    observations: &ObservationRepo<'_>,
) -> Result<CloudflarePersistenceSummary, PicoError> {
    use discovery::cloudflare::{AuthorityResolution, ScopeState};

    let status = result
        .credential_status
        .map(|value| value.as_str().to_string());
    // The safe credential_type projection was stored on the credential Resource
    // by the ScanService; carry it onto the Worker mutation relationship so the
    // persisted authority records what kind of credential produced it.
    let credential_type = credential
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("credential_type"))
        .and_then(|value| value.as_str())
        .unwrap_or("api_token")
        .to_string();
    // Refresh only safe provider status on the already-normalized credential
    // Resource. The token identifier and raw provider response remain
    // transient and are deliberately not persisted here.
    let mut credential_resource = credential.clone();
    let mut credential_metadata = credential_resource
        .metadata
        .take()
        .unwrap_or_else(|| serde_json::json!({}));
    if let serde_json::Value::Object(fields) = &mut credential_metadata {
        fields.insert(
            "validity".to_string(),
            serde_json::Value::String(status.clone().unwrap_or_else(|| "UNKNOWN".to_string())),
        );
        fields.insert(
            "provider_authority_observed".to_string(),
            serde_json::Value::Bool(true),
        );
    }
    validate_secret_safe(&credential_metadata)?;
    credential_resource.metadata = Some(credential_metadata);
    credential_resource.last_observed_at = chrono::Utc::now();
    resources.upsert(&credential_resource)?;
    let credential = &credential_resource;
    let mut summary = CloudflarePersistenceSummary {
        credential_status: status.clone(),
        ..CloudflarePersistenceSummary::default()
    };

    let credential_status = status.as_deref().unwrap_or("UNKNOWN");
    for account in &result.accounts {
        let account_key = format!("cloudflare:account:{}", account.account_id);
        let account_name = account
            .name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("Cloudflare Account");
        let mut resource = match resources.get_by_canonical_key(&account_key)? {
            Some(resource) => resource,
            None => Resource::new(&account_key, "provider_account", "cloudflare", account_name)?,
        };
        resource.last_observed_at = chrono::Utc::now();
        resource.metadata = Some(serde_json::json!({
            "account_id": account.account_id,
            "account_type": account.account_type,
            "environment": "UNKNOWN",
            "source": "cloudflare_api",
            "scope_state": account.scope.as_str(),
        }));
        validate_secret_safe(resource.metadata.as_ref().expect("metadata set"))?;
        resources.upsert(&resource)?;
        observe_resource(observations, scan_id, &resource, "cloudflare_provider")?;
        evidence_for_subject(
            evidence,
            scan_id,
            EvidenceClass::Direct,
            "cloudflare_account_inventory",
            &account.source_locator,
            &account_key,
            "Cloudflare account observed through the bounded account inventory operation",
            serde_json::json!({
                "account_id": account.account_id,
                "scope_state": account.scope.as_str(),
            }),
        )?;

        let state = match account.scope {
            ScopeState::InScope => RelationshipState::Derived,
            ScopeState::OutOfScope => RelationshipState::Blocked,
            ScopeState::Unknown => RelationshipState::Unknown,
        };
        let relationship_key = format!("{credential_key}|scoped_to|{account_key}");
        let metadata = serde_json::json!({
            "scope_state": account.scope.as_str(),
            "credential_status": credential_status,
            "authority_resolution": "UNKNOWN",
        });
        persist_cloudflare_relationship(
            relationships,
            evidence,
            observations,
            scan_id,
            credential,
            &resource,
            &relationship_key,
            "scoped_to",
            state,
            metadata,
            "Cloudflare token policy account scope was normalized by the provider adapter",
            &account.source_locator,
        )?;
        summary.account_count += 1;
    }

    for worker in &result.workers {
        let worker_key = worker.canonical_key();
        let sink_impact = normalize_sink_impact(worker.sink_impact.as_deref());
        let mut resource = match resources.get_by_canonical_key(&worker_key)? {
            Some(resource) => resource,
            None => Resource::new(&worker_key, "worker", "cloudflare", &worker.script_name)?,
        };
        resource.last_observed_at = chrono::Utc::now();
        resource.metadata = Some(serde_json::json!({
            "account_id": worker.account_id,
            "worker_tag": worker.worker_tag,
            "identity_precision": worker.identity_precision(),
            "environment": sink_impact,
            "sink_impact": sink_impact,
            "consequential_sink": true,
            "source": "cloudflare_api",
        }));
        validate_secret_safe(resource.metadata.as_ref().expect("metadata set"))?;
        resources.upsert(&resource)?;
        observe_resource(observations, scan_id, &resource, "cloudflare_provider")?;
        evidence_for_subject(
            evidence,
            scan_id,
            EvidenceClass::Direct,
            "cloudflare_worker_inventory",
            &worker.source_locator,
            &worker_key,
            "Cloudflare Worker observed through the bounded Worker inventory operation",
            serde_json::json!({
                "account_id": worker.account_id,
                "worker_identity": worker_key,
                "identity_precision": worker.identity_precision(),
                "sink_impact": sink_impact,
            }),
        )?;
        summary.worker_count += 1;

        // The provider emits one authority observation per enumerated Worker.
        // A missing observation is intentionally not upgraded to write access.
        if let Some(authority) = result.authorities.iter().find(|candidate| {
            candidate.worker_key == worker_key && candidate.account_id == worker.account_id
        }) {
            let relationship_key = format!("{credential_key}|can_mutate|{worker_key}");
            let metadata = serde_json::json!({
                "capability": "WORKERS_SCRIPTS_WRITE",
                "authority_resolution": authority.resolution.as_str(),
                "credential_status": credential_status,
                "permission_state": authority.permission_state,
                "account_scope_state": authority.scope_state.as_str(),
                "target_observation_state": "OBSERVED",
                "sink_impact": sink_impact,
                "credential_type": credential_type,
                "granted_permissions": authority.granted_permissions,
                "zone_scoped": authority.zone_scoped,
                "unknown_reasons": authority.unknown_reasons,
            });
            persist_cloudflare_relationship(
                relationships,
                evidence,
                observations,
                scan_id,
                credential,
                &resource,
                &relationship_key,
                "can_mutate",
                authority.state,
                metadata,
                "Cloudflare read-only policy and scope evidence resolved Worker mutation authority",
                &authority.source_locator,
            )?;
            summary.worker_mutation_authority = Some(
                match authority.state {
                    RelationshipState::Derived => "CONFIRMED",
                    RelationshipState::Blocked => "BLOCKED",
                    _ => "UNKNOWN",
                }
                .to_string(),
            );
            summary.authority_resolution = Some(authority.resolution.as_str().to_string());
        } else if result.credential_status
            != Some(discovery::cloudflare::CredentialStatus::Inactive)
        {
            let relationship_key = format!("{credential_key}|can_mutate|{worker_key}");
            let metadata = serde_json::json!({
                "capability": "WORKERS_SCRIPTS_WRITE",
                "authority_resolution": AuthorityResolution::Unknown.as_str(),
                "credential_status": credential_status,
                "credential_type": credential_type,
                "granted_permissions": serde_json::Value::Array(Vec::new()),
                "zone_scoped": false,
                "unknown_reasons": ["AUTHORITY_RESULT_UNAVAILABLE"],
            });
            persist_cloudflare_relationship(
                relationships,
                evidence,
                observations,
                scan_id,
                credential,
                &resource,
                &relationship_key,
                "can_mutate",
                RelationshipState::Unknown,
                metadata,
                "Worker observed but Cloudflare mutation authority was not resolved",
                &worker.source_locator,
            )?;
            summary.worker_mutation_authority = Some("UNKNOWN".to_string());
            summary.authority_resolution = Some(AuthorityResolution::Unknown.as_str().to_string());
        }
    }

    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn persist_cloudflare_relationship(
    relationships: &RelationshipRepo<'_>,
    evidence: &EvidenceRepo<'_>,
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    from: &Resource,
    to: &Resource,
    key: &str,
    kind: &str,
    state: RelationshipState,
    metadata: serde_json::Value,
    explanation: &str,
    locator: &str,
) -> Result<(), PicoError> {
    validate_secret_safe(&metadata)?;
    let mut relationship = match relationships.get_by_canonical_key(key)? {
        Some(relationship) => relationship,
        None => Relationship::new(key, &from.id, &to.id, kind, state)?,
    };
    relationship.state = state;
    relationship.last_observed_at = chrono::Utc::now();
    relationship.metadata = Some(metadata.clone());
    relationships.upsert(&relationship)?;

    let mut item = Evidence::new(
        scan_id,
        EvidenceClass::Derived,
        "cloudflare_authority_resolution",
        locator,
        key,
        explanation,
        Sensitivity::Internal,
    )?;
    item.metadata = Some(metadata.clone());
    evidence.insert(&item)?;
    relationships.link_evidence(&relationship.id, &item.id)?;

    let mut observation = Observation::new(
        scan_id,
        "relationship",
        &relationship.id,
        "observed",
        "cloudflare_provider",
    )?;
    observation.metadata = Some(relationship_snapshot_metadata(&relationship));
    observations.insert(&observation)
}

#[allow(clippy::too_many_arguments)]
fn persist_github_relationship(
    relationships: &RelationshipRepo<'_>,
    evidence: &EvidenceRepo<'_>,
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    from: &Resource,
    to: &Resource,
    key: &str,
    kind: &str,
    state: RelationshipState,
    metadata: serde_json::Value,
    explanation: &str,
    locator: &str,
) -> Result<(), PicoError> {
    validate_secret_safe(&metadata)?;
    let mut relationship = match relationships.get_by_canonical_key(key)? {
        Some(relationship) => relationship,
        None => Relationship::new(key, &from.id, &to.id, kind, state)?,
    };
    relationship.state = state;
    relationship.last_observed_at = chrono::Utc::now();
    relationship.metadata = Some(metadata.clone());
    relationships.upsert(&relationship)?;

    let mut item = Evidence::new(
        scan_id,
        EvidenceClass::Derived,
        "github_authority_resolution",
        locator,
        key,
        explanation,
        Sensitivity::Internal,
    )?;
    item.metadata = Some(metadata.clone());
    evidence.insert(&item)?;
    relationships.link_evidence(&relationship.id, &item.id)?;

    let mut observation = Observation::new(
        scan_id,
        "relationship",
        &relationship.id,
        "observed",
        "github_credential_adapter",
    )?;
    observation.metadata = Some(relationship_snapshot_metadata(&relationship));
    observations.insert(&observation)
}

fn validate_secret_safe(value: &serde_json::Value) -> Result<(), PicoError> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, nested) in object {
                let lower = key.to_ascii_lowercase();
                if lower.contains("raw")
                    || lower.contains("password")
                    || lower.contains("authorization")
                    || lower.contains("private_key")
                    || lower == "token_value"
                {
                    return Err(PicoError::scan(format!(
                        "secret-safety validation rejected metadata field {key}"
                    )));
                }
                validate_secret_safe(nested)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                validate_secret_safe(item)?;
            }
        }
        serde_json::Value::String(value) if crate::shared::looks_like_token_value(value) => {
            return Err(PicoError::scan(
                "secret-safety validation rejected a token-shaped value".to_string(),
            ));
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_credential_relationship(
    relationships: &RelationshipRepo<'_>,
    evidence: &EvidenceRepo<'_>,
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    from: &Resource,
    to: &Resource,
    key: &str,
    state: RelationshipState,
    metadata: serde_json::Value,
    explanation: &str,
    locator: &str,
    provider: &str,
) -> Result<(), PicoError> {
    validate_secret_safe(&metadata)?;
    let mut relationship = match relationships.get_by_canonical_key(key)? {
        Some(relationship) => relationship,
        None => Relationship::new(key, &from.id, &to.id, "can_access", state)?,
    };
    relationship.state = state;
    relationship.last_observed_at = chrono::Utc::now();
    relationship.metadata = Some(metadata.clone());
    relationships.upsert(&relationship)?;
    let mut item = Evidence::new(
        scan_id,
        EvidenceClass::Derived,
        &format!("{provider}_credential_reachability"),
        locator,
        key,
        explanation,
        Sensitivity::Internal,
    )?;
    item.metadata = Some(metadata.clone());
    evidence.insert(&item)?;
    relationships.link_evidence(&relationship.id, &item.id)?;
    let mut observation = Observation::new(
        scan_id,
        "relationship",
        &relationship.id,
        "observed",
        &format!("{provider}_credential_adapter"),
    )?;
    observation.metadata = Some(relationship_snapshot_metadata(&relationship));
    observations.insert(&observation)
}

fn observe_resource(
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    resource: &Resource,
    source: &str,
) -> Result<(), PicoError> {
    let mut observation = Observation::new(scan_id, "resource", &resource.id, "present", source)?;
    observation.metadata = Some(resource_snapshot_metadata(resource));
    observations.insert(&observation)
}

#[allow(clippy::too_many_arguments)]
fn evidence_for_subject(
    evidence: &EvidenceRepo<'_>,
    scan_id: &str,
    class: EvidenceClass,
    source_type: &str,
    locator: &str,
    subject: &str,
    observation: &str,
    metadata: serde_json::Value,
) -> Result<(), PicoError> {
    let mut item = Evidence::new(
        scan_id,
        class,
        source_type,
        locator,
        subject,
        observation,
        Sensitivity::Internal,
    )?;
    item.metadata = Some(metadata);
    evidence.insert(&item)
}

#[allow(clippy::too_many_arguments)]
fn persist_influence_relationship(
    relationships: &RelationshipRepo<'_>,
    evidence: &EvidenceRepo<'_>,
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    from: &Resource,
    to: &Resource,
    key: &str,
    kind: &str,
    state: RelationshipState,
    metadata: serde_json::Value,
    explanation: &str,
    locator: &str,
) -> Result<(), PicoError> {
    let mut relationship = match relationships.get_by_canonical_key(key)? {
        Some(relationship) => relationship,
        None => Relationship::new(key, &from.id, &to.id, kind, state)?,
    };
    relationship.state = state;
    relationship.last_observed_at = chrono::Utc::now();
    relationship.metadata = Some(metadata.clone());
    relationships.upsert(&relationship)?;
    let mut item = Evidence::new(
        scan_id,
        EvidenceClass::Derived,
        "github_mcp_influence",
        locator,
        key,
        explanation,
        Sensitivity::Internal,
    )?;
    item.metadata = Some(metadata);
    evidence.insert(&item)?;
    relationships.link_evidence(&relationship.id, &item.id)?;
    let mut observation = Observation::new(
        scan_id,
        "relationship",
        &relationship.id,
        "observed",
        "github_mcp_adapter",
    )?;
    observation.metadata = Some(relationship_snapshot_metadata(&relationship));
    observations.insert(&observation)
}

#[cfg(test)]
mod tests {
    use super::OPERATOR_REACHABILITY;
    use crate::discovery::EnvironmentReachability;

    /// The operator entry point must assert Proven reachability: with the
    /// parameter pinned to Unknown upstream, the live provider gate
    /// (opencode.rs provider_reachable) can never open and inspect_live is
    /// dead code from the shipped CLI. Structural tie, per Sprint 012 §13.
    #[test]
    fn operator_entry_point_asserts_proven_reachability() {
        assert_eq!(OPERATOR_REACHABILITY, EnvironmentReachability::Proven);
    }
}
