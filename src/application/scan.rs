//! `pico scan` application service (SPRINT-001.md §12).

use std::path::Path;

use crate::discovery;
use crate::domain::{
    Evidence, EvidenceClass, Observation, Relationship, RelationshipState, Resource, Scan,
    ScanStatus, Sensitivity,
};
use crate::persistence::{
    Database, EvidenceRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanRepo,
};
use crate::shared::{PicoError, PICO_VERSION};

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
    pub bash_permission: Option<String>,
    pub github_mcp_observed: bool,
    pub influence_strength: Option<String>,
    pub cloudflare_credential_observed: bool,
    pub credential_reachability: Option<String>,
    pub cloudflare_credential_status: Option<String>,
    pub cloudflare_account_count: u64,
    pub cloudflare_worker_count: u64,
    pub worker_mutation_authority: Option<String>,
    pub authority_resolution: Option<String>,
}

/// Runs bounded local discovery in an initialized workspace.
pub struct ScanService;

impl ScanService {
    pub fn run(workspace: &Path) -> Result<ScanResult, PicoError> {
        Self::run_with_home(
            workspace,
            std::env::var_os("HOME").as_deref().map(Path::new),
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
        let mut db = Database::open_existing(&workspace.join(".pico").join("pico.db"))?;
        db.migrate()?;

        let scan_repo = ScanRepo::new(db.connection());
        let scan = Scan::start(PICO_VERSION)?;
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
        let resource_repo = ResourceRepo::new(db.connection());
        let evidence_repo = EvidenceRepo::new(db.connection());
        let observation_repo = ObservationRepo::new(db.connection());
        let mut actor_seen = false;
        let mut actor_resource = None;
        for actor in discovered.actors {
            if actor.provider != "opencode" {
                continue;
            }
            let mut resource = match resource_repo.get_by_canonical_key("agent:opencode")? {
                Some(resource) => resource,
                None => Resource::new("agent:opencode", "agent", "opencode", "OpenCode")?,
            };
            resource.last_observed_at = chrono::Utc::now();
            resource_repo.upsert(&resource)?;
            evidence_repo.insert(&Evidence::new(
                &scan.id,
                EvidenceClass::Direct,
                actor.source_type,
                &actor.source_locator,
                "agent:opencode",
                "supported OpenCode configuration observed",
                Sensitivity::Internal,
            )?)?;
            if !actor_seen {
                observation_repo.insert(&Observation::new(
                    &scan.id,
                    "resource",
                    &resource.id,
                    "present",
                    "opencode_adapter",
                )?)?;
                actor_seen = true;
            }
            actor_resource = Some(resource);
        }

        let relationship_repo = RelationshipRepo::new(db.connection());
        let mut bash_permission = None;
        let mut bash_resource = None;
        if let (Some(actor), Some(capability)) = (
            actor_resource.as_ref(),
            discovered.bash_capabilities.first(),
        ) {
            let mut bash = match resource_repo.get_by_canonical_key("shell:bash")? {
                Some(resource) => resource,
                None => Resource::new("shell:bash", "shell", "local", "Bash")?,
            };
            bash.last_observed_at = chrono::Utc::now();
            bash.metadata = Some(serde_json::json!({"capability": "EXECUTE"}));
            resource_repo.upsert(&bash)?;
            bash_resource = Some(bash.clone());

            let relationship_key = "agent:opencode|can_execute|shell:bash";
            let state = match capability.permission {
                discovery::PermissionAction::Allow | discovery::PermissionAction::Ask => {
                    RelationshipState::Derived
                }
                discovery::PermissionAction::Deny => RelationshipState::Blocked,
                discovery::PermissionAction::Unknown => RelationshipState::Unknown,
            };
            let mut relationship = match relationship_repo.get_by_canonical_key(relationship_key)? {
                Some(relationship) => relationship,
                None => {
                    Relationship::new(relationship_key, &actor.id, &bash.id, "can_execute", state)?
                }
            };
            relationship.state = state;
            relationship.last_observed_at = chrono::Utc::now();
            let capability_metadata = serde_json::json!({
                "effective_permission": capability.permission.as_str(),
                "scope": capability.scope.as_str(),
                "runtime_mode": capability.runtime_mode,
            });
            relationship.metadata = Some(capability_metadata.clone());
            relationship_repo.upsert(&relationship)?;

            let mut evidence = Evidence::new(
                &scan.id,
                EvidenceClass::Derived,
                "opencode_effective_permission",
                &capability.source_locator,
                relationship_key,
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

            let mut bash_observation = Observation::new(
                &scan.id,
                "resource",
                &bash.id,
                "present",
                "opencode_adapter",
            )?;
            bash_observation.metadata = Some(capability_metadata.clone());
            observation_repo.insert(&bash_observation)?;

            let mut relationship_observation = Observation::new(
                &scan.id,
                "relationship",
                &relationship.id,
                "effective_permission",
                "opencode_adapter",
            )?;
            relationship_observation.metadata = Some(capability_metadata);
            observation_repo.insert(&relationship_observation)?;
            bash_permission = Some(capability.permission.as_str().to_string());
        }

        let mut github_mcp_observed = false;
        let mut influence_strength = None;
        if let Some(actor) = actor_resource.as_ref() {
            for surface in &discovered.github_surfaces {
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
                    "discovery": "opencode_v2_static",
                }));
                resource_repo.upsert(&server_resource)?;
                observe_resource(
                    &observation_repo,
                    &scan.id,
                    &server_resource,
                    "github_mcp_adapter",
                )?;
                evidence_for_subject(
                    &evidence_repo,
                    &scan.id,
                    EvidenceClass::Direct,
                    "opencode_mcp_config",
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
                persist_influence_relationship(
                    &relationship_repo,
                    &evidence_repo,
                    &observation_repo,
                    &scan.id,
                    actor,
                    &server_resource,
                    &format!("agent:opencode|configured_with|{server_key}"),
                    "configured_with",
                    if surface.server.enabled {
                        RelationshipState::Derived
                    } else {
                        RelationshipState::Blocked
                    },
                    serde_json::json!({"enabled": surface.server.enabled, "transport": surface.server.transport.as_str()}),
                    if surface.server.enabled {
                        "OpenCode is configured with the supported GitHub MCP server"
                    } else {
                        "OpenCode has a supported GitHub MCP server configured but disabled"
                    },
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
                    tool_resource.metadata = Some(serde_json::json!({
                        "content_class": tool.content_class,
                        "trust": tool.trust,
                        "influence_strength": tool.influence_strength,
                        "discovery_tier": tool.discovery_tier,
                        "permission": tool.permission.as_str(),
                        "permission_pattern": tool.permission_pattern,
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
                        &format!("agent:opencode|can_call|{tool_key}"),
                        "can_call",
                        call_state,
                        serde_json::json!({
                            "permission": tool.permission.as_str(),
                            "permission_pattern": tool.permission_pattern,
                            "runtime_mode": "UNKNOWN",
                        }),
                        &format!(
                            "OpenCode MCP permission for {} is {}",
                            tool.name,
                            tool.permission.as_str()
                        ),
                        &surface.server.source_locator,
                    )?;
                    let content_key = format!("source:{}", tool.content_class);
                    let content_name = match tool.content_class {
                        "github:public:issue-content" => "Public GitHub issue content",
                        "github:public:pull-request-content" => {
                            "Public GitHub pull-request content"
                        }
                        _ => "GitHub repository content",
                    };
                    let mut content_resource = match resource_repo
                        .get_by_canonical_key(&content_key)?
                    {
                        Some(resource) => resource,
                        None => {
                            Resource::new(&content_key, "external_content", "github", content_name)?
                        }
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
        }

        let mut cloudflare_credential_observed = false;
        let mut credential_reachability = None;
        let mut cloudflare_credential_status = None;
        let mut cloudflare_account_count = 0;
        let mut cloudflare_worker_count = 0;
        let mut worker_mutation_authority = None;
        let mut authority_resolution = None;
        for credential in &discovered.credentials {
            cloudflare_credential_observed = true;
            let credential_key = format!(
                "credential:{}:{}",
                credential.provider, credential.fingerprint
            );
            let mut resource = match resource_repo.get_by_canonical_key(&credential_key)? {
                Some(resource) => resource,
                None => Resource::new(
                    &credential_key,
                    "credential",
                    credential.provider,
                    "Cloudflare API Token",
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
                "fingerprint_version": "sha256:pico-credential-v1",
            });
            validate_secret_safe(&resource_metadata)?;
            resource.metadata = Some(resource_metadata);
            resource_repo.upsert(&resource)?;
            observe_resource(
                &observation_repo,
                &scan.id,
                &resource,
                "cloudflare_credential_adapter",
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
                "cloudflare_credential_reference",
                &credential.source_locator,
                &credential_key,
                "supported Cloudflare credential reference is present",
                reference_metadata,
            )?;

            if let Some(bash) = bash_resource.as_ref() {
                let (state, reachability) = match (
                    credential.environment,
                    discovered
                        .bash_capabilities
                        .first()
                        .map(|capability| capability.permission),
                ) {
                    (
                        discovery::EnvironmentReachability::Proven,
                        Some(discovery::PermissionAction::Allow),
                    ) => (RelationshipState::Derived, "REACHABLE"),
                    (
                        discovery::EnvironmentReachability::Proven,
                        Some(discovery::PermissionAction::Ask),
                    ) => (RelationshipState::Derived, "APPROVAL_GATED"),
                    (
                        discovery::EnvironmentReachability::Proven,
                        Some(discovery::PermissionAction::Deny),
                    ) => (RelationshipState::Blocked, "BLOCKED"),
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
        }

        let completed = if discovered.problems.is_empty() {
            scan.complete()?
        } else {
            scan.partial()?
        };
        scan_repo.update(&completed)?;

        let resource_count = resource_repo.count()?;
        let relationship_count = relationship_repo.count()?;
        let evidence_count = evidence_repo.count()?;

        Ok(ScanResult {
            scan_id: completed.id,
            status: completed.status,
            started_at: completed.started_at,
            completed_at: completed.completed_at,
            resource_count,
            agent_count: u64::from(actor_seen),
            relationship_count,
            evidence_count,
            finding_count: 0,
            bash_permission,
            github_mcp_observed,
            influence_strength,
            cloudflare_credential_observed,
            credential_reachability,
            cloudflare_credential_status,
            cloudflare_account_count,
            cloudflare_worker_count,
            worker_mutation_authority,
            authority_resolution,
        })
    }
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
            None => Resource::new(&account_key, "account", "cloudflare", account_name)?,
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
        let mut resource = match resources.get_by_canonical_key(&worker_key)? {
            Some(resource) => resource,
            None => Resource::new(&worker_key, "worker", "cloudflare", &worker.script_name)?,
        };
        resource.last_observed_at = chrono::Utc::now();
        resource.metadata = Some(serde_json::json!({
            "account_id": worker.account_id,
            "worker_tag": worker.worker_tag,
            "identity_precision": worker.identity_precision(),
            "environment": "UNKNOWN",
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
    observation.metadata = Some(metadata);
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
        "cloudflare_credential_reachability",
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
        "cloudflare_credential_adapter",
    )?;
    observation.metadata = Some(metadata);
    observations.insert(&observation)
}

fn observe_resource(
    observations: &ObservationRepo<'_>,
    scan_id: &str,
    resource: &Resource,
    source: &str,
) -> Result<(), PicoError> {
    observations.insert(&Observation::new(
        scan_id,
        "resource",
        &resource.id,
        "present",
        source,
    )?)
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
    observation.metadata = Some(serde_json::json!({"state": state.as_str()}));
    observations.insert(&observation)
}
