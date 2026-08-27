//! Provider-neutral deterministic analysis result types.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::RelationshipState;
use crate::graph::SecurityGraph;

pub const ANALYSIS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalysisStatus {
    Complete,
    Limited,
    Failed,
}

impl AnalysisStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Limited => "LIMITED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CandidateDisposition {
    Active,
    Blocked,
    Unresolved,
    None,
}

impl CandidateDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Blocked => "BLOCKED",
            Self::Unresolved => "UNRESOLVED",
            Self::None => "NONE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PathPhase {
    Influence,
    Authority,
}

impl PathPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Influence => "INFLUENCE",
            Self::Authority => "AUTHORITY",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TraversalDirection {
    Forward,
    Reverse,
}

impl TraversalDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "FORWARD",
            Self::Reverse => "REVERSE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEdgeRef {
    pub relationship_id: String,
    pub phase: PathPhase,
    pub traversal: TraversalDirection,
    pub position: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceTrust {
    TrustedInternal,
    AuthenticatedInternal,
    AuthenticatedExternal,
    PublicExternal,
    OpenWorld,
    Unknown,
}

impl SourceTrust {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedInternal => "TRUSTED_INTERNAL",
            Self::AuthenticatedInternal => "AUTHENTICATED_INTERNAL",
            Self::AuthenticatedExternal => "AUTHENTICATED_EXTERNAL",
            Self::PublicExternal => "PUBLIC_EXTERNAL",
            Self::OpenWorld => "OPEN_WORLD",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("UNKNOWN").to_ascii_uppercase().as_str() {
            "TRUSTED_INTERNAL" => Self::TrustedInternal,
            "AUTHENTICATED_INTERNAL" => Self::AuthenticatedInternal,
            "AUTHENTICATED_EXTERNAL" => Self::AuthenticatedExternal,
            "PUBLIC_EXTERNAL" => Self::PublicExternal,
            "OPEN_WORLD" => Self::OpenWorld,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InfluenceStrength {
    MetadataOnly,
    ManualRetrieval,
    AgentRetrievable,
    AutomaticallyInjected,
    InstructionBearing,
    AgentInjectable,
    AgentMutable,
    Unknown,
}

impl InfluenceStrength {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "METADATA_ONLY",
            Self::ManualRetrieval => "MANUAL_RETRIEVAL",
            Self::AgentRetrievable => "AGENT_RETRIEVABLE",
            Self::AutomaticallyInjected => "AUTOMATICALLY_INJECTED",
            Self::InstructionBearing => "INSTRUCTION_BEARING",
            Self::AgentInjectable => "AGENT_INJECTABLE",
            Self::AgentMutable => "AGENT_MUTABLE",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("UNKNOWN").to_ascii_uppercase().as_str() {
            "METADATA_ONLY" => Self::MetadataOnly,
            "MANUAL_RETRIEVAL" => Self::ManualRetrieval,
            "AGENT_RETRIEVABLE" => Self::AgentRetrievable,
            "AUTOMATICALLY_INJECTED" => Self::AutomaticallyInjected,
            "INSTRUCTION_BEARING" => Self::InstructionBearing,
            "AGENT_INJECTABLE" => Self::AgentInjectable,
            "AGENT_MUTABLE" => Self::AgentMutable,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CapabilityClass {
    Read,
    Write,
    Execute,
    Admin,
    Unknown,
}

impl CapabilityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Execute => "EXECUTE",
            Self::Admin => "ADMIN",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("UNKNOWN").to_ascii_uppercase().as_str() {
            "READ" => Self::Read,
            "WRITE" => Self::Write,
            "EXECUTE" => Self::Execute,
            "ADMIN" => Self::Admin,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityResolution {
    Exact,
    Scoped,
    BehavioralReadOnly,
    Unknown,
}

impl AuthorityResolution {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "EXACT",
            Self::Scoped => "SCOPED",
            Self::BehavioralReadOnly => "BEHAVIORAL_READ_ONLY",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("UNKNOWN").to_ascii_uppercase().as_str() {
            "EXACT" => Self::Exact,
            "SCOPED" => Self::Scoped,
            "BEHAVIORAL_READ_ONLY" => Self::BehavioralReadOnly,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SinkImpact {
    LocalDev,
    Repository,
    Staging,
    Production,
    SecretStore,
    Database,
    Iam,
    Billing,
    ExternalSideEffect,
    Unknown,
}

impl SinkImpact {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalDev => "LOCAL_DEV",
            Self::Repository => "REPOSITORY",
            Self::Staging => "STAGING",
            Self::Production => "PRODUCTION",
            Self::SecretStore => "SECRET_STORE",
            Self::Database => "DATABASE",
            Self::Iam => "IAM",
            Self::Billing => "BILLING",
            Self::ExternalSideEffect => "EXTERNAL_SIDE_EFFECT",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or("UNKNOWN").to_ascii_uppercase().as_str() {
            "LOCAL_DEV" => Self::LocalDev,
            "REPOSITORY" => Self::Repository,
            "STAGING" => Self::Staging,
            "PRODUCTION" => Self::Production,
            "SECRET_STORE" => Self::SecretStore,
            "DATABASE" => Self::Database,
            "IAM" => Self::Iam,
            "BILLING" => Self::Billing,
            "EXTERNAL_SIDE_EFFECT" => Self::ExternalSideEffect,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SegmentDisposition {
    Active,
    Blocked,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfluencePath {
    pub source_resource_id: String,
    pub actor_resource_id: String,
    pub edges: Vec<PathEdgeRef>,
    pub source_trust: SourceTrust,
    pub influence_strength: InfluenceStrength,
    pub evidence_ids: Vec<String>,
    pub disposition: SegmentDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityPath {
    pub actor_resource_id: String,
    pub sink_resource_id: String,
    pub edges: Vec<PathEdgeRef>,
    pub capability: CapabilityClass,
    pub authority_resolution: AuthorityResolution,
    pub sink_impact: SinkImpact,
    pub evidence_ids: Vec<String>,
    pub disposition: SegmentDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BoundaryKind {
    HardDeny,
    Sandbox,
    MandatoryApproval,
    CredentialScope,
    ResourceScope,
    NetworkIsolation,
    ProcessIsolation,
    SoftPolicy,
    Mutation,
}

impl BoundaryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardDeny => "HARD_DENY",
            Self::Sandbox => "SANDBOX",
            Self::MandatoryApproval => "MANDATORY_APPROVAL",
            Self::CredentialScope => "CREDENTIAL_SCOPE",
            Self::ResourceScope => "RESOURCE_SCOPE",
            Self::NetworkIsolation => "NETWORK_ISOLATION",
            Self::ProcessIsolation => "PROCESS_ISOLATION",
            Self::SoftPolicy => "SOFT_POLICY",
            Self::Mutation => "MUTATION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BoundaryDecision {
    Interrupts,
    DoesNotInterrupt,
    Unresolved,
}

impl BoundaryDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupts => "INTERRUPTS",
            Self::DoesNotInterrupt => "DOES_NOT_INTERRUPT",
            Self::Unresolved => "UNRESOLVED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryEvaluation {
    pub kind: BoundaryKind,
    pub affected_resource_ids: Vec<String>,
    pub affected_relationship_ids: Vec<String>,
    pub enforcement: String,
    pub interrupted_phase: Option<PathPhase>,
    pub decision: BoundaryDecision,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub analysis_version: u32,
    pub source_resource_id: String,
    pub actor_resource_id: String,
    pub sink_resource_id: String,
    pub influence_edges: Vec<PathEdgeRef>,
    pub authority_edges: Vec<PathEdgeRef>,
    pub boundary_evaluations: Vec<BoundaryEvaluation>,
    pub source_trust: SourceTrust,
    pub influence_strength: InfluenceStrength,
    pub capability: CapabilityClass,
    pub authority_resolution: AuthorityResolution,
    pub sink_impact: SinkImpact,
    pub evidence_ids: Vec<String>,
    pub disposition: CandidateDisposition,
}

impl AttackPath {
    pub fn fingerprint_input(&self, graph: &SecurityGraph) -> String {
        let source_key = graph
            .node(&self.source_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or(&self.source_resource_id);
        let actor_key = graph
            .node(&self.actor_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or(&self.actor_resource_id);
        let sink_key = graph
            .node(&self.sink_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or(&self.sink_resource_id);
        let mut value = String::new();
        append_field(&mut value, "version", &self.analysis_version.to_string());
        append_field(&mut value, "source", source_key);
        append_field(&mut value, "actor", actor_key);
        append_field(&mut value, "sink", sink_key);
        append_field(&mut value, "disposition", self.disposition.as_str());
        for edge in self
            .influence_edges
            .iter()
            .chain(self.authority_edges.iter())
        {
            let relationship_key = graph
                .edge(&edge.relationship_id)
                .map(|candidate| candidate.canonical_key.as_str())
                .unwrap_or(&edge.relationship_id);
            append_field(
                &mut value,
                "edge",
                &format!(
                    "{}:{}:{}:{}",
                    relationship_key,
                    edge.phase.as_str(),
                    edge.traversal.as_str(),
                    edge.position
                ),
            );
        }
        let mut boundaries = self
            .boundary_evaluations
            .iter()
            .map(|boundary| {
                let mut resources = boundary
                    .affected_resource_ids
                    .iter()
                    .map(|id| {
                        graph
                            .node(id)
                            .map(|node| node.canonical_key.as_str())
                            .unwrap_or(id)
                    })
                    .collect::<Vec<_>>();
                resources.sort();
                let mut relationships = boundary
                    .affected_relationship_ids
                    .iter()
                    .map(|id| {
                        graph
                            .edge(id)
                            .map(|edge| edge.canonical_key.as_str())
                            .unwrap_or(id)
                    })
                    .collect::<Vec<_>>();
                relationships.sort();
                (boundary, resources, relationships)
            })
            .collect::<Vec<_>>();
        boundaries.sort_by(
            |(left, left_resources, left_relationships),
             (right, right_resources, right_relationships)| {
                left.kind
                    .cmp(&right.kind)
                    .then(left.decision.cmp(&right.decision))
                    .then(left.enforcement.cmp(&right.enforcement))
                    .then(left.interrupted_phase.cmp(&right.interrupted_phase))
                    .then(left_resources.cmp(right_resources))
                    .then(left_relationships.cmp(right_relationships))
            },
        );
        for (boundary, resources, relationships) in boundaries {
            append_field(
                &mut value,
                "boundary",
                &format!(
                    "{}:{}:{}:{}:{}:{}",
                    boundary.kind.as_str(),
                    boundary.decision.as_str(),
                    boundary.enforcement,
                    boundary
                        .interrupted_phase
                        .map(PathPhase::as_str)
                        .unwrap_or("NONE"),
                    resources.join(","),
                    relationships.join(",")
                ),
            );
        }
        value
    }

    pub fn with_fingerprint(mut self, graph: &SecurityGraph) -> Self {
        let digest = Sha256::digest(self.fingerprint_input(graph).as_bytes());
        self.fingerprint = format!("sha256:{digest:x}");
        self
    }
}

fn append_field(output: &mut String, label: &str, value: &str) {
    output.push_str(&format!("{}:{}:{}:", label.len(), label, value.len()));
    output.push_str(value);
    output.push(';');
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisLimits {
    pub maximum_depth: usize,
    pub maximum_edge_examinations: usize,
    pub maximum_frontier_nodes: usize,
    pub maximum_reachable_nodes: usize,
    pub maximum_influence_paths_per_actor: usize,
    pub maximum_authority_paths_per_actor: usize,
    pub maximum_candidate_joins: usize,
    pub maximum_emitted_attack_paths: usize,
    pub maximum_unresolved_candidates: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            maximum_depth: 8,
            maximum_edge_examinations: 256,
            maximum_frontier_nodes: 128,
            maximum_reachable_nodes: 128,
            maximum_influence_paths_per_actor: 32,
            maximum_authority_paths_per_actor: 32,
            maximum_candidate_joins: 256,
            maximum_emitted_attack_paths: 128,
            maximum_unresolved_candidates: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub scan_id: String,
    pub analysis_version: u32,
    pub status: AnalysisStatus,
    pub candidate_disposition: CandidateDisposition,
    pub influence_paths: Vec<InfluencePath>,
    pub authority_paths: Vec<AuthorityPath>,
    pub boundary_evaluations: Vec<BoundaryEvaluation>,
    pub attack_paths: Vec<AttackPath>,
    pub unresolved_candidate_count: usize,
    pub diagnostics: Vec<String>,
}

impl AnalysisResult {
    pub fn empty(graph: &SecurityGraph) -> Self {
        Self {
            scan_id: graph.scan_id.clone(),
            analysis_version: ANALYSIS_VERSION,
            status: AnalysisStatus::Complete,
            candidate_disposition: CandidateDisposition::None,
            influence_paths: Vec::new(),
            authority_paths: Vec::new(),
            boundary_evaluations: Vec::new(),
            attack_paths: Vec::new(),
            unresolved_candidate_count: 0,
            diagnostics: Vec::new(),
        }
    }
}

pub(crate) fn metadata_string(value: Option<&serde_json::Value>, key: &str) -> Option<String> {
    value
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(key))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn metadata_bool(value: Option<&serde_json::Value>, key: &str) -> Option<bool> {
    value
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(key))
        .and_then(serde_json::Value::as_bool)
}

pub(crate) fn metadata_string_array(value: Option<&serde_json::Value>, key: &str) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(key))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn edge_state_disposition(state: RelationshipState) -> SegmentDisposition {
    match state {
        RelationshipState::Blocked => SegmentDisposition::Blocked,
        RelationshipState::Unknown => SegmentDisposition::Unresolved,
        _ => SegmentDisposition::Active,
    }
}
