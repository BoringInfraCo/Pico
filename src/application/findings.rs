//! Read-only Finding query and explanation (SPRINT-010.md §5).
//!
//! This service composes persisted Findings, AttackPaths, Evidence, reasons,
//! boundaries, and remediations into stable application DTOs inside one
//! coherent read-only SQLite snapshot. It never writes, migrates, reruns
//! analysis, or contacts providers, and it never exposes raw metadata,
//! credentials, or unsafe locators.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use crate::analysis::{BoundaryDecision, BoundaryEvaluation};
use crate::domain::{Evidence, Scan, ScanStatus, GRAPH_SNAPSHOT_VERSION};
use crate::findings::{Confidence, FindingResult, ReasonCode, Severity};
use crate::graph::{project, ProjectionInput, SecurityGraph};
use crate::persistence::{
    codec, require_schema_version, AttackPathEdgeRecord, AttackPathRecord, AttackPathRepo,
    Database, EvidenceRepo, FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord,
    FindingRecord, FindingRemediationRecord, FindingRepo, ObservationRepo, RelationshipRepo,
    ResourceRepo, ScanAnalysisRepo, ScanRepo,
};
use crate::shared::PicoError;

const SUPPORTED_FINDING_VERSION: u32 = 1;
const SUPPORTED_ANALYSIS_VERSION: u32 = 1;
const MAX_FINDINGS_PER_SCAN: usize = 128;
const MAX_PATHS_PER_FINDING: usize = 256;
const MAX_EDGES_PER_PATH: usize = 256;
const MAX_EVIDENCE_PER_FINDING: usize = 1024;
const MAX_REASONS_PER_FINDING: usize = 64;
const MAX_REMEDIATIONS_PER_FINDING: usize = 64;
const MAX_STRING_LENGTH: usize = 8192;
const MAX_DTO_BYTES: usize = 4 * 1024 * 1024;

const SCOPE_NOTE: &str = "This Finding describes a potential exposure established from the recorded scan. It does not establish exploitation, malicious content, or compromise.";
const BOUNDARY_SUMMARY: &str =
    "No proven enforced boundary recorded for this scan interrupts this path.";
const REMEDIATION_NOTE: &str = "Recommendations only. Pico did not apply these changes.";

const SUPPORTED_REMEDIATION_RULES: &[&str] = &[
    "ENFORCE_BASH_APPROVAL_OR_DENY",
    "REMOVE_AGENT_CREDENTIAL_REACHABILITY",
    "RESTRICT_EXTERNAL_RETRIEVAL",
    "SCOPE_PRODUCTION_MUTATION_AUTHORITY",
];

/// Latest COMPLETE selection with per-Finding summaries.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingList {
    pub selected_scan: Option<ScanBrief>,
    pub newest_scan_attempt: Option<ScanBrief>,
    pub freshness: Freshness,
    pub freshness_warning: Option<String>,
    pub findings: Vec<FindingSummary>,
}

/// Minimal scan identity used by list and detail DTOs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanBrief {
    pub id: String,
    pub status: String,
    pub completed_at: Option<String>,
}

/// Whether displayed results describe the newest complete state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Freshness {
    LatestComplete,
    #[serde(rename = "NEWER_INCOMPLETE_ATTEMPT")]
    NewerIncomplete,
}

/// One deterministic Finding summary in `pico findings` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub finding_class: String,
    pub status: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub attack_path_count: u64,
    pub affected_sink_count: u64,
    pub fingerprint: String,
}

/// Whether a detail view describes the latest complete state or history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Currentness {
    LatestComplete,
    Historical { newer_complete_scan_id: String },
}

/// Complete composed explanation of one exact persisted Finding.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingDetail {
    pub id: String,
    pub fingerprint: String,
    pub finding_version: u32,
    pub scan: ScanBrief,
    pub currentness: Currentness,
    pub freshness_warning: Option<String>,
    pub finding_class: String,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub severity: String,
    pub confidence: String,
    pub scope_note: String,
    pub severity_basis: String,
    pub confidence_basis: String,
    pub reasons: Vec<ReasonView>,
    pub paths: Vec<ExplainedPath>,
    pub evidence: Vec<EvidenceView>,
    pub boundary_summary: String,
    pub uncertainties: Vec<String>,
    pub remediations: Vec<RemediationView>,
    pub remediation_note: String,
    pub created_at: String,
}

/// One persisted AttackPath rendered with traversal-aware steps.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExplainedPath {
    pub id: String,
    pub fingerprint: String,
    pub disposition: String,
    pub source_trust: String,
    pub influence_strength: String,
    pub capability: String,
    pub authority_resolution: String,
    pub sink_impact: String,
    pub source_resource_id: String,
    pub actor_resource_id: String,
    pub sink_resource_id: String,
    pub steps: Vec<PathStep>,
    pub boundaries: Vec<BoundaryView>,
}

/// One traversal-applied step of an explained path.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathStep {
    pub position: u32,
    pub phase: String,
    pub traversal: String,
    pub relationship_id: String,
    pub relationship_kind: String,
    pub from_resource: ResourceView,
    pub to_resource: ResourceView,
    pub relationship_state: String,
    pub evidence_ids: Vec<String>,
}

/// Historical graph node identity and labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceView {
    pub id: String,
    pub canonical_key: String,
    pub kind: String,
    pub provider: String,
    pub name: String,
}

/// Minimized same-scan evidence provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceView {
    pub id: String,
    pub class: String,
    pub source_type: String,
    pub safe_source_locator: Option<String>,
    pub subject: String,
    pub observation: String,
    pub captured_at: String,
    pub freshness: String,
    pub sensitivity: String,
    pub support_roles: Vec<String>,
}

/// Recorded boundary evaluation on a linked path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundaryView {
    pub kind: String,
    pub decision: String,
    pub enforcement: String,
}

/// Fixed provider-neutral reason narration in stored order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonView {
    pub position: u32,
    pub code: String,
    pub explanation: String,
}

/// One remediation cut point with historically resolved targets.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RemediationView {
    pub position: u32,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub security_effect: String,
    pub cut_phase: String,
    pub target_resource_ids: Vec<String>,
    pub target_resources: Vec<ResourceView>,
    pub target_relationship_ids: Vec<String>,
}

/// Disambiguated list outcome shared verbatim by CLI and MCP surfaces
/// (SPRINT-011.md §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingsListState {
    NoScans,
    NoCompleteScan,
    ResultsAvailable,
}

const GUIDANCE_NO_SCANS: &[&str] = &[
    "No scans have been run yet in this workspace.",
    "Run `pico scan` to discover the paths agents create.",
];

const GUIDANCE_NO_COMPLETE_SCAN: &[&str] = &[
    "No COMPLETE scan exists in this workspace.",
    "This is not an all-clear; no authoritative scan exists.",
];

const GUIDANCE_ZERO_FINDINGS: &str =
    "No Findings were produced for this COMPLETE scan within Pico's supported scope.";
const GUIDANCE_RESULTS_AVAILABLE: &str = "Run get_finding with a listed ID to inspect it.";

/// Classifies a composed list into the fixed shared states.
pub fn findings_list_state(list: &FindingList) -> FindingsListState {
    if list.selected_scan.is_some() {
        FindingsListState::ResultsAvailable
    } else if list.newest_scan_attempt.is_some() {
        FindingsListState::NoCompleteScan
    } else {
        FindingsListState::NoScans
    }
}

/// Returns the fixed provider-neutral guidance sentences for a list state.
pub fn findings_list_guidance(state: FindingsListState, list: &FindingList) -> Vec<String> {
    match state {
        FindingsListState::NoScans => GUIDANCE_NO_SCANS.iter().map(|l| (*l).to_string()).collect(),
        FindingsListState::NoCompleteScan => GUIDANCE_NO_COMPLETE_SCAN
            .iter()
            .map(|l| (*l).to_string())
            .collect(),
        FindingsListState::ResultsAvailable => {
            if list.findings.is_empty() {
                vec![GUIDANCE_ZERO_FINDINGS.to_string()]
            } else {
                vec![GUIDANCE_RESULTS_AVAILABLE.to_string()]
            }
        }
    }
}

/// Deterministic navigation IDs for a generated Finding result, ordered by
/// severity descending, confidence descending, then title, fingerprint, id.
pub fn finding_navigation_ids(result: &FindingResult) -> Vec<String> {
    let mut findings = result.findings.clone();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(right.confidence.cmp(&left.confidence))
            .then(left.title.cmp(&right.title))
            .then(left.fingerprint.cmp(&right.fingerprint))
            .then(left.id.cmp(&right.id))
    });
    findings.into_iter().map(|finding| finding.id).collect()
}

/// Query and explain persisted Findings read-only.
pub struct FindingQueryService;

impl FindingQueryService {
    /// Summarize the Findings of the newest COMPLETE scan.
    pub fn list_latest(workspace: &Path) -> Result<FindingList, PicoError> {
        let result = with_read_snapshot(workspace, |conn| {
            let scans = ScanRepo::new(conn);
            let selected = scans.newest_complete()?;
            let newest_attempt = scans.newest_attempt()?;
            let (freshness, warning) = freshness_context(&selected, &newest_attempt);
            let findings = match &selected {
                Some(scan) => summarize_scan(conn, &scan.id)?,
                None => Vec::new(),
            };
            Ok(FindingList {
                selected_scan: selected.as_ref().map(scan_brief),
                newest_scan_attempt: newest_attempt.as_ref().map(scan_brief),
                freshness,
                freshness_warning: warning,
                findings,
            })
        })?;
        enforce_dto_budget(&result)?;
        Ok(result)
    }

    /// Compose the full explanation of one exact Finding ID.
    pub fn get(workspace: &Path, finding_id: &str) -> Result<FindingDetail, PicoError> {
        if finding_id.trim().is_empty() {
            return Err(PicoError::usage("a Finding ID is required"));
        }
        let result = with_read_snapshot(workspace, |conn| compose_detail(conn, finding_id))?;
        enforce_dto_budget(&result)?;
        Ok(result)
    }
}

fn with_read_snapshot<T>(
    workspace: &Path,
    compose: impl FnOnce(&Connection) -> Result<T, PicoError>,
) -> Result<T, PicoError> {
    let db_path = workspace.join(".pico").join("pico.db");
    let db = Database::open_read_only(&db_path)?;
    require_schema_version(db.connection())?;
    let tx = db
        .connection()
        .unchecked_transaction()
        .map_err(|e| PicoError::database(e.to_string()))?;
    let outcome = compose(&tx);
    match outcome {
        Ok(value) => {
            tx.commit()
                .map_err(|e| PicoError::database(e.to_string()))?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback();
            Err(error)
        }
    }
}

fn attempt_is_newer(attempt: &Scan, complete: &Scan) -> bool {
    (attempt.started_at, attempt.id.as_str()) > (complete.started_at, complete.id.as_str())
}

fn attempt_status_warns(status: ScanStatus) -> bool {
    matches!(
        status,
        ScanStatus::Running | ScanStatus::Partial | ScanStatus::Failed
    )
}

fn freshness_context(
    selected_complete: &Option<Scan>,
    newest_attempt: &Option<Scan>,
) -> (Freshness, Option<String>) {
    if let (Some(complete), Some(attempt)) = (selected_complete, newest_attempt) {
        if attempt_status_warns(attempt.status) && attempt_is_newer(attempt, complete) {
            return (
                Freshness::NewerIncomplete,
                Some(format!(
                    "Freshness: A newer scan {} is {}.\nShowing the last COMPLETE scan; these results may not describe current state.",
                    attempt.id,
                    attempt.status.as_str()
                )),
            );
        }
    }
    (Freshness::LatestComplete, None)
}

fn scan_brief(scan: &Scan) -> ScanBrief {
    ScanBrief {
        id: scan.id.clone(),
        status: scan.status.as_str().to_string(),
        completed_at: scan.completed_at.map(codec::ts_to_text),
    }
}

fn integrity(message: impl Into<String>) -> PicoError {
    PicoError::database(format!("integrity failure: {}", message.into()))
}

fn bounded_string(label: &str, value: &str) -> Result<String, PicoError> {
    if value.chars().count() > MAX_STRING_LENGTH {
        return Err(integrity(format!(
            "{label} exceeds the supported length of {MAX_STRING_LENGTH} characters"
        )));
    }
    Ok(value.to_string())
}

fn parse_u32_version(field: &str, value: &str) -> Result<u32, PicoError> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| integrity(format!("{field} is not a supported version value: {value}")))
}

fn parse_severity(value: &str) -> Result<Severity, PicoError> {
    match value {
        "INFO" => Ok(Severity::Info),
        "LOW" => Ok(Severity::Low),
        "MEDIUM" => Ok(Severity::Medium),
        "HIGH" => Ok(Severity::High),
        "CRITICAL" => Ok(Severity::Critical),
        other => Err(integrity(format!("unsupported finding severity {other}"))),
    }
}

fn parse_confidence(value: &str) -> Result<Confidence, PicoError> {
    match value {
        "LOW" => Ok(Confidence::Low),
        "MEDIUM" => Ok(Confidence::Medium),
        "HIGH" => Ok(Confidence::High),
        other => Err(integrity(format!("unsupported finding confidence {other}"))),
    }
}

fn parse_reason_code(code: &str) -> Result<ReasonCode, PicoError> {
    match code {
        "EXTERNAL_INFLUENCE_SOURCE" => Ok(ReasonCode::ExternalInfluenceSource),
        "AGENT_RETRIEVABLE_CONTENT" => Ok(ReasonCode::AgentRetrievableContent),
        "AUTONOMOUS_EXECUTION_CAPABILITY" => Ok(ReasonCode::AutonomousExecutionCapability),
        "REACHABLE_CREDENTIAL_AUTHORITY" => Ok(ReasonCode::ReachableCredentialAuthority),
        "PRODUCTION_MUTATION_AUTHORITY" => Ok(ReasonCode::ProductionMutationAuthority),
        "NO_ENFORCED_BOUNDARY" => Ok(ReasonCode::NoEnforcedBoundary),
        other => Err(integrity(format!(
            "unsupported finding reason code {other}"
        ))),
    }
}

fn reason_explanation(code: ReasonCode) -> &'static str {
    match code {
        ReasonCode::ExternalInfluenceSource => {
            "The path begins at content from outside the workspace boundary."
        }
        ReasonCode::AgentRetrievableContent => {
            "The coding agent can retrieve that external content through its configured tools."
        }
        ReasonCode::AutonomousExecutionCapability => {
            "The agent can execute commands autonomously without a technically enforced approval boundary."
        }
        ReasonCode::ReachableCredentialAuthority => {
            "An authority-bearing credential is reachable from that execution environment."
        }
        ReasonCode::ProductionMutationAuthority => {
            "That credential holds authority to change an explicitly classified production resource."
        }
        ReasonCode::NoEnforcedBoundary => {
            "No proven enforced boundary recorded for this scan interrupts the path between external content and production mutation."
        }
    }
}

fn validate_finding_header(
    record: &FindingRecord,
) -> Result<(u32, Severity, Confidence), PicoError> {
    let version = parse_u32_version("finding_version", &record.finding_version)?;
    if version != SUPPORTED_FINDING_VERSION {
        return Err(integrity(format!(
            "unsupported finding version {version} for finding {}",
            record.id
        )));
    }
    if record.finding_class != "UNTRUSTED_TO_PRODUCTION" {
        return Err(integrity(format!(
            "unsupported finding class {} for finding {}",
            record.finding_class, record.id
        )));
    }
    let severity = parse_severity(&record.severity)?;
    let confidence = parse_confidence(&record.confidence)?;
    if record.status != "OPEN" {
        return Err(integrity(format!(
            "unsupported finding status {} for finding {}",
            record.status, record.id
        )));
    }
    Ok((version, severity, confidence))
}

fn contiguous_positions(
    label: &str,
    positions: impl Iterator<Item = u32>,
) -> Result<(), PicoError> {
    for (index, position) in positions.enumerate() {
        if position != index as u32 {
            return Err(integrity(format!(
                "{label} positions are not zero-based contiguous"
            )));
        }
    }
    Ok(())
}

fn linked_paths(
    conn: &Connection,
    record: &FindingRecord,
) -> Result<Vec<AttackPathRecord>, PicoError> {
    let repo = FindingRepo::new(conn);
    let paths_repo = AttackPathRepo::new(conn);
    let links: Vec<FindingPathRecord> = repo.list_paths(&record.id)?;
    if links.len() > MAX_PATHS_PER_FINDING {
        return Err(integrity(format!(
            "finding {} exceeds the supported attack-path budget of {MAX_PATHS_PER_FINDING}",
            record.id
        )));
    }
    contiguous_positions(
        &format!("finding {} paths", record.id),
        links.iter().map(|link| link.position),
    )?;
    if links.is_empty() {
        return Err(integrity(format!(
            "finding {} has no linked attack paths",
            record.id
        )));
    }
    let mut paths = Vec::with_capacity(links.len());
    for link in &links {
        let path = paths_repo.get(&link.attack_path_id)?.ok_or_else(|| {
            integrity(format!(
                "finding {} links missing attack path {}",
                record.id, link.attack_path_id
            ))
        })?;
        if path.scan_id != record.scan_id {
            return Err(integrity(format!(
                "attack path {} belongs to another scan than finding {}",
                path.id, record.id
            )));
        }
        let version = parse_u32_version("analysis_version", &path.analysis_version)?;
        if version != SUPPORTED_ANALYSIS_VERSION {
            return Err(integrity(format!(
                "unsupported analysis version {version} on attack path {}",
                path.id
            )));
        }
        if path.disposition != "ACTIVE" {
            return Err(integrity(format!(
                "attack path {} linked to finding {} is not ACTIVE",
                path.id, record.id
            )));
        }
        if path.sink_impact != "PRODUCTION" {
            return Err(integrity(format!(
                "attack path {} linked to finding {} does not impact PRODUCTION",
                path.id, record.id
            )));
        }
        paths.push(path);
    }
    Ok(paths)
}

struct FindingEvidence {
    views: Vec<EvidenceView>,
    ids: BTreeSet<String>,
}

fn finding_evidence_views(
    conn: &Connection,
    record: &FindingRecord,
) -> Result<FindingEvidence, PicoError> {
    let repo = FindingRepo::new(conn);
    let rows: Vec<FindingEvidenceRecord> = repo.list_evidence(&record.id)?;
    if rows.len() > MAX_EVIDENCE_PER_FINDING {
        return Err(integrity(format!(
            "finding {} exceeds the supported evidence budget of {MAX_EVIDENCE_PER_FINDING}",
            record.id
        )));
    }
    contiguous_positions(
        &format!("finding {} evidence", record.id),
        rows.iter().map(|row| row.position),
    )?;
    for row in &rows {
        if !matches!(
            row.support_role.as_str(),
            "SUPPORTING" | "SINK_CLASSIFICATION"
        ) {
            return Err(integrity(format!(
                "unsupported finding evidence role {} on finding {}",
                row.support_role, record.id
            )));
        }
    }
    let mut ids = BTreeSet::new();
    let mut resolved = Vec::with_capacity(rows.len());
    for row in &rows {
        let item = resolve_same_scan_evidence(conn, &row.evidence_id, &record.scan_id)?;
        ids.insert(item.id.clone());
        resolved.push(item);
    }
    let mut views = Vec::with_capacity(rows.len());
    for (row, item) in rows.iter().zip(&resolved) {
        let mut view = evidence_view(item)?;
        view.support_roles = rows
            .iter()
            .filter(|candidate| candidate.evidence_id == row.evidence_id)
            .map(|candidate| candidate.support_role.clone())
            .collect::<Vec<_>>();
        view.support_roles.dedup();
        views.push(view);
    }
    Ok(FindingEvidence { views, ids })
}

fn resolve_same_scan_evidence(
    conn: &Connection,
    evidence_id: &str,
    scan_id: &str,
) -> Result<Evidence, PicoError> {
    let item = EvidenceRepo::new(conn)
        .get(evidence_id)?
        .ok_or_else(|| integrity(format!("evidence {evidence_id} is missing")))?;
    if item.scan_id != scan_id {
        return Err(integrity(format!(
            "evidence {evidence_id} belongs to another scan than {scan_id}"
        )));
    }
    Ok(item)
}

fn safe_source_locator(locator: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "users/",
        "/home/",
        "\\",
        "authorization",
        "bearer",
        "token",
        "password",
        "secret",
    ];
    if locator.is_empty() || locator.chars().count() > 512 {
        return false;
    }
    let mut characters = locator.chars();
    if !characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
    {
        return false;
    }
    if !characters
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '/' | '@' | ' ' | '-'))
    {
        return false;
    }
    let lowered = locator.to_ascii_lowercase();
    !FORBIDDEN.iter().any(|needle| lowered.contains(needle))
}

fn evidence_view(item: &Evidence) -> Result<EvidenceView, PicoError> {
    Ok(EvidenceView {
        id: bounded_string("evidence id", &item.id)?,
        class: bounded_string("evidence class", item.class.as_str())?,
        source_type: bounded_string("evidence source type", &item.source_type)?,
        safe_source_locator: if safe_source_locator(&item.source_locator) {
            Some(item.source_locator.clone())
        } else {
            None
        },
        subject: bounded_string("evidence subject", &item.subject)?,
        observation: bounded_string("evidence observation", &item.observation)?,
        captured_at: codec::ts_to_text(item.captured_at),
        freshness: bounded_string(
            "evidence freshness",
            item.freshness.as_deref().unwrap_or("UNKNOWN"),
        )?,
        sensitivity: bounded_string("evidence sensitivity", item.sensitivity.as_str())?,
        support_roles: Vec::new(),
    })
}

fn historical_graph(conn: &Connection, record: &FindingRecord) -> Result<SecurityGraph, PicoError> {
    let resources = ResourceRepo::new(conn).list()?;
    let relationships = RelationshipRepo::new(conn).list()?;
    let observations = ObservationRepo::new(conn).list_for_scan(&record.scan_id)?;
    let evidence = EvidenceRepo::new(conn).list()?;
    let relationship_evidence = RelationshipRepo::new(conn).evidence_links()?;
    project(ProjectionInput {
        scan_id: &record.scan_id,
        snapshot_version: GRAPH_SNAPSHOT_VERSION as u32,
        resources: &resources,
        relationships: &relationships,
        observations: &observations,
        evidence: &evidence,
        relationship_evidence: &relationship_evidence,
    })
    .map_err(|error| {
        integrity(format!(
            "historical projection for scan {} failed: {error}",
            record.scan_id
        ))
    })
}

fn resource_view(graph: &SecurityGraph, resource_id: &str) -> Result<ResourceView, PicoError> {
    let node = graph.node(resource_id).ok_or_else(|| {
        integrity(format!(
            "resource {resource_id} is absent from the historical graph"
        ))
    })?;
    Ok(ResourceView {
        id: bounded_string("resource id", &node.resource_id)?,
        canonical_key: bounded_string("resource key", &node.canonical_key)?,
        kind: bounded_string("resource kind", &node.kind)?,
        provider: bounded_string("resource provider", &node.provider)?,
        name: bounded_string("resource name", &node.name)?,
    })
}

fn path_steps(
    graph: &SecurityGraph,
    path: &AttackPathRecord,
    edges: &[AttackPathEdgeRecord],
) -> Result<Vec<PathStep>, PicoError> {
    if edges.is_empty() {
        return Err(integrity(format!("attack path {} has no edges", path.id)));
    }
    contiguous_positions(
        &format!("attack path {} edges", path.id),
        edges.iter().map(|edge| edge.position),
    )?;
    let mut previous_phase: Option<&str> = None;
    let mut current = path.source_resource_id.clone();
    let mut steps = Vec::with_capacity(edges.len());
    for edge in edges {
        if !matches!(edge.phase.as_str(), "INFLUENCE" | "AUTHORITY") {
            return Err(integrity(format!(
                "unsupported attack path edge phase {} on path {}",
                edge.phase, path.id
            )));
        }
        if !matches!(edge.traversal.as_str(), "FORWARD" | "REVERSE") {
            return Err(integrity(format!(
                "unsupported attack path traversal {} on path {}",
                edge.traversal, path.id
            )));
        }
        if previous_phase == Some("AUTHORITY") && edge.phase == "INFLUENCE" {
            return Err(integrity(format!(
                "attack path {} has INFLUENCE edges after AUTHORITY edges",
                path.id
            )));
        }
        if edge.phase == "AUTHORITY"
            && previous_phase == Some("INFLUENCE")
            && current != path.actor_resource_id
        {
            return Err(integrity(format!(
                "attack path {} phase transition does not land on the declared actor",
                path.id
            )));
        }
        let relationship = graph.edge(&edge.relationship_id).ok_or_else(|| {
            integrity(format!(
                "attack path {} references relationship {} absent from the historical graph",
                path.id, edge.relationship_id
            ))
        })?;
        let (from, to) = match edge.traversal.as_str() {
            "FORWARD" => (&relationship.from_resource_id, &relationship.to_resource_id),
            _ => (&relationship.to_resource_id, &relationship.from_resource_id),
        };
        if from != &current {
            return Err(integrity(format!(
                "attack path {} edges do not form one connected chain at position {}",
                path.id, edge.position
            )));
        }
        steps.push(PathStep {
            position: edge.position,
            phase: edge.phase.clone(),
            traversal: edge.traversal.clone(),
            relationship_id: bounded_string("relationship id", &relationship.relationship_id)?,
            relationship_kind: bounded_string("relationship kind", &relationship.kind)?,
            from_resource: resource_view(graph, from)?,
            to_resource: resource_view(graph, to)?,
            relationship_state: bounded_string("relationship state", relationship.state.as_str())?,
            evidence_ids: graph
                .evidence_index
                .relationship_evidence(&edge.relationship_id)
                .to_vec(),
        });
        current = to.clone();
        previous_phase = Some(edge.phase.as_str());
    }
    if current != path.sink_resource_id {
        return Err(integrity(format!(
            "attack path {} does not reach its declared sink through one connected chain",
            path.id
        )));
    }
    Ok(steps)
}

fn boundary_views(path: &AttackPathRecord) -> Result<Vec<BoundaryView>, PicoError> {
    let metadata = path.boundary_metadata.as_ref().ok_or_else(|| {
        integrity(format!(
            "active attack path {} has no boundary metadata",
            path.id
        ))
    })?;
    let evaluations: Vec<BoundaryEvaluation> =
        serde_json::from_value(metadata.clone()).map_err(|error| {
            integrity(format!(
                "attack path {} has malformed boundary metadata: {error}",
                path.id
            ))
        })?;
    let mut views = Vec::with_capacity(evaluations.len());
    for evaluation in &evaluations {
        if evaluation.decision != BoundaryDecision::DoesNotInterrupt {
            return Err(integrity(format!(
                "attack path {} carries boundary decision {} which violates active-Finding eligibility",
                path.id,
                evaluation.decision.as_str()
            )));
        }
        views.push(BoundaryView {
            kind: bounded_string("boundary kind", evaluation.kind.as_str())?,
            decision: bounded_string("boundary decision", evaluation.decision.as_str())?,
            enforcement: bounded_string("boundary enforcement", &evaluation.enforcement)?,
        });
    }
    Ok(views)
}

fn explained_paths(
    conn: &Connection,
    graph: &SecurityGraph,
    record: &FindingRecord,
    paths: &[AttackPathRecord],
    finding_evidence_ids: &BTreeSet<String>,
) -> Result<Vec<ExplainedPath>, PicoError> {
    let paths_repo = AttackPathRepo::new(conn);
    let mut output = Vec::with_capacity(paths.len());
    for path in paths {
        let edges = paths_repo.list_edges(&path.id)?;
        if edges.len() > MAX_EDGES_PER_PATH {
            return Err(integrity(format!(
                "attack path {} exceeds the supported edge budget of {MAX_EDGES_PER_PATH}",
                path.id
            )));
        }
        let steps = path_steps(graph, path, &edges)?;
        let path_evidence_rows = paths_repo.list_evidence(&path.id)?;
        contiguous_positions(
            &format!("attack path {} evidence", path.id),
            path_evidence_rows.iter().map(|row| row.position),
        )?;
        for row in &path_evidence_rows {
            resolve_same_scan_evidence(conn, &row.evidence_id, &record.scan_id)?;
            if !finding_evidence_ids.contains(&row.evidence_id) {
                return Err(integrity(format!(
                    "attack path {} evidence {} is outside the finding evidence set",
                    path.id, row.evidence_id
                )));
            }
        }
        output.push(ExplainedPath {
            id: bounded_string("attack path id", &path.id)?,
            fingerprint: bounded_string("attack path fingerprint", &path.fingerprint)?,
            disposition: bounded_string("path disposition", &path.disposition)?,
            source_trust: bounded_string("source trust", &path.source_trust)?,
            influence_strength: bounded_string("influence strength", &path.influence_strength)?,
            capability: bounded_string("capability", &path.capability)?,
            authority_resolution: bounded_string(
                "authority resolution",
                &path.authority_resolution,
            )?,
            sink_impact: bounded_string("sink impact", &path.sink_impact)?,
            source_resource_id: path.source_resource_id.clone(),
            actor_resource_id: path.actor_resource_id.clone(),
            sink_resource_id: path.sink_resource_id.clone(),
            steps,
            boundaries: boundary_views(path)?,
        });
    }
    Ok(output)
}

fn reason_views(
    conn: &Connection,
    graph: &SecurityGraph,
    record: &FindingRecord,
    linked_path_ids: &BTreeSet<String>,
    finding_evidence_ids: &BTreeSet<String>,
) -> Result<Vec<ReasonView>, PicoError> {
    let reasons: Vec<FindingReasonRecord> = FindingRepo::new(conn).list_reasons(&record.id)?;
    if reasons.len() > MAX_REASONS_PER_FINDING {
        return Err(integrity(format!(
            "finding {} exceeds the supported reason budget of {MAX_REASONS_PER_FINDING}",
            record.id
        )));
    }
    contiguous_positions(
        &format!("finding {} reasons", record.id),
        reasons.iter().map(|reason| reason.position),
    )?;
    let canonical_keys: BTreeSet<&str> = graph
        .nodes
        .iter()
        .map(|node| node.canonical_key.as_str())
        .collect();
    let node_ids: BTreeSet<&str> = graph
        .nodes
        .iter()
        .map(|node| node.resource_id.as_str())
        .collect();
    let mut views = Vec::with_capacity(reasons.len());
    for reason in &reasons {
        let code = parse_reason_code(&reason.reason_code)?;
        // Sprint 009 persists stable Resource identities here; canonical keys
        // remain accepted so the reference vocabulary can evolve without a
        // schema change.
        for resource_id in &reason.resource_ids {
            if !node_ids.contains(resource_id.as_str())
                && !canonical_keys.contains(resource_id.as_str())
            {
                return Err(integrity(format!(
                    "reason {} on finding {} references unknown resource {resource_id}",
                    reason.reason_code, record.id
                )));
            }
        }
        for relationship_id in &reason.relationship_ids {
            if graph.edge(relationship_id).is_none() {
                return Err(integrity(format!(
                    "reason {} on finding {} references unknown relationship {relationship_id}",
                    reason.reason_code, record.id
                )));
            }
        }
        for path_id in &reason.attack_path_ids {
            if !linked_path_ids.contains(path_id) {
                return Err(integrity(format!(
                    "reason {} on finding {} references unlinked attack path {path_id}",
                    reason.reason_code, record.id
                )));
            }
        }
        for evidence_id in &reason.evidence_ids {
            if !finding_evidence_ids.contains(evidence_id) {
                return Err(integrity(format!(
                    "reason {} on finding {} references unsupported evidence {evidence_id}",
                    reason.reason_code, record.id
                )));
            }
        }
        views.push(ReasonView {
            position: reason.position,
            code: bounded_string("reason code", code.as_str())?,
            explanation: reason_explanation(code).to_string(),
        });
    }
    Ok(views)
}

fn remediation_views(
    conn: &Connection,
    graph: &SecurityGraph,
    record: &FindingRecord,
    path_edges_by_phase: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<RemediationView>, PicoError> {
    let remediations: Vec<FindingRemediationRecord> =
        FindingRepo::new(conn).list_remediations(&record.id)?;
    if remediations.len() > MAX_REMEDIATIONS_PER_FINDING {
        return Err(integrity(format!(
            "finding {} exceeds the supported remediation budget of {MAX_REMEDIATIONS_PER_FINDING}",
            record.id
        )));
    }
    contiguous_positions(
        &format!("finding {} remediations", record.id),
        remediations.iter().map(|remediation| remediation.position),
    )?;
    let mut views = Vec::with_capacity(remediations.len());
    for remediation in &remediations {
        if !SUPPORTED_REMEDIATION_RULES.contains(&remediation.rule_id.as_str()) {
            return Err(integrity(format!(
                "unsupported remediation rule {} on finding {}",
                remediation.rule_id, record.id
            )));
        }
        if !matches!(remediation.cut_phase.as_str(), "INFLUENCE" | "AUTHORITY") {
            return Err(integrity(format!(
                "unsupported remediation cut phase {} on finding {}",
                remediation.cut_phase, record.id
            )));
        }
        let phase_edges = path_edges_by_phase
            .get(&remediation.cut_phase)
            .cloned()
            .unwrap_or_default();
        let mut endpoints: BTreeSet<&str> = BTreeSet::new();
        for relationship_id in &remediation.target_relationship_ids {
            if !phase_edges.contains(relationship_id) {
                return Err(integrity(format!(
                    "remediation {} on finding {} targets relationship {relationship_id} outside its declared phase",
                    remediation.rule_id, record.id
                )));
            }
            let edge = graph.edge(relationship_id).ok_or_else(|| {
                integrity(format!(
                    "remediation {} targets relationship {relationship_id} absent from the historical graph",
                    remediation.rule_id
                ))
            })?;
            endpoints.insert(edge.from_resource_id.as_str());
            endpoints.insert(edge.to_resource_id.as_str());
        }
        for resource_id in &remediation.target_resource_ids {
            if !endpoints.contains(resource_id.as_str()) {
                return Err(integrity(format!(
                    "remediation {} on finding {} targets resource {resource_id} outside its cut-point edges",
                    remediation.rule_id, record.id
                )));
            }
        }
        let target_resources = remediation
            .target_resource_ids
            .iter()
            .map(|resource_id| resource_view(graph, resource_id))
            .collect::<Result<Vec<_>, _>>()?;
        views.push(RemediationView {
            position: remediation.position,
            rule_id: bounded_string("remediation rule", &remediation.rule_id)?,
            title: bounded_string("remediation title", &remediation.title)?,
            description: bounded_string("remediation description", &remediation.description)?,
            security_effect: bounded_string(
                "remediation security effect",
                &remediation.security_effect,
            )?,
            cut_phase: bounded_string("cut phase", &remediation.cut_phase)?,
            target_resource_ids: remediation.target_resource_ids.clone(),
            target_resources,
            target_relationship_ids: remediation.target_relationship_ids.clone(),
        });
    }
    Ok(views)
}

fn validate_scan_and_analysis(
    conn: &Connection,
    record: &FindingRecord,
) -> Result<ScanBrief, PicoError> {
    let scan = ScanRepo::new(conn).get(&record.scan_id)?.ok_or_else(|| {
        integrity(format!(
            "finding {} references missing scan {}",
            record.id, record.scan_id
        ))
    })?;
    if scan.status != ScanStatus::Complete {
        return Err(integrity(format!(
            "finding {} references scan {} that is not COMPLETE",
            record.id, scan.id
        )));
    }
    if scan.completed_at.is_none() {
        return Err(integrity(format!(
            "finding {} references COMPLETE scan {} without a completion time",
            record.id, scan.id
        )));
    }
    let snapshot_version = scan
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("graph_snapshot_version"))
        .and_then(serde_json::Value::as_u64);
    if snapshot_version != Some(GRAPH_SNAPSHOT_VERSION) {
        return Err(integrity(format!(
            "scan {} declares an unsupported graph snapshot version",
            scan.id
        )));
    }
    let analysis = ScanAnalysisRepo::new(conn)
        .get(&record.scan_id)?
        .ok_or_else(|| {
            integrity(format!(
                "finding {} references scan {} without a recorded analysis",
                record.id, record.scan_id
            ))
        })?;
    let version = parse_u32_version("analysis_version", &analysis.analysis_version)?;
    if version != SUPPORTED_ANALYSIS_VERSION {
        return Err(integrity(format!(
            "unsupported analysis version {version} for scan {}",
            scan.id
        )));
    }
    if analysis.status != "COMPLETE" {
        return Err(integrity(format!(
            "finding {} references scan {} whose analysis is not COMPLETE",
            record.id, scan.id
        )));
    }
    Ok(scan_brief(&scan))
}

fn severity_basis(severity: Severity, first_path_source_trust: Option<&str>) -> String {
    match severity {
        Severity::Critical => match first_path_source_trust {
            Some("OPEN_WORLD") => {
                "Persisted OPEN_WORLD source trust on an otherwise eligible active production-mutation path.".to_string()
            }
            _ => {
                "Persisted PUBLIC_EXTERNAL source trust on an otherwise eligible active production-mutation path.".to_string()
            }
        },
        Severity::High => {
            "Persisted AUTHENTICATED_EXTERNAL source trust on an otherwise eligible active production-mutation path.".to_string()
        }
        Severity::Medium | Severity::Low | Severity::Info => {
            "Persisted severity recorded by the deterministic generation contract; no recomputation was performed.".to_string()
        }
    }
}

fn confidence_basis(confidence: Confidence) -> String {
    match confidence {
        Confidence::High => {
            "Persisted CONFIRMED/DERIVED security-critical Relationships with non-INFERRED same-scan supporting and production Evidence and exact or scoped authority.".to_string()
        }
        Confidence::Medium | Confidence::Low => {
            "Persisted confidence recorded by the deterministic generation contract; no recomputation was performed.".to_string()
        }
    }
}

fn uncertainty_statements() -> Vec<String> {
    vec![
        "This is observed potential reachability, not runtime use or exploitation.".to_string(),
        "The conclusion is limited to Pico's supported scan scope.".to_string(),
        "This Finding reflects its originating scan and may describe historical state.".to_string(),
        "Evidence freshness is UNKNOWN wherever no freshness value was persisted.".to_string(),
    ]
}

fn compose_detail(conn: &Connection, finding_id: &str) -> Result<FindingDetail, PicoError> {
    let repo = FindingRepo::new(conn);
    let record = repo.get(finding_id)?.ok_or_else(|| {
        PicoError::usage(format!(
            "Finding {finding_id} was not found in this workspace"
        ))
    })?;
    let (finding_version, severity, confidence) = validate_finding_header(&record)?;
    let scan = validate_scan_and_analysis(conn, &record)?;
    let paths = linked_paths(conn, &record)?;
    let evidence = finding_evidence_views(conn, &record)?;
    let graph = historical_graph(conn, &record)?;
    let explained = explained_paths(conn, &graph, &record, &paths, &evidence.ids)?;

    let linked_path_ids: BTreeSet<String> = paths.iter().map(|path| path.id.clone()).collect();
    let mut path_edges_by_phase: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let paths_repo = AttackPathRepo::new(conn);
    for path in &paths {
        for edge in paths_repo.list_edges(&path.id)? {
            path_edges_by_phase
                .entry(edge.phase.clone())
                .or_default()
                .insert(edge.relationship_id);
        }
    }

    let reasons = reason_views(conn, &graph, &record, &linked_path_ids, &evidence.ids)?;
    let remediations = remediation_views(conn, &graph, &record, &path_edges_by_phase)?;

    let scans = ScanRepo::new(conn);
    let newest_complete = scans.newest_complete()?;
    let newest_attempt = scans.newest_attempt()?;
    let (_, warning) = freshness_context(&newest_complete, &newest_attempt);
    let currentness = match &newest_complete {
        Some(latest) if latest.id == record.scan_id => Currentness::LatestComplete,
        Some(latest) => Currentness::Historical {
            newer_complete_scan_id: latest.id.clone(),
        },
        None => Currentness::Historical {
            newer_complete_scan_id: record.scan_id.clone(),
        },
    };

    let detail = FindingDetail {
        id: bounded_string("finding id", &record.id)?,
        fingerprint: bounded_string("finding fingerprint", &record.fingerprint)?,
        finding_version,
        scan,
        currentness,
        freshness_warning: warning,
        finding_class: bounded_string("finding class", &record.finding_class)?,
        status: bounded_string("finding status", &record.status)?,
        title: bounded_string("finding title", &record.title)?,
        summary: bounded_string("finding summary", &record.summary)?,
        severity: bounded_string("finding severity", &record.severity)?,
        confidence: bounded_string("finding confidence", &record.confidence)?,
        scope_note: SCOPE_NOTE.to_string(),
        severity_basis: severity_basis(
            severity,
            explained.first().map(|path| path.source_trust.as_str()),
        ),
        confidence_basis: confidence_basis(confidence),
        reasons,
        paths: explained,
        evidence: evidence.views,
        boundary_summary: BOUNDARY_SUMMARY.to_string(),
        uncertainties: uncertainty_statements(),
        remediations,
        remediation_note: REMEDIATION_NOTE.to_string(),
        created_at: codec::ts_to_text(record.created_at),
    };
    Ok(detail)
}

fn summarize_scan(conn: &Connection, scan_id: &str) -> Result<Vec<FindingSummary>, PicoError> {
    let records: Vec<FindingRecord> = FindingRepo::new(conn).list_for_scan(scan_id)?;
    if records.len() > MAX_FINDINGS_PER_SCAN {
        return Err(integrity(format!(
            "scan {scan_id} exceeds the supported Finding budget of {MAX_FINDINGS_PER_SCAN}"
        )));
    }
    let mut parsed = Vec::with_capacity(records.len());
    for record in &records {
        validate_finding_header(record)?;
        let linked = linked_paths(conn, record)?;
        let mut sinks = BTreeSet::new();
        for path in &linked {
            sinks.insert(path.sink_resource_id.clone());
        }
        parsed.push((
            (
                parse_severity(&record.severity)?,
                parse_confidence(&record.confidence)?,
            ),
            FindingSummary {
                id: bounded_string("finding id", &record.id)?,
                finding_class: bounded_string("finding class", &record.finding_class)?,
                status: bounded_string("finding status", &record.status)?,
                title: bounded_string("finding title", &record.title)?,
                severity: bounded_string("finding severity", &record.severity)?,
                confidence: bounded_string("finding confidence", &record.confidence)?,
                attack_path_count: linked.len() as u64,
                affected_sink_count: sinks.len() as u64,
                fingerprint: bounded_string("finding fingerprint", &record.fingerprint)?,
            },
        ));
    }
    parsed.sort_by(|(left_key, left), (right_key, right)| {
        right_key
            .0
            .cmp(&left_key.0)
            .then(right_key.1.cmp(&left_key.1))
            .then(left.title.cmp(&right.title))
            .then(left.fingerprint.cmp(&right.fingerprint))
            .then(left.id.cmp(&right.id))
    });
    Ok(parsed.into_iter().map(|(_, summary)| summary).collect())
}

fn enforce_dto_budget<T: Serialize>(value: &T) -> Result<(), PicoError> {
    let serialized = serde_json::to_vec(value)
        .map_err(|error| PicoError::database(format!("DTO serialization failed: {error}")))?;
    if serialized.len() > MAX_DTO_BYTES {
        return Err(integrity(format!(
            "composed explanation exceeds the supported size of {MAX_DTO_BYTES} bytes"
        )));
    }
    Ok(())
}
