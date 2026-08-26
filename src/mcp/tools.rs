//! The MCP tool surface: the two read-only descriptors and dispatch into
//! `FindingQueryService` (SPRINT-011.md §7-§13).
//!
//! Owns only protocol shaping. Persisted strings pass through
//! `terminal_safe` inside MCP-owned mirror structs before serialization;
//! application types are never mutated.

use std::path::Path;

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::application::{
    findings_list_guidance, findings_list_state, Currentness, FindingDetail, FindingList,
    FindingQueryService, FindingsListState, Freshness, ScanBrief,
};
use crate::mcp::protocol::{APPLICATION_ERROR, INTERNAL_ERROR, INVALID_PARAMS};
use crate::shared::{terminal_safe, PicoError};

const LIST_FINDINGS: &str = "list_findings";
const GET_FINDING: &str = "get_finding";

/// A tool-dispatch failure mapped onto a JSON-RPC error code.
pub struct ToolError {
    pub code: i64,
    pub message: String,
}

fn tool_error(code: i64, message: impl Into<String>) -> ToolError {
    ToolError {
        code,
        message: message.into(),
    }
}

/// Returns the two tool descriptors in stable order, both readOnlyHint.
pub fn descriptors() -> Vec<Value> {
    vec![
        json!({
            "name": LIST_FINDINGS,
            "description":
                "List security Findings from the newest COMPLETE scan in this workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "annotations": { "readOnlyHint": true },
        }),
        json!({
            "name": GET_FINDING,
            "description": "Get one persisted security Finding by its exact ID.",
            "inputSchema": {
                "type": "object",
                "properties": { "id": { "type": "string", "minLength": 1 } },
                "required": ["id"],
                "additionalProperties": false,
            },
            "annotations": { "readOnlyHint": true },
        }),
    ]
}

/// Dispatches one tools/call into the read-only application query layer.
pub fn call(params: &Value, workspace: &Path) -> Result<Value, ToolError> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| tool_error(INVALID_PARAMS, "tool name is required"))?;
    let arguments = match params.get("arguments") {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => Value::Object(Map::new()),
    };
    match name {
        LIST_FINDINGS => list_findings(workspace),
        GET_FINDING => get_finding(arguments.get("id"), workspace),
        other => Err(tool_error(INVALID_PARAMS, format!("unknown tool: {other}"))),
    }
}

fn list_findings(workspace: &Path) -> Result<Value, ToolError> {
    match FindingQueryService::list_latest(workspace) {
        Ok(list) => text_content(&ListPayload::new(&list)),
        Err(error) => Err(application_tool_error(&error)),
    }
}

fn get_finding(id: Option<&Value>, workspace: &Path) -> Result<Value, ToolError> {
    let id = match id {
        Some(Value::String(raw)) if !raw.trim().is_empty() => raw,
        _ => {
            return Err(tool_error(
                INVALID_PARAMS,
                "a non-empty Finding ID is required",
            ))
        }
    };
    match FindingQueryService::get(workspace, id) {
        Ok(detail) => text_content(&SafeDetail::new(&detail)),
        Err(error) => Err(application_tool_error(&error)),
    }
}

fn application_tool_error(error: &PicoError) -> ToolError {
    tool_error(
        match error {
            PicoError::Usage(_) => INVALID_PARAMS,
            _ => APPLICATION_ERROR,
        },
        error.to_string(),
    )
}

fn text_content<T: Serialize>(payload: &T) -> Result<Value, ToolError> {
    let text = serde_json::to_string_pretty(payload).map_err(|error| {
        tool_error(
            INTERNAL_ERROR,
            format!("tool result shaping failed: {error}"),
        )
    })?;
    Ok(json!({ "content": [ { "type": "text", "text": text } ] }))
}

#[derive(Serialize)]
struct ListPayload {
    #[serde(flatten)]
    list: SafeList,
    state: FindingsListState,
    guidance: Vec<String>,
}

impl ListPayload {
    fn new(list: &FindingList) -> Self {
        ListPayload {
            list: SafeList::new(list),
            state: findings_list_state(list),
            guidance: findings_list_guidance(findings_list_state(list), list),
        }
    }
}

#[derive(Serialize)]
struct SafeList {
    selected_scan: Option<SafeScanBrief>,
    newest_scan_attempt: Option<SafeScanBrief>,
    freshness: Freshness,
    freshness_warning: Option<String>,
    findings: Vec<SafeFindingSummary>,
}

impl SafeList {
    fn new(list: &FindingList) -> Self {
        SafeList {
            selected_scan: list.selected_scan.as_ref().map(SafeScanBrief::new),
            newest_scan_attempt: list.newest_scan_attempt.as_ref().map(SafeScanBrief::new),
            freshness: list.freshness,
            freshness_warning: safe_optional(list.freshness_warning.as_deref()),
            findings: list.findings.iter().map(SafeFindingSummary::new).collect(),
        }
    }
}

#[derive(Serialize)]
struct SafeScanBrief {
    id: String,
    status: String,
    completed_at: Option<String>,
}

impl SafeScanBrief {
    fn new(brief: &ScanBrief) -> Self {
        SafeScanBrief {
            id: terminal_safe(&brief.id),
            status: terminal_safe(&brief.status),
            completed_at: safe_optional(brief.completed_at.as_deref()),
        }
    }
}

#[derive(Serialize)]
struct SafeFindingSummary {
    id: String,
    finding_class: String,
    status: String,
    title: String,
    severity: String,
    confidence: String,
    attack_path_count: u64,
    affected_sink_count: u64,
    fingerprint: String,
}

impl SafeFindingSummary {
    fn new(summary: &crate::application::FindingSummary) -> Self {
        SafeFindingSummary {
            id: terminal_safe(&summary.id),
            finding_class: terminal_safe(&summary.finding_class),
            status: terminal_safe(&summary.status),
            title: terminal_safe(&summary.title),
            severity: terminal_safe(&summary.severity),
            confidence: terminal_safe(&summary.confidence),
            attack_path_count: summary.attack_path_count,
            affected_sink_count: summary.affected_sink_count,
            fingerprint: terminal_safe(&summary.fingerprint),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SafeCurrentness {
    LatestComplete,
    Historical { newer_complete_scan_id: String },
}

impl SafeCurrentness {
    fn new(currentness: &Currentness) -> Self {
        match currentness {
            Currentness::LatestComplete => SafeCurrentness::LatestComplete,
            Currentness::Historical {
                newer_complete_scan_id,
            } => SafeCurrentness::Historical {
                newer_complete_scan_id: terminal_safe(newer_complete_scan_id),
            },
        }
    }
}

#[derive(Serialize)]
struct SafeDetail {
    id: String,
    fingerprint: String,
    attack_path_fingerprints: Vec<String>,
    finding_version: u32,
    scan: SafeScanBrief,
    currentness: SafeCurrentness,
    freshness_warning: Option<String>,
    finding_class: String,
    status: String,
    title: String,
    summary: String,
    severity: String,
    confidence: String,
    scope_note: String,
    severity_basis: String,
    confidence_basis: String,
    weakest_evidence: String,
    reasons: Vec<SafeReasonView>,
    paths: Vec<SafeExplainedPath>,
    evidence: Vec<SafeEvidenceView>,
    boundary_summary: String,
    uncertainties: Vec<String>,
    remediations: Vec<SafeRemediationView>,
    remediation_note: String,
    created_at: String,
}

impl SafeDetail {
    fn new(detail: &FindingDetail) -> Self {
        SafeDetail {
            id: terminal_safe(&detail.id),
            fingerprint: terminal_safe(&detail.fingerprint),
            attack_path_fingerprints: safe_strings(&detail.attack_path_fingerprints),
            finding_version: detail.finding_version,
            scan: SafeScanBrief::new(&detail.scan),
            currentness: SafeCurrentness::new(&detail.currentness),
            freshness_warning: safe_optional(detail.freshness_warning.as_deref()),
            finding_class: terminal_safe(&detail.finding_class),
            status: terminal_safe(&detail.status),
            title: terminal_safe(&detail.title),
            summary: terminal_safe(&detail.summary),
            severity: terminal_safe(&detail.severity),
            confidence: terminal_safe(&detail.confidence),
            scope_note: terminal_safe(&detail.scope_note),
            severity_basis: terminal_safe(&detail.severity_basis),
            confidence_basis: terminal_safe(&detail.confidence_basis),
            weakest_evidence: terminal_safe(&detail.weakest_evidence),
            reasons: detail.reasons.iter().map(SafeReasonView::new).collect(),
            paths: detail.paths.iter().map(SafeExplainedPath::new).collect(),
            evidence: detail.evidence.iter().map(SafeEvidenceView::new).collect(),
            boundary_summary: terminal_safe(&detail.boundary_summary),
            uncertainties: safe_strings(&detail.uncertainties),
            remediations: detail
                .remediations
                .iter()
                .map(SafeRemediationView::new)
                .collect(),
            remediation_note: terminal_safe(&detail.remediation_note),
            created_at: terminal_safe(&detail.created_at),
        }
    }
}

#[derive(Serialize)]
struct SafeReasonView {
    position: u32,
    code: String,
    explanation: String,
}

impl SafeReasonView {
    fn new(reason: &crate::application::ReasonView) -> Self {
        SafeReasonView {
            position: reason.position,
            code: terminal_safe(&reason.code),
            explanation: terminal_safe(&reason.explanation),
        }
    }
}

#[derive(Serialize)]
struct SafeExplainedPath {
    id: String,
    fingerprint: String,
    disposition: String,
    source_trust: String,
    influence_strength: String,
    capability: String,
    authority_resolution: String,
    sink_impact: String,
    source_resource_id: String,
    actor_resource_id: String,
    sink_resource_id: String,
    steps: Vec<SafePathStep>,
    boundaries: Vec<SafeBoundaryView>,
}

impl SafeExplainedPath {
    fn new(path: &crate::application::ExplainedPath) -> Self {
        SafeExplainedPath {
            id: terminal_safe(&path.id),
            fingerprint: terminal_safe(&path.fingerprint),
            disposition: terminal_safe(&path.disposition),
            source_trust: terminal_safe(&path.source_trust),
            influence_strength: terminal_safe(&path.influence_strength),
            capability: terminal_safe(&path.capability),
            authority_resolution: terminal_safe(&path.authority_resolution),
            sink_impact: terminal_safe(&path.sink_impact),
            source_resource_id: terminal_safe(&path.source_resource_id),
            actor_resource_id: terminal_safe(&path.actor_resource_id),
            sink_resource_id: terminal_safe(&path.sink_resource_id),
            steps: path.steps.iter().map(SafePathStep::new).collect(),
            boundaries: path.boundaries.iter().map(SafeBoundaryView::new).collect(),
        }
    }
}

#[derive(Serialize)]
struct SafePathStep {
    position: u32,
    phase: String,
    traversal: String,
    relationship_id: String,
    relationship_kind: String,
    from_resource: SafeResourceView,
    to_resource: SafeResourceView,
    relationship_state: String,
    evidence_ids: Vec<String>,
    supporting_evidence: Vec<SafeEdgeEvidenceProvenance>,
}

impl SafePathStep {
    fn new(step: &crate::application::PathStep) -> Self {
        SafePathStep {
            position: step.position,
            phase: terminal_safe(&step.phase),
            traversal: terminal_safe(&step.traversal),
            relationship_id: terminal_safe(&step.relationship_id),
            relationship_kind: terminal_safe(&step.relationship_kind),
            from_resource: SafeResourceView::new(&step.from_resource),
            to_resource: SafeResourceView::new(&step.to_resource),
            relationship_state: terminal_safe(&step.relationship_state),
            evidence_ids: safe_strings(&step.evidence_ids),
            supporting_evidence: step
                .supporting_evidence
                .iter()
                .map(SafeEdgeEvidenceProvenance::new)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SafeEdgeEvidenceProvenance {
    evidence_id: String,
    safe_source_locator: Option<String>,
    captured_at: String,
    freshness: String,
}

impl SafeEdgeEvidenceProvenance {
    fn new(provenance: &crate::application::findings::EdgeEvidenceProvenance) -> Self {
        SafeEdgeEvidenceProvenance {
            evidence_id: terminal_safe(&provenance.evidence_id),
            safe_source_locator: safe_optional(provenance.safe_source_locator.as_deref()),
            captured_at: terminal_safe(&provenance.captured_at),
            freshness: terminal_safe(&provenance.freshness),
        }
    }
}

#[derive(Serialize)]
struct SafeResourceView {
    id: String,
    canonical_key: String,
    kind: String,
    provider: String,
    name: String,
}

impl SafeResourceView {
    fn new(resource: &crate::application::ResourceView) -> Self {
        SafeResourceView {
            id: terminal_safe(&resource.id),
            canonical_key: terminal_safe(&resource.canonical_key),
            kind: terminal_safe(&resource.kind),
            provider: terminal_safe(&resource.provider),
            name: terminal_safe(&resource.name),
        }
    }
}

#[derive(Serialize)]
struct SafeBoundaryView {
    kind: String,
    decision: String,
    enforcement: String,
}

impl SafeBoundaryView {
    fn new(boundary: &crate::application::BoundaryView) -> Self {
        SafeBoundaryView {
            kind: terminal_safe(&boundary.kind),
            decision: terminal_safe(&boundary.decision),
            enforcement: terminal_safe(&boundary.enforcement),
        }
    }
}

#[derive(Serialize)]
struct SafeEvidenceView {
    id: String,
    class: String,
    source_type: String,
    safe_source_locator: Option<String>,
    subject: String,
    observation: String,
    captured_at: String,
    freshness: String,
    sensitivity: String,
    support_roles: Vec<String>,
}

impl SafeEvidenceView {
    fn new(evidence: &crate::application::EvidenceView) -> Self {
        SafeEvidenceView {
            id: terminal_safe(&evidence.id),
            class: terminal_safe(&evidence.class),
            source_type: terminal_safe(&evidence.source_type),
            safe_source_locator: safe_optional(evidence.safe_source_locator.as_deref()),
            subject: terminal_safe(&evidence.subject),
            observation: terminal_safe(&evidence.observation),
            captured_at: terminal_safe(&evidence.captured_at),
            freshness: terminal_safe(&evidence.freshness),
            sensitivity: terminal_safe(&evidence.sensitivity),
            support_roles: safe_strings(&evidence.support_roles),
        }
    }
}

#[derive(Serialize)]
struct SafeRemediationView {
    position: u32,
    rule_id: String,
    title: String,
    description: String,
    security_effect: String,
    cut_phase: String,
    target_resource_ids: Vec<String>,
    target_resources: Vec<SafeResourceView>,
    target_relationship_ids: Vec<String>,
    target_relationship_descriptions: Vec<String>,
}

impl SafeRemediationView {
    fn new(remediation: &crate::application::RemediationView) -> Self {
        SafeRemediationView {
            position: remediation.position,
            rule_id: terminal_safe(&remediation.rule_id),
            title: terminal_safe(&remediation.title),
            description: terminal_safe(&remediation.description),
            security_effect: terminal_safe(&remediation.security_effect),
            cut_phase: terminal_safe(&remediation.cut_phase),
            target_resource_ids: safe_strings(&remediation.target_resource_ids),
            target_resources: remediation
                .target_resources
                .iter()
                .map(SafeResourceView::new)
                .collect(),
            target_relationship_ids: safe_strings(&remediation.target_relationship_ids),
            target_relationship_descriptions: safe_strings(
                &remediation.target_relationship_descriptions,
            ),
        }
    }
}

fn safe_optional(value: Option<&str>) -> Option<String> {
    value.map(terminal_safe)
}

fn safe_strings(values: &[String]) -> Vec<String> {
    values.iter().map(|value| terminal_safe(value)).collect()
}
