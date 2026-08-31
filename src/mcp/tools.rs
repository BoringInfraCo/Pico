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
        terminal_safe(&error.to_string()),
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
    diagnostics: Option<SafeScanDiagnostics>,
    github_credentials: Vec<SafeGitHubCredentialView>,
}

impl SafeList {
    fn new(list: &FindingList) -> Self {
        SafeList {
            selected_scan: list.selected_scan.as_ref().map(SafeScanBrief::new),
            newest_scan_attempt: list.newest_scan_attempt.as_ref().map(SafeScanBrief::new),
            freshness: list.freshness,
            freshness_warning: safe_optional(list.freshness_warning.as_deref()),
            findings: list.findings.iter().map(SafeFindingSummary::new).collect(),
            diagnostics: list.diagnostics.as_ref().map(SafeScanDiagnostics::new),
            github_credentials: list
                .github_credentials
                .iter()
                .map(SafeGitHubCredentialView::new)
                .collect(),
        }
    }
}

/// Machine-readable per-GitHub-credential authority entry mirrored from the
/// application `GitHubCredentialView` (SPRINT-021 R7). All strings pass through
/// `terminal_safe` before serialization; raw token values never enter this
/// shape.
#[derive(Serialize)]
struct SafeGitHubCredentialView {
    credential_type: String,
    authority_resolution: String,
    permission_state: String,
    unknown_reasons: Vec<String>,
}

impl SafeGitHubCredentialView {
    fn new(credential: &crate::application::GitHubCredentialView) -> Self {
        SafeGitHubCredentialView {
            credential_type: terminal_safe(&credential.credential_type),
            authority_resolution: terminal_safe(&credential.authority_resolution),
            permission_state: terminal_safe(&credential.permission_state),
            unknown_reasons: safe_strings(&credential.unknown_reasons),
        }
    }
}

/// Machine-readable scan diagnostics mirrored from
/// `findings::diagnostics::ScanDiagnostics`. All provider-supplied strings pass
/// through `terminal_safe` before serialization; the structure is an exact
/// field-for-field projection so the MCP payload and the application DTO
/// serialize identically for the same scan.
#[derive(Serialize)]
struct SafeScanDiagnostics {
    provider_statuses: Vec<SafeProviderDiagnostic>,
    scan_status: String,
    partial_reason: Option<String>,
    suppressed: Vec<SafeSuppressedReason>,
    reduced_confidence: Vec<SafeConfidenceNote>,
}

impl SafeScanDiagnostics {
    fn new(diagnostics: &crate::findings::diagnostics::ScanDiagnostics) -> Self {
        SafeScanDiagnostics {
            provider_statuses: diagnostics
                .provider_statuses
                .iter()
                .map(SafeProviderDiagnostic::new)
                .collect(),
            scan_status: terminal_safe(&diagnostics.scan_status),
            partial_reason: diagnostics.partial_reason.as_deref().map(terminal_safe),
            suppressed: diagnostics
                .suppressed
                .iter()
                .map(SafeSuppressedReason::new)
                .collect(),
            reduced_confidence: diagnostics
                .reduced_confidence
                .iter()
                .map(SafeConfidenceNote::new)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SafeProviderDiagnostic {
    name: String,
    reachable: bool,
    problems: Vec<String>,
}

impl SafeProviderDiagnostic {
    fn new(provider: &crate::findings::diagnostics::ProviderDiagnostic) -> Self {
        SafeProviderDiagnostic {
            name: terminal_safe(&provider.name),
            reachable: provider.reachable,
            problems: safe_strings(&provider.problems),
        }
    }
}

#[derive(Serialize)]
struct SafeSuppressedReason {
    fingerprint: String,
    reason: String,
}

impl SafeSuppressedReason {
    fn new(reason: &crate::findings::diagnostics::SuppressedReason) -> Self {
        SafeSuppressedReason {
            fingerprint: terminal_safe(&reason.fingerprint),
            reason: terminal_safe(&reason.reason),
        }
    }
}

#[derive(Serialize)]
struct SafeConfidenceNote {
    fingerprint: String,
    edges: Vec<(String, String, f64)>,
}

impl SafeConfidenceNote {
    fn new(note: &crate::findings::diagnostics::ConfidenceNote) -> Self {
        SafeConfidenceNote {
            fingerprint: terminal_safe(&note.fingerprint),
            edges: note
                .edges
                .iter()
                .map(|(edge_key, freshness, penalty)| {
                    (terminal_safe(edge_key), terminal_safe(freshness), *penalty)
                })
                .collect(),
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
    /// Per-GitHub-credential authority facts for the finding's originating scan
    /// (SPRINT-021 R7), one entry per observed GitHub credential.
    github_credentials: Vec<SafeGitHubCredentialView>,
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
            github_credentials: detail
                .github_credentials
                .iter()
                .map(SafeGitHubCredentialView::new)
                .collect(),
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
    effective_bash_capability: Option<String>,
    bash_boundary: Option<String>,
    /// Per-agent effective Bash posture, one entry per
    /// `agent:<provider>|can_execute|shell:bash` edge in the scan graph
    /// (SPRINT-020 R7). Present alongside the legacy single-agent fields so mixed
    /// OpenCode + Claude Code workspaces surface every actor.
    agents: Vec<SafeAgentBashView>,
    github_influence: Vec<SafeGitHubInfluenceView>,
    cloudflare_authority: Vec<SafeCloudflareAuthorityView>,
}

#[derive(Serialize)]
struct SafeAgentBashView {
    provider: String,
    effective_bash_capability: String,
    bash_boundary: Option<String>,
}

impl SafeAgentBashView {
    fn new(agent: &crate::application::findings::AgentBashView) -> Self {
        SafeAgentBashView {
            provider: terminal_safe(&agent.provider),
            effective_bash_capability: terminal_safe(&agent.effective_bash_capability),
            bash_boundary: agent.bash_boundary.as_deref().map(terminal_safe),
        }
    }
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
            effective_bash_capability: path.effective_bash_capability.as_deref().map(terminal_safe),
            bash_boundary: path.bash_boundary.as_deref().map(terminal_safe),
            agents: path.agents.iter().map(SafeAgentBashView::new).collect(),
            github_influence: path
                .github_influence
                .iter()
                .map(SafeGitHubInfluenceView::new)
                .collect(),
            cloudflare_authority: path
                .cloudflare_authority
                .iter()
                .map(SafeCloudflareAuthorityView::new)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SafeCloudflareAuthorityView {
    worker_key: String,
    credential_type: String,
    granted_permissions: Vec<String>,
    authority_resolution: String,
    permission_state: String,
    account_scope_state: String,
    zone_scoped: bool,
}

impl SafeCloudflareAuthorityView {
    fn new(entry: &crate::application::findings::CloudflareAuthorityView) -> Self {
        SafeCloudflareAuthorityView {
            worker_key: terminal_safe(&entry.worker_key),
            credential_type: terminal_safe(&entry.credential_type),
            granted_permissions: safe_strings(&entry.granted_permissions),
            authority_resolution: terminal_safe(&entry.authority_resolution),
            permission_state: terminal_safe(&entry.permission_state),
            account_scope_state: terminal_safe(&entry.account_scope_state),
            zone_scoped: entry.zone_scoped,
        }
    }
}

#[derive(Serialize)]
struct SafeGitHubInfluenceView {
    tool_name: String,
    content_class: String,
    trust: String,
    influence_strength: String,
}

impl SafeGitHubInfluenceView {
    fn new(entry: &crate::application::findings::GitHubInfluenceView) -> Self {
        SafeGitHubInfluenceView {
            tool_name: terminal_safe(&entry.tool_name),
            content_class: terminal_safe(&entry.content_class),
            trust: terminal_safe(&entry.trust),
            influence_strength: terminal_safe(&entry.influence_strength),
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

#[cfg(test)]
mod tests {
    use super::{SafeExplainedPath, SafeGitHubCredentialView, SafeScanDiagnostics};
    use crate::application::ExplainedPath;
    use crate::findings::diagnostics::{
        ConfidenceNote, ProviderDiagnostic, ScanDiagnostics, SuppressedReason,
    };

    /// Asserts the MCP `SafeScanDiagnostics` mirror serializes every structured
    /// diagnostics field with the exact application-DTO field names, so the
    /// `list_findings` payload carries `provider_statuses`, `scan_status`,
    /// `partial_reason`, `suppressed`, and `reduced_confidence` (SPRINT-019 R7).
    #[test]
    fn safe_scan_diagnostics_serializes_structured_fields() {
        let detail = ScanDiagnostics {
            provider_statuses: vec![
                ProviderDiagnostic {
                    name: "opencode".to_string(),
                    reachable: true,
                    problems: vec![],
                },
                ProviderDiagnostic {
                    name: "cloudflare".to_string(),
                    reachable: false,
                    problems: vec![
                        "cloudflare token verification failed: provider returned HTTP 401"
                            .to_string(),
                    ],
                },
            ],
            scan_status: "PARTIAL".to_string(),
            partial_reason: Some("cloudflare".to_string()),
            suppressed: vec![SuppressedReason {
                fingerprint: "sha256:suppressed-candidate".to_string(),
                reason: "edge evidence is STALE; candidate not confirmed".to_string(),
            }],
            reduced_confidence: vec![ConfidenceNote {
                fingerprint: "sha256:active-finding".to_string(),
                edges: vec![(
                    "agent:opencode|can_execute|shell:bash".to_string(),
                    "STALE".to_string(),
                    0.25,
                )],
            }],
        };
        let safe = SafeScanDiagnostics::new(&detail);
        let value = serde_json::to_value(&safe).expect("serializable");

        assert_eq!(
            value["provider_statuses"].as_array().unwrap().len(),
            2,
            "both provider statuses must be present"
        );
        assert_eq!(value["scan_status"], serde_json::json!("PARTIAL"));
        assert_eq!(value["partial_reason"], serde_json::json!("cloudflare"));
        assert_eq!(
            value["suppressed"][0]["fingerprint"],
            serde_json::json!("sha256:suppressed-candidate")
        );
        assert_eq!(
            value["reduced_confidence"][0]["fingerprint"],
            serde_json::json!("sha256:active-finding")
        );
        let edge = value["reduced_confidence"][0]["edges"][0].clone();
        assert_eq!(
            edge,
            serde_json::json!(["agent:opencode|can_execute|shell:bash", "STALE", 0.25]),
            "edge tuple (edge_key, freshness, penalty) must serialize as a 3-element array"
        );
    }

    /// Asserts the MCP `SafeGitHubCredentialView` mirror serializes the
    /// credential type, authority resolution tier, permission state, and
    /// unknown-reason codes with the exact application-DTO field names, so the
    /// `list_findings` / `get_finding` payloads carry `github_credentials`
    /// (SPRINT-021 R7).
    #[test]
    fn safe_github_credential_view_serializes_authority_facts() {
        use crate::application::GitHubCredentialView;
        for (credential, expected) in [
            (
                GitHubCredentialView {
                    credential_type: "classic_pat".to_string(),
                    authority_resolution: "EXACT".to_string(),
                    permission_state: "REPO_WRITE".to_string(),
                    unknown_reasons: vec![],
                },
                serde_json::json!({
                    "credential_type": "classic_pat",
                    "authority_resolution": "EXACT",
                    "permission_state": "REPO_WRITE",
                    "unknown_reasons": [],
                }),
            ),
            (
                GitHubCredentialView {
                    credential_type: "fine_grained_pat".to_string(),
                    authority_resolution: "UNKNOWN".to_string(),
                    permission_state: "READ_OR_UNKNOWN".to_string(),
                    unknown_reasons: vec![
                        "GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE".to_string()
                    ],
                },
                serde_json::json!({
                    "credential_type": "fine_grained_pat",
                    "authority_resolution": "UNKNOWN",
                    "permission_state": "READ_OR_UNKNOWN",
                    "unknown_reasons": ["GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE"],
                }),
            ),
        ] {
            let safe = SafeGitHubCredentialView::new(&credential);
            let value = serde_json::to_value(&safe).expect("serializable");
            assert_eq!(value, expected);
        }
    }

    /// Asserts the MCP mirror serializes the effective Bash capability and its
    /// interrupting boundary for every resolved OpenCode posture (SPRINT-016 R7).
    #[test]
    fn safe_explained_path_serializes_effective_bash_capability() {
        let cases = [
            ("APPROVAL_GATED", Some("MANDATORY_APPROVAL")),
            ("DENIED", Some("HARD_DENY")),
            ("SANDBOXED", Some("SANDBOX")),
            ("AUTO_ALLOW", None),
        ];
        for (label, boundary) in cases {
            let path = ExplainedPath {
                id: "p".to_string(),
                fingerprint: "sha256:p".to_string(),
                disposition: "ACTIVE".to_string(),
                source_trust: "PUBLIC_EXTERNAL".to_string(),
                influence_strength: "AGENT_RETRIEVABLE".to_string(),
                capability: "EXECUTE".to_string(),
                authority_resolution: "EXACT".to_string(),
                sink_impact: "PRODUCTION".to_string(),
                source_resource_id: "s".to_string(),
                actor_resource_id: "a".to_string(),
                sink_resource_id: "k".to_string(),
                steps: vec![],
                boundaries: vec![],
                effective_bash_capability: Some(label.to_string()),
                bash_boundary: boundary.map(str::to_string),
                agents: vec![],
                github_influence: vec![],
                cloudflare_authority: vec![],
            };
            let safe = SafeExplainedPath::new(&path);
            let value = serde_json::to_value(&safe).expect("serializable");
            assert_eq!(
                value["effective_bash_capability"],
                serde_json::json!(label),
                "MCP field must carry the effective Bash capability for {label}"
            );
            assert_eq!(
                value["bash_boundary"],
                serde_json::json!(boundary),
                "MCP field must carry the interrupting boundary for {label}"
            );
        }
    }

    /// Asserts the MCP mirror serializes the per-agent effective Bash posture
    /// array for a mixed OpenCode + Claude Code explained path, while keeping the
    /// legacy single-agent fields intact (SPRINT-020 R7).
    #[test]
    fn safe_explained_path_serializes_per_agent_bash() {
        use crate::application::findings::AgentBashView;
        let path = ExplainedPath {
            id: "p".to_string(),
            fingerprint: "sha256:p".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_INJECTABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            source_resource_id: "s".to_string(),
            actor_resource_id: "a".to_string(),
            sink_resource_id: "k".to_string(),
            steps: vec![],
            boundaries: vec![],
            effective_bash_capability: Some("AUTO_ALLOW".to_string()),
            bash_boundary: None,
            agents: vec![
                AgentBashView {
                    provider: "opencode".to_string(),
                    effective_bash_capability: "AUTO_ALLOW".to_string(),
                    bash_boundary: None,
                },
                AgentBashView {
                    provider: "claude".to_string(),
                    effective_bash_capability: "APPROVAL_GATED".to_string(),
                    bash_boundary: Some("MANDATORY_APPROVAL".to_string()),
                },
            ],
            github_influence: vec![],
            cloudflare_authority: vec![],
        };
        let safe = SafeExplainedPath::new(&path);
        let value = serde_json::to_value(&safe).expect("serializable");
        let array = value["agents"].as_array().expect("agents must be an array");
        assert_eq!(array.len(), 2);
        assert_eq!(
            array[0],
            serde_json::json!({
                "provider": "opencode",
                "effective_bash_capability": "AUTO_ALLOW",
                "bash_boundary": null,
            })
        );
        assert_eq!(
            array[1],
            serde_json::json!({
                "provider": "claude",
                "effective_bash_capability": "APPROVAL_GATED",
                "bash_boundary": "MANDATORY_APPROVAL",
            })
        );
        assert_eq!(
            value["effective_bash_capability"],
            serde_json::json!("AUTO_ALLOW"),
            "legacy single-agent field must stay intact"
        );
        assert_eq!(value["bash_boundary"], serde_json::Value::Null);
    }

    /// Asserts the MCP mirror serializes per-tool GitHub MCP influence entries
    /// for both a read and a write tool (SPRINT-017 R7).
    #[test]
    fn safe_explained_path_serializes_github_influence() {
        use crate::application::findings::GitHubInfluenceView;
        let path = ExplainedPath {
            id: "p".to_string(),
            fingerprint: "sha256:p".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_INJECTABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            source_resource_id: "s".to_string(),
            actor_resource_id: "a".to_string(),
            sink_resource_id: "k".to_string(),
            steps: vec![],
            boundaries: vec![],
            effective_bash_capability: None,
            bash_boundary: None,
            agents: vec![],
            github_influence: vec![
                GitHubInfluenceView {
                    tool_name: "issue_read".to_string(),
                    content_class: "github:public:issue-content".to_string(),
                    trust: "PUBLIC_EXTERNAL".to_string(),
                    influence_strength: "AGENT_INJECTABLE".to_string(),
                },
                GitHubInfluenceView {
                    tool_name: "create_issue".to_string(),
                    content_class: "github:write:issue".to_string(),
                    trust: "UNKNOWN".to_string(),
                    influence_strength: "AGENT_MUTABLE".to_string(),
                },
            ],
            cloudflare_authority: vec![],
        };
        let safe = SafeExplainedPath::new(&path);
        let value = serde_json::to_value(&safe).expect("serializable");
        let array = value["github_influence"]
            .as_array()
            .expect("github_influence must be an array");
        assert_eq!(array.len(), 2);
        assert_eq!(
            array[0],
            serde_json::json!({
                "tool_name": "issue_read",
                "content_class": "github:public:issue-content",
                "trust": "PUBLIC_EXTERNAL",
                "influence_strength": "AGENT_INJECTABLE",
            })
        );
        assert_eq!(
            array[1],
            serde_json::json!({
                "tool_name": "create_issue",
                "content_class": "github:write:issue",
                "trust": "UNKNOWN",
                "influence_strength": "AGENT_MUTABLE",
            })
        );
    }

    /// Asserts the MCP mirror serializes per-Cloudflare-edge authority entries
    /// with the credential type, granted permission groups, resolution tier,
    /// permission state, scope state, and zone-scoped flag (SPRINT-018 R7).
    #[test]
    fn safe_explained_path_serializes_cloudflare_authority() {
        use crate::application::findings::CloudflareAuthorityView;
        let path = ExplainedPath {
            id: "p".to_string(),
            fingerprint: "sha256:p".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_INJECTABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            source_resource_id: "s".to_string(),
            actor_resource_id: "a".to_string(),
            sink_resource_id: "k".to_string(),
            steps: vec![],
            boundaries: vec![],
            effective_bash_capability: None,
            bash_boundary: None,
            agents: vec![],
            github_influence: vec![],
            cloudflare_authority: vec![
                CloudflareAuthorityView {
                    worker_key: "cloudflare:worker:account-1234567890123456:tag".to_string(),
                    credential_type: "api_token".to_string(),
                    granted_permissions: vec!["Workers Scripts Write".to_string()],
                    authority_resolution: "EXACT".to_string(),
                    permission_state: "WORKERS_SCRIPTS_WRITE".to_string(),
                    account_scope_state: "IN_SCOPE".to_string(),
                    zone_scoped: false,
                },
                CloudflareAuthorityView {
                    worker_key: "cloudflare:worker:global:*".to_string(),
                    credential_type: "api_key".to_string(),
                    granted_permissions: vec![],
                    authority_resolution: "EXACT".to_string(),
                    permission_state: "GLOBAL_API_KEY".to_string(),
                    account_scope_state: "IN_SCOPE".to_string(),
                    zone_scoped: false,
                },
            ],
        };
        let safe = SafeExplainedPath::new(&path);
        let value = serde_json::to_value(&safe).expect("serializable");
        let array = value["cloudflare_authority"]
            .as_array()
            .expect("cloudflare_authority must be an array");
        assert_eq!(array.len(), 2);
        assert_eq!(
            array[0],
            serde_json::json!({
                "worker_key": "cloudflare:worker:account-1234567890123456:tag",
                "credential_type": "api_token",
                "granted_permissions": ["Workers Scripts Write"],
                "authority_resolution": "EXACT",
                "permission_state": "WORKERS_SCRIPTS_WRITE",
                "account_scope_state": "IN_SCOPE",
                "zone_scoped": false,
            })
        );
        assert_eq!(array[1]["credential_type"], serde_json::json!("api_key"));
        assert_eq!(
            array[1]["permission_state"],
            serde_json::json!("GLOBAL_API_KEY")
        );
    }
}
