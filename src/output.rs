//! Versioned, allowlisted public diff/history output, shared by CLI and MCP.
//! Application and persistence types are never serialized directly.
use serde::Serialize;

use crate::application::compare_contract::{DiffProvenance, DiffSideProvenance};
use crate::application::diff::{ComparedVia, DiffNotComparableReason};
use crate::application::graph_diff::{GraphDelta, GraphSubject, GraphSubjectDiff};
use crate::application::{
    DiffFinding, FindingDiffResult, FindingLifecycleChange, Freshness, ScanBrief, ScanHistory,
};
use crate::shared::{terminal_safe, PicoError};

pub const SCHEMA_VERSION: u32 = 1;
const HISTORY_LIMIT: &str = "First-seen and reappearance refer only to retained COMPLETE observations at or before the destination scan; earlier pruned history is unknown.";
const ABSENCE_LIMIT: &str = "A finding-set disappearance or unobserved graph subject does not by itself confirm remediation; consult attribution and disappearance_confirmed.";

#[derive(Debug, Serialize)]
pub struct DiffOutput {
    schema_version: u32,
    command: &'static str,
    #[serde(flatten)]
    result: DiffResult,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DiffResult {
    InsufficientHistory {
        reason: &'static str,
        newest_complete: Option<Scan>,
        newest_attempt: Option<Scan>,
        freshness: &'static str,
        limitations: Vec<&'static str>,
    },
    NotComparable {
        from: Scan,
        to: Scan,
        newest_attempt: Option<Scan>,
        freshness: &'static str,
        compared_via: &'static str,
        provenance: Provenance,
        reason: &'static str,
        gaps: Vec<Gap>,
        limitations: Vec<&'static str>,
    },
    Ready {
        from: Scan,
        to: Scan,
        newest_attempt: Option<Scan>,
        freshness: &'static str,
        compared_via: &'static str,
        provenance: Provenance,
        findings: Findings,
        graph: Box<Graph>,
        attribution: Attribution,
        limitations: Vec<&'static str>,
    },
}

#[derive(Debug, Serialize)]
struct Scan {
    id: String,
    status: String,
    completed_at: Option<String>,
}
impl From<&ScanBrief> for Scan {
    fn from(v: &ScanBrief) -> Self {
        Self {
            id: safe(&v.id),
            status: safe(&v.status),
            completed_at: optional(&v.completed_at),
        }
    }
}
#[derive(Debug, Serialize)]
struct Contract {
    comparison_contract_version: u32,
    graph_snapshot_version: u64,
    analysis_version: u32,
    finding_version: u32,
}
#[derive(Debug, Serialize)]
struct SideProvenance {
    pico_version: String,
    contract: Option<Contract>,
}
impl From<&DiffSideProvenance> for SideProvenance {
    fn from(v: &DiffSideProvenance) -> Self {
        Self {
            pico_version: safe(&v.pico_version),
            contract: v.contract.map(|c| Contract {
                comparison_contract_version: c.comparison_contract_version,
                graph_snapshot_version: c.graph_snapshot_version,
                analysis_version: c.analysis_version,
                finding_version: c.finding_version,
            }),
        }
    }
}
#[derive(Debug, Serialize)]
struct Provenance {
    from: SideProvenance,
    to: SideProvenance,
}
impl From<&DiffProvenance> for Provenance {
    fn from(v: &DiffProvenance) -> Self {
        Self {
            from: (&v.from).into(),
            to: (&v.to).into(),
        }
    }
}
#[derive(Debug, Serialize)]
struct Gap {
    side: &'static str,
    field: String,
}
#[derive(Debug, Serialize)]
struct Findings {
    unchanged: Vec<Finding>,
    appeared: Vec<Finding>,
    not_observed: Vec<Finding>,
    weakened: Vec<Lifecycle>,
    strengthened: Vec<Lifecycle>,
    uncertain: Vec<Lifecycle>,
}
#[derive(Debug, Serialize)]
struct Finding {
    id: String,
    fingerprint: String,
    family_fingerprint: String,
    title: String,
    severity: String,
    confidence: String,
    cause: Option<Cause>,
}
#[derive(Debug, Serialize)]
struct Cause {
    summary: String,
    graph_key: Option<String>,
    field: Option<String>,
    from_value: Option<String>,
    to_value: Option<String>,
    evidence_source_types: Vec<String>,
}
impl From<&DiffFinding> for Finding {
    fn from(v: &DiffFinding) -> Self {
        Self {
            id: safe(&v.id),
            fingerprint: safe(&v.fingerprint),
            family_fingerprint: safe(&v.family_fingerprint),
            title: safe(&v.title),
            severity: safe(&v.severity),
            confidence: safe(&v.confidence),
            cause: v.cause.as_ref().map(|c| Cause {
                summary: safe(&c.summary),
                graph_key: optional(&c.graph_key),
                field: optional(&c.field),
                from_value: optional(&c.from_value),
                to_value: optional(&c.to_value),
                evidence_source_types: c.evidence_source_types.iter().map(|s| safe(s)).collect(),
            }),
        }
    }
}
#[derive(Debug, Serialize)]
struct Lifecycle {
    from: Finding,
    to: Finding,
    deltas: Vec<RatingDelta>,
}
#[derive(Debug, Serialize)]
struct RatingDelta {
    field: String,
    from_value: String,
    to_value: String,
}
impl From<&FindingLifecycleChange> for Lifecycle {
    fn from(v: &FindingLifecycleChange) -> Self {
        Self {
            from: (&v.from).into(),
            to: (&v.to).into(),
            deltas: v
                .deltas
                .iter()
                .map(|d| RatingDelta {
                    field: safe(&d.field),
                    from_value: safe(&d.from_value),
                    to_value: safe(&d.to_value),
                })
                .collect(),
        }
    }
}
#[derive(Debug, Serialize)]
struct Graph {
    resources: Subjects,
    relationships: Subjects,
}
#[derive(Debug, Serialize)]
struct Subjects {
    unchanged: Vec<Subject>,
    first_seen: Vec<Subject>,
    reappeared: Vec<Subject>,
    changed: Vec<Subject>,
    not_observed: Vec<Subject>,
}
impl From<&GraphSubjectDiff> for Subjects {
    fn from(v: &GraphSubjectDiff) -> Self {
        Self {
            unchanged: v.unchanged.iter().map(Into::into).collect(),
            first_seen: v.first_seen.iter().map(Into::into).collect(),
            reappeared: v.reappeared.iter().map(Into::into).collect(),
            changed: v.changed.iter().map(Into::into).collect(),
            not_observed: v.disappeared.iter().map(Into::into).collect(),
        }
    }
}
#[derive(Debug, Serialize)]
struct Subject {
    canonical_key: String,
    kind: String,
    provider: Option<String>,
    name: Option<String>,
    state: Option<String>,
    first_seen_scan_id: String,
    last_seen_scan_id: String,
    deltas: Vec<Delta>,
}
impl From<&GraphSubject> for Subject {
    fn from(v: &GraphSubject) -> Self {
        Self {
            canonical_key: safe(&v.canonical_key),
            kind: safe(&v.kind),
            provider: optional(&v.provider),
            name: optional(&v.name),
            state: optional(&v.state),
            first_seen_scan_id: safe(&v.first_seen_scan_id),
            last_seen_scan_id: safe(&v.last_seen_scan_id),
            deltas: v.deltas.iter().map(Into::into).collect(),
        }
    }
}
#[derive(Debug, Serialize)]
struct Delta {
    field: String,
    before: TypedValue,
    after: TypedValue,
}
#[derive(Debug, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum TypedValue {
    Missing,
    Null,
    Redacted,
    Value(serde_json::Value),
}
impl From<&GraphDelta> for Delta {
    fn from(v: &GraphDelta) -> Self {
        Self {
            field: safe(&v.field),
            before: typed(&v.field, &v.before),
            after: typed(&v.field, &v.after),
        }
    }
}

#[derive(Debug, Serialize)]
struct Attribution {
    version: u32,
    graph_changes: Vec<ChangeAttribution>,
    finding_changes: Vec<ChangeAttribution>,
}
#[derive(Debug, Serialize)]
struct ChangeAttribution {
    key: String,
    lifecycle: String,
    classification: &'static str,
    reasons: Vec<String>,
    before: SideEvidence,
    after: SideEvidence,
    disappearance_confirmed: bool,
}
#[derive(Debug, Serialize)]
struct SideEvidence {
    source_types: Vec<String>,
    evidence_ids: Vec<String>,
    supported_fields: Vec<String>,
    coverage: &'static str,
}

fn safe(s: &str) -> String {
    if token_shaped(s) {
        "[redacted]".into()
    } else {
        terminal_safe(s)
    }
}
fn optional(s: &Option<String>) -> Option<String> {
    s.as_deref().map(safe)
}
fn selection(v: &ComparedVia) -> &'static str {
    match v {
        ComparedVia::LatestTwo => "latest_two",
        ComparedVia::ExplicitPair => "explicit_pair",
    }
}
fn freshness(v: Freshness, via: &ComparedVia) -> &'static str {
    if matches!(via, ComparedVia::ExplicitPair) {
        return "not_assessed";
    }
    match v {
        Freshness::LatestComplete => "latest_complete",
        Freshness::NewerIncomplete => "newer_incomplete_attempt",
    }
}

/// Project a successful query, including typed query limitations.
pub fn diff(v: &FindingDiffResult) -> DiffOutput {
    let result = match v {
        FindingDiffResult::NoCompleteScan => DiffResult::InsufficientHistory {
            reason: "no_complete_scan",
            newest_complete: None,
            newest_attempt: None,
            freshness: "not_assessed",
            limitations: vec![HISTORY_LIMIT],
        },
        FindingDiffResult::NeedPrevious {
            newest_complete,
            newest_attempt,
        } => DiffResult::InsufficientHistory {
            reason: "need_previous_complete",
            newest_complete: Some(newest_complete.into()),
            newest_attempt: newest_attempt.as_ref().map(Into::into),
            freshness: "not_assessed",
            limitations: vec![HISTORY_LIMIT],
        },
        FindingDiffResult::NotComparable(d) => DiffResult::NotComparable {
            from: (&d.from).into(),
            to: (&d.to).into(),
            newest_attempt: d.newest_attempt.as_ref().map(Into::into),
            freshness: freshness(d.freshness, &d.compared_via),
            compared_via: selection(&d.compared_via),
            provenance: (&d.provenance).into(),
            reason: match d.reason {
                DiffNotComparableReason::ProvenanceUnavailable => "provenance_unavailable",
                DiffNotComparableReason::ContractChanged => "contract_changed",
                DiffNotComparableReason::ContractUnsupported => "contract_unsupported",
            },
            gaps: d
                .gaps
                .iter()
                .map(|g| Gap {
                    side: match g.side {
                        crate::application::compare_contract::DiffSide::From => "from",
                        crate::application::compare_contract::DiffSide::To => "to",
                    },
                    field: g.field.as_str().to_string(),
                })
                .collect(),
            limitations: vec![HISTORY_LIMIT],
        },
        FindingDiffResult::Ready(d) => DiffResult::Ready {
            from: (&d.from).into(),
            to: (&d.to).into(),
            newest_attempt: d.newest_attempt.as_ref().map(Into::into),
            freshness: freshness(d.freshness, &d.compared_via),
            compared_via: selection(&d.compared_via),
            provenance: (&d.provenance).into(),
            findings: Findings {
                unchanged: d.unchanged.iter().map(Into::into).collect(),
                appeared: d.appeared.iter().map(Into::into).collect(),
                not_observed: d.disappeared.iter().map(Into::into).collect(),
                weakened: d.weakened.iter().map(Into::into).collect(),
                strengthened: d.strengthened.iter().map(Into::into).collect(),
                uncertain: d.uncertain.iter().map(Into::into).collect(),
            },
            graph: Box::new(Graph {
                resources: (&d.graph.resources).into(),
                relationships: (&d.graph.relationships).into(),
            }),
            attribution: attribution(&d.attribution),
            limitations: vec![HISTORY_LIMIT, ABSENCE_LIMIT],
        },
    };
    DiffOutput {
        schema_version: SCHEMA_VERSION,
        command: "diff",
        result,
    }
}

#[derive(Debug, Serialize)]
pub struct HistoryOutput {
    schema_version: u32,
    command: &'static str,
    status: &'static str,
    retained_history_only: bool,
    complete_scan_count: usize,
    oldest_complete_scan_id: Option<String>,
    newest_complete_scan_id: Option<String>,
    scans: Vec<HistoryScan>,
    limitations: Vec<&'static str>,
}
#[derive(Debug, Serialize)]
struct HistoryScan {
    id: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    finding_count: u64,
}
/// Project the actual retained catalog, without claiming unpruned history.
pub fn history(v: &ScanHistory) -> HistoryOutput {
    let mut scans: Vec<_> = v.scans.iter().collect();
    scans.sort_by(|a, b| (&a.started_at, &a.id).cmp(&(&b.started_at, &b.id)));
    let mut complete: Vec<_> = scans
        .iter()
        .copied()
        .filter(|s| s.status == "COMPLETE")
        .collect();
    complete.sort_by(|a, b| {
        (&a.completed_at, &a.started_at, &a.id).cmp(&(&b.completed_at, &b.started_at, &b.id))
    });
    HistoryOutput { schema_version: SCHEMA_VERSION, command: "history", status: "ready", retained_history_only: true, complete_scan_count: complete.len(), oldest_complete_scan_id: complete.first().map(|s| safe(&s.id)), newest_complete_scan_id: complete.last().map(|s| safe(&s.id)), scans: scans.iter().map(|s| HistoryScan { id: safe(&s.id), status: safe(&s.status), started_at: optional(&s.started_at), completed_at: optional(&s.completed_at), finding_count: s.finding_count }).collect(), limitations: vec!["Only retained scans are listed; earlier pruned history is unknown. Incomplete attempts are context and are never diff operands."] }
}

#[derive(Debug, Serialize)]
pub struct ErrorOutput {
    schema_version: u32,
    command: String,
    status: &'static str,
    error: PublicError,
}
#[derive(Debug, Serialize)]
struct PublicError {
    code: &'static str,
    message: &'static str,
}
/// Stable error categories deliberately never include untrusted error details.
pub fn error(command: &str, v: &PicoError) -> ErrorOutput {
    let (code, message) = match v { PicoError::Usage(_) => ("usage_error", "Invalid query arguments; diff requires two distinct retained COMPLETE scans in chronological order, or no IDs."), PicoError::Scan(_) | PicoError::Init(_) | PicoError::Database(_) | PicoError::Migration(_) => ("database_error", "Cannot read a supported, consistent Pico database."), PicoError::Io(_) => ("io_error", "Cannot access the workspace."), _ => ("internal_error", "The query could not be completed.") };
    ErrorOutput {
        schema_version: SCHEMA_VERSION,
        command: safe(command),
        status: "error",
        error: PublicError { code, message },
    }
}

fn typed(field: &str, value: &crate::application::graph_diff::TypedValue) -> TypedValue {
    use crate::application::graph_diff::TypedValue as Input;
    match value {
        Input::Missing => TypedValue::Missing,
        Input::Null => TypedValue::Null,
        Input::Value(value) => {
            let projected = match value {
                serde_json::Value::String(s) if !token_shaped(s) => {
                    Some(serde_json::Value::String(safe(s)))
                }
                serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(value.clone()),
                serde_json::Value::Array(items)
                    if matches!(field, "granted_permissions" | "unknown_reasons") =>
                {
                    items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .filter(|s| !token_shaped(s))
                                .map(|s| serde_json::Value::String(safe(s)))
                        })
                        .collect::<Option<Vec<_>>>()
                        .map(serde_json::Value::Array)
                }
                _ => None,
            };
            projected
                .map(TypedValue::Value)
                .unwrap_or(TypedValue::Redacted)
        }
    }
}
fn token_shaped(value: &str) -> bool {
    ["ghp_", "gho_", "ghs_", "ghr_", "github_pat_", "cfut_"]
        .iter()
        .any(|prefix| value.contains(prefix))
}
fn attribution(v: &crate::application::ComparisonAttribution) -> Attribution {
    Attribution {
        version: v.version,
        graph_changes: v.graph_changes.iter().map(change_attribution).collect(),
        finding_changes: v.finding_changes.iter().map(change_attribution).collect(),
    }
}
fn change_attribution(v: &crate::application::ChangeAttribution) -> ChangeAttribution {
    use crate::application::AttributionClass;
    ChangeAttribution {
        key: safe(&v.key),
        lifecycle: if v.lifecycle == "disappeared" {
            "not_observed".to_string()
        } else {
            safe(&v.lifecycle)
        },
        classification: match v.classification {
            AttributionClass::ObservedEnvironmentChange => "observed_environment_change",
            AttributionClass::EvidenceChange => "evidence_change",
            AttributionClass::Mixed => "mixed",
            AttributionClass::Unattributed => "unattributed",
        },
        reasons: v.reasons.iter().map(|s| safe(s)).collect(),
        before: side_evidence(&v.before),
        after: side_evidence(&v.after),
        disappearance_confirmed: v.disappearance_confirmed,
    }
}
fn side_evidence(v: &crate::application::SideEvidence) -> SideEvidence {
    use crate::application::attribution::CoverageState;
    SideEvidence {
        source_types: v.source_types.iter().map(|s| safe(s)).collect(),
        evidence_ids: v.evidence_ids.iter().map(|s| safe(s)).collect(),
        supported_fields: v.supported_fields.iter().map(|s| safe(s)).collect(),
        coverage: match v.coverage {
            CoverageState::Inspected => "inspected",
            CoverageState::Incomplete => "incomplete",
            CoverageState::NotAttempted => "not_attempted",
            CoverageState::Unknown => "unknown",
        },
    }
}
