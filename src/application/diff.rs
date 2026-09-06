//! `pico diff` application service (SPRINT-024.md).
//!
//! Compares Findings from the last two COMPLETE scans by fingerprint.
//! Incomplete attempts never participate as a comparison side.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use crate::application::cause::{attach_causes, FindingCause};
use crate::application::compare_contract::{
    load_side_provenance, ComparisonContractVersions, ComparisonProvenanceGap, DiffProvenance,
    DiffSide, DiffSideProvenance, SideProvenance, CURRENT_COMPARISON_CONTRACT,
};
use crate::application::graph_diff::{compare_graph, validate_complete_chronology, GraphDiff};
use crate::application::{Freshness, ScanBrief};
use crate::domain::Scan;
use crate::persistence::{codec, require_schema_version, Database, ScanRepo};
use crate::shared::PicoError;

/// One Finding identity in a diff side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffFinding {
    pub id: String,
    pub fingerprint: String,
    pub family_fingerprint: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub cause: Option<FindingCause>,
}

/// One rating field change within a lifecycle pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingRatingDelta {
    pub field: String,
    pub from_value: String,
    pub to_value: String,
}

/// One family-linked Finding whose full fingerprint changed between scans.
///
/// Lifecycle pairs never receive graph causes; their Cause lines come from
/// `deltas` at render time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingLifecycleChange {
    pub from: DiffFinding,
    pub to: DiffFinding,
    pub deltas: Vec<FindingRatingDelta>,
}

/// Fingerprint-set comparison of two COMPLETE scans.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingDiff {
    pub from: ScanBrief,
    pub to: ScanBrief,
    pub newest_attempt: Option<ScanBrief>,
    pub freshness: Freshness,
    pub freshness_warning: Option<String>,
    pub compared_via: ComparedVia,
    /// Persisted comparison-contract provenance for both sides (SPRINT-029
    /// §5.3). On `Ready` both contracts are `Some`, equal, and equal to
    /// `CURRENT_COMPARISON_CONTRACT`.
    pub provenance: DiffProvenance,
    pub unchanged: Vec<DiffFinding>,
    pub appeared: Vec<DiffFinding>,
    pub disappeared: Vec<DiffFinding>,
    pub weakened: Vec<FindingLifecycleChange>,
    pub strengthened: Vec<FindingLifecycleChange>,
    pub uncertain: Vec<FindingLifecycleChange>,
    pub graph: GraphDiff,
    pub attribution: crate::application::ComparisonAttribution,
}

/// How the comparison pair was selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ComparedVia {
    /// Last two COMPLETE scans (implicit).
    LatestTwo,
    /// Explicit scan ids from the user.
    ExplicitPair,
}

/// Why a comparison pair is not comparable (SPRINT-029 §5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiffNotComparableReason {
    /// Required legacy provenance cannot be derived for at least one side.
    ProvenanceUnavailable,
    /// Both tuples are derivable but differ.
    ContractChanged,
    /// Both tuples are equal but unsupported by this build.
    ContractUnsupported,
}

/// A comparison pair that may not be compared (SPRINT-029 §5.3).
///
/// This is a successful read result, not an error: the CLI explains why
/// comparison was skipped and never renders it as an all-clear. No Finding,
/// graph, or Cause comparison input is materialized for this pair.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffNotComparable {
    pub from: ScanBrief,
    pub to: ScanBrief,
    pub newest_attempt: Option<ScanBrief>,
    pub freshness: Freshness,
    pub freshness_warning: Option<String>,
    pub compared_via: ComparedVia,
    pub provenance: DiffProvenance,
    pub reason: DiffNotComparableReason,
    /// Missing provenance components by side in tuple-field order. Non-empty
    /// only for `ProvenanceUnavailable`.
    pub gaps: Vec<ComparisonProvenanceGap>,
}

/// Outcome of `pico diff` when two COMPLETE scans may not exist yet.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum FindingDiffResult {
    NoCompleteScan,
    NeedPrevious {
        newest_complete: ScanBrief,
        newest_attempt: Option<ScanBrief>,
    },
    NotComparable(DiffNotComparable),
    Ready(FindingDiff),
}

/// Read-only comparison of persisted COMPLETE scans.
pub struct DiffService;

impl DiffService {
    /// Diff Findings between two explicit COMPLETE scans by id.
    pub fn compare(
        workspace: &Path,
        from_id: &str,
        to_id: &str,
    ) -> Result<FindingDiffResult, PicoError> {
        if from_id == to_id {
            return Err(PicoError::usage("cannot diff a scan with itself"));
        }
        with_read_snapshot(workspace, |conn| {
            let scans = ScanRepo::new(conn);
            let from_scan = scans
                .get(from_id)?
                .ok_or_else(|| PicoError::usage(format!("scan {from_id} not found")))?;
            let to_scan = scans
                .get(to_id)?
                .ok_or_else(|| PicoError::usage(format!("scan {to_id} not found")))?;
            if from_scan.status != crate::domain::ScanStatus::Complete {
                return Err(PicoError::usage(format!(
                    "scan {from_id} is {}; diff requires COMPLETE",
                    from_scan.status.as_str()
                )));
            }
            if to_scan.status != crate::domain::ScanStatus::Complete {
                return Err(PicoError::usage(format!(
                    "scan {to_id} is {}; diff requires COMPLETE",
                    to_scan.status.as_str()
                )));
            }
            let complete = scans.list_complete()?;
            validate_complete_chronology(&from_scan, &to_scan, &complete)?;
            let ComparisonGuardDecision {
                provenance,
                outcome,
            } = evaluate_contract_guard(conn, &from_scan, &to_scan)?;
            match outcome {
                ComparisonGuardOutcome::NotComparable { reason, gaps } => {
                    Ok(FindingDiffResult::NotComparable(DiffNotComparable {
                        from: scan_brief(&from_scan),
                        to: scan_brief(&to_scan),
                        newest_attempt: None,
                        freshness: Freshness::LatestComplete,
                        freshness_warning: None,
                        compared_via: ComparedVia::ExplicitPair,
                        provenance,
                        reason,
                        gaps,
                    }))
                }
                ComparisonGuardOutcome::Proceed(contract) => {
                    // A Ready result guarantees both provenance contracts are
                    // Some, equal, and equal to the current contract.
                    debug_assert_eq!(contract, CURRENT_COMPARISON_CONTRACT);
                    let from_findings = findings_by_fingerprint(conn, &from_scan.id)?;
                    let to_findings = findings_by_fingerprint(conn, &to_scan.id)?;
                    let graph = compare_graph(conn, &from_scan, &to_scan, &complete)?;
                    let mut diff = compare(
                        scan_brief(&from_scan),
                        scan_brief(&to_scan),
                        None,
                        Freshness::LatestComplete,
                        None,
                        ComparedVia::ExplicitPair,
                        provenance,
                        from_findings,
                        to_findings,
                        graph,
                    );
                    attach_causes(
                        conn,
                        &from_scan.id,
                        &to_scan.id,
                        &mut diff.appeared,
                        &mut diff.disappeared,
                        &diff.graph,
                    )?;
                    crate::application::attribution::attach_attribution(
                        conn, &from_scan, &to_scan, &mut diff,
                    )?;
                    Ok(FindingDiffResult::Ready(diff))
                }
            }
        })
    }

    /// Diff Findings from the last two COMPLETE scans in `workspace`.
    pub fn latest(workspace: &Path) -> Result<FindingDiffResult, PicoError> {
        with_read_snapshot(workspace, |conn| {
            let scans = ScanRepo::new(conn);
            let complete = scans.list_complete()?;
            let newest_attempt = scans.newest_attempt()?;
            match complete.as_slice() {
                [] => Ok(FindingDiffResult::NoCompleteScan),
                [newest] => Ok(FindingDiffResult::NeedPrevious {
                    newest_complete: scan_brief(newest),
                    newest_attempt: newest_attempt.as_ref().map(scan_brief),
                }),
                [to, from, ..] => {
                    let (freshness, freshness_warning) =
                        freshness_context(to, newest_attempt.as_ref());
                    validate_complete_chronology(from, to, &complete)?;
                    let ComparisonGuardDecision {
                        provenance,
                        outcome,
                    } = evaluate_contract_guard(conn, from, to)?;
                    match outcome {
                        ComparisonGuardOutcome::NotComparable { reason, gaps } => {
                            Ok(FindingDiffResult::NotComparable(DiffNotComparable {
                                from: scan_brief(from),
                                to: scan_brief(to),
                                newest_attempt: newest_attempt.as_ref().map(scan_brief),
                                freshness,
                                freshness_warning,
                                compared_via: ComparedVia::LatestTwo,
                                provenance,
                                reason,
                                gaps,
                            }))
                        }
                        ComparisonGuardOutcome::Proceed(contract) => {
                            // A Ready result guarantees both provenance
                            // contracts are Some, equal, and current.
                            debug_assert_eq!(contract, CURRENT_COMPARISON_CONTRACT);
                            let from_findings = findings_by_fingerprint(conn, &from.id)?;
                            let to_findings = findings_by_fingerprint(conn, &to.id)?;
                            let graph = compare_graph(conn, from, to, &complete)?;
                            let mut diff = compare(
                                scan_brief(from),
                                scan_brief(to),
                                newest_attempt.as_ref().map(scan_brief),
                                freshness,
                                freshness_warning,
                                ComparedVia::LatestTwo,
                                provenance,
                                from_findings,
                                to_findings,
                                graph,
                            );
                            attach_causes(
                                conn,
                                &from.id,
                                &to.id,
                                &mut diff.appeared,
                                &mut diff.disappeared,
                                &diff.graph,
                            )?;
                            crate::application::attribution::attach_attribution(
                                conn, from, to, &mut diff,
                            )?;
                            Ok(FindingDiffResult::Ready(diff))
                        }
                    }
                }
            }
        })
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

/// Guard outcome for one comparison pair (SPRINT-029 §5.4, frozen ordering).
struct ComparisonGuardDecision {
    /// Persisted provenance for both sides; attached to every result (Ready
    /// and NotComparable alike). Built from version columns and metadata only.
    provenance: DiffProvenance,
    outcome: ComparisonGuardOutcome,
}

enum ComparisonGuardOutcome {
    /// Both tuples are present, equal, and current; the comparison may load
    /// Findings, graph sets, and causes.
    Proceed(ComparisonContractVersions),
    /// Comparison is skipped before any diff input is materialized.
    NotComparable {
        reason: DiffNotComparableReason,
        gaps: Vec<ComparisonProvenanceGap>,
    },
}

/// Evaluate the comparison-contract guard for one COMPLETE pair
/// (SPRINT-029 §5.4): unavailable provenance → `ProvenanceUnavailable`, a
/// differing tuple → `ContractChanged`, an equal non-current tuple →
/// `ContractUnsupported`, and only the current tuple proceeds.
///
/// Provenance loading inspects version columns and metadata only (the R8
/// structural guarantee): no Finding fingerprint sets, no graph-set
/// projection, and no causes are materialized before the guard decides
/// `Proceed`.
fn evaluate_contract_guard(
    conn: &Connection,
    from: &Scan,
    to: &Scan,
) -> Result<ComparisonGuardDecision, PicoError> {
    let from_provenance = load_side_provenance(conn, from)?;
    let to_provenance = load_side_provenance(conn, to)?;
    let provenance = DiffProvenance {
        from: side_provenance(from, &from_provenance),
        to: side_provenance(to, &to_provenance),
    };
    let outcome = match (&from_provenance, &to_provenance) {
        (SideProvenance::Available(from_contract), SideProvenance::Available(to_contract)) => {
            if from_contract != to_contract {
                ComparisonGuardOutcome::NotComparable {
                    reason: DiffNotComparableReason::ContractChanged,
                    gaps: Vec::new(),
                }
            } else if *from_contract != CURRENT_COMPARISON_CONTRACT {
                ComparisonGuardOutcome::NotComparable {
                    reason: DiffNotComparableReason::ContractUnsupported,
                    gaps: Vec::new(),
                }
            } else {
                ComparisonGuardOutcome::Proceed(*from_contract)
            }
        }
        _ => {
            // Side gaps in From-then-To order, each side's fields in
            // tuple-field declaration order (from the loader).
            let mut gaps = Vec::new();
            for (side, loaded) in [
                (DiffSide::From, &from_provenance),
                (DiffSide::To, &to_provenance),
            ] {
                if let SideProvenance::Unavailable(fields) = loaded {
                    gaps.extend(fields.iter().map(|field| ComparisonProvenanceGap {
                        side,
                        field: *field,
                    }));
                }
            }
            ComparisonGuardOutcome::NotComparable {
                reason: DiffNotComparableReason::ProvenanceUnavailable,
                gaps,
            }
        }
    };
    Ok(ComparisonGuardDecision {
        provenance,
        outcome,
    })
}

/// Project one side's loaded provenance into the public DTO. An unavailable
/// side carries no contract but still reports its validated package version.
fn side_provenance(scan: &Scan, loaded: &SideProvenance) -> DiffSideProvenance {
    DiffSideProvenance {
        pico_version: scan.pico_version.clone(),
        contract: match loaded {
            SideProvenance::Available(contract) => Some(*contract),
            SideProvenance::Unavailable(_) => None,
        },
    }
}

/// Loads Findings by full fingerprint, including the family_fingerprint
/// column. A DB missing that column is a corrupted or unmigrated DB claiming
/// a current schema version; the error propagates fail-closed (no retry).
/// A NULL `family_fingerprint` is likewise corruption (schema v6 declares the
/// column NOT NULL) and fails closed; the legacy `''` value stays valid.
fn findings_by_fingerprint(
    conn: &Connection,
    scan_id: &str,
) -> Result<BTreeMap<String, DiffFinding>, PicoError> {
    let mut statement = conn
        .prepare(
            "SELECT id, fingerprint, family_fingerprint,
                    title, severity, confidence
             FROM findings WHERE scan_id = ?1 ORDER BY fingerprint, id",
        )
        .map_err(|error| PicoError::database(error.to_string()))?;
    let rows = statement
        .query_map([scan_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| PicoError::database(error.to_string()))?;
    let mut by_fingerprint = BTreeMap::new();
    for row in rows {
        let (id, fingerprint, family, title, severity, confidence) =
            row.map_err(|error| PicoError::database(error.to_string()))?;
        let Some(family) = family else {
            return Err(PicoError::database(format!(
                "finding {id} has NULL family_fingerprint; database integrity violated"
            )));
        };
        by_fingerprint
            .entry(fingerprint.clone())
            .or_insert(DiffFinding {
                id,
                fingerprint,
                family_fingerprint: family,
                title,
                severity,
                confidence,
                cause: None,
            });
    }
    Ok(by_fingerprint)
}

#[allow(clippy::too_many_arguments)]
fn compare(
    from: ScanBrief,
    to: ScanBrief,
    newest_attempt: Option<ScanBrief>,
    freshness: Freshness,
    freshness_warning: Option<String>,
    compared_via: ComparedVia,
    provenance: DiffProvenance,
    from_findings: BTreeMap<String, DiffFinding>,
    to_findings: BTreeMap<String, DiffFinding>,
    graph: GraphDiff,
) -> FindingDiff {
    // Phase 1: identical full fingerprint -> unchanged (same as before).
    let mut unchanged = Vec::new();
    let mut from_residual = Vec::new();
    let mut to_residual = Vec::new();
    for (fingerprint, finding) in &to_findings {
        if from_findings.contains_key(fingerprint) {
            unchanged.push(finding.clone());
        } else {
            to_residual.push(finding.clone());
        }
    }
    for (fingerprint, finding) in &from_findings {
        if !to_findings.contains_key(fingerprint) {
            from_residual.push(finding.clone());
        }
    }
    // Phase 2: group residuals by effective family and pair 1:1 only.
    let mut from_by_family: BTreeMap<String, Vec<DiffFinding>> = BTreeMap::new();
    for finding in from_residual {
        from_by_family
            .entry(effective_family(&finding).to_owned())
            .or_default()
            .push(finding);
    }
    let mut to_by_family: BTreeMap<String, Vec<DiffFinding>> = BTreeMap::new();
    for finding in to_residual {
        to_by_family
            .entry(effective_family(&finding).to_owned())
            .or_default()
            .push(finding);
    }
    let mut appeared = Vec::new();
    let mut disappeared = Vec::new();
    let mut weakened = Vec::new();
    let mut strengthened = Vec::new();
    let mut uncertain = Vec::new();
    {
        use std::collections::BTreeSet;
        let mut families = BTreeSet::new();
        families.extend(from_by_family.keys().cloned());
        families.extend(to_by_family.keys().cloned());
        for family in families {
            let old = from_by_family.get(&family);
            let new = to_by_family.get(&family);
            match (old, new) {
                (Some(old_members), Some(new_members)) => {
                    if old_members.len() != 1 || new_members.len() != 1 {
                        disappeared.extend(old_members.iter().cloned());
                        appeared.extend(new_members.iter().cloned());
                    } else {
                        let from_finding = &old_members[0];
                        let to_finding = &new_members[0];
                        let deltas = rating_deltas(from_finding, to_finding);
                        let change = FindingLifecycleChange {
                            from: from_finding.clone(),
                            to: to_finding.clone(),
                            deltas,
                        };
                        match classify(from_finding, to_finding) {
                            LifecycleKind::Weakened => weakened.push(change),
                            LifecycleKind::Strengthened => strengthened.push(change),
                            LifecycleKind::Uncertain => uncertain.push(change),
                        }
                    }
                }
                (Some(old_members), None) => {
                    disappeared.extend(old_members.iter().cloned());
                }
                (None, Some(new_members)) => {
                    appeared.extend(new_members.iter().cloned());
                }
                (None, None) => {}
            }
        }
    }
    sort_findings(&mut unchanged);
    sort_findings(&mut appeared);
    sort_findings(&mut disappeared);
    sort_lifecycle(&mut weakened);
    sort_lifecycle(&mut strengthened);
    sort_lifecycle(&mut uncertain);
    FindingDiff {
        from,
        to,
        newest_attempt,
        freshness,
        freshness_warning,
        compared_via,
        provenance,
        unchanged,
        appeared,
        disappeared,
        weakened,
        strengthened,
        uncertain,
        graph,
        attribution: Default::default(),
    }
}

/// Effective join key: the family fingerprint when present, otherwise the
/// full fingerprint (legacy fallback). Legacy `''` rows therefore never join
/// across differing fingerprints.
fn effective_family(finding: &DiffFinding) -> &str {
    if finding.family_fingerprint.is_empty() {
        &finding.fingerprint
    } else {
        &finding.family_fingerprint
    }
}

fn severity_rank(severity: &str) -> Option<u8> {
    match severity {
        "INFO" => Some(0),
        "LOW" => Some(1),
        "MEDIUM" => Some(2),
        "HIGH" => Some(3),
        "CRITICAL" => Some(4),
        _ => None,
    }
}

fn confidence_rank(confidence: &str) -> Option<u8> {
    match confidence {
        "LOW" => Some(0),
        "MEDIUM" => Some(1),
        "HIGH" => Some(2),
        _ => None,
    }
}

/// Severity first, then confidence, for differing raw values only.
///
/// `field` carries the frozen machine contract values "severity" |
/// "confidence" (lowercase); `from_value`/`to_value` stay raw (INFO/LOW/…).
fn rating_deltas(from: &DiffFinding, to: &DiffFinding) -> Vec<FindingRatingDelta> {
    let mut deltas = Vec::new();
    if from.severity != to.severity {
        deltas.push(FindingRatingDelta {
            field: "severity".to_string(),
            from_value: from.severity.clone(),
            to_value: to.severity.clone(),
        });
    }
    if from.confidence != to.confidence {
        deltas.push(FindingRatingDelta {
            field: "confidence".to_string(),
            from_value: from.confidence.clone(),
            to_value: to.confidence.clone(),
        });
    }
    deltas
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleKind {
    Weakened,
    Strengthened,
    Uncertain,
}

fn classify(from: &DiffFinding, to: &DiffFinding) -> LifecycleKind {
    let Some(from_sev) = severity_rank(&from.severity) else {
        return LifecycleKind::Uncertain;
    };
    let Some(to_sev) = severity_rank(&to.severity) else {
        return LifecycleKind::Uncertain;
    };
    let Some(from_conf) = confidence_rank(&from.confidence) else {
        return LifecycleKind::Uncertain;
    };
    let Some(to_conf) = confidence_rank(&to.confidence) else {
        return LifecycleKind::Uncertain;
    };
    match (from_sev.cmp(&to_sev), from_conf.cmp(&to_conf)) {
        // Severity down (+ confidence down/equal) -> weakened.
        (std::cmp::Ordering::Greater, std::cmp::Ordering::Greater)
        | (std::cmp::Ordering::Greater, std::cmp::Ordering::Equal)
        | (std::cmp::Ordering::Equal, std::cmp::Ordering::Greater) => LifecycleKind::Weakened,
        // Severity up (+ confidence up/equal) -> strengthened.
        (std::cmp::Ordering::Less, std::cmp::Ordering::Less)
        | (std::cmp::Ordering::Less, std::cmp::Ordering::Equal)
        | (std::cmp::Ordering::Equal, std::cmp::Ordering::Less) => LifecycleKind::Strengthened,
        // Opposing directions -> uncertain.
        (std::cmp::Ordering::Greater, std::cmp::Ordering::Less)
        | (std::cmp::Ordering::Less, std::cmp::Ordering::Greater) => LifecycleKind::Uncertain,
        // Both equal but fingerprints differ -> uncertain anomaly.
        (std::cmp::Ordering::Equal, std::cmp::Ordering::Equal) => LifecycleKind::Uncertain,
    }
}

fn sort_findings(findings: &mut [DiffFinding]) {
    findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then(left.id.cmp(&right.id))
    });
}

fn sort_lifecycle(changes: &mut [FindingLifecycleChange]) {
    changes.sort_by(|left, right| {
        left.to
            .fingerprint
            .cmp(&right.to.fingerprint)
            .then(left.to.id.cmp(&right.to.id))
            .then(left.from.fingerprint.cmp(&right.from.fingerprint))
            .then(left.from.id.cmp(&right.from.id))
    });
}

fn scan_brief(scan: &Scan) -> ScanBrief {
    ScanBrief {
        id: scan.id.clone(),
        status: scan.status.as_str().to_string(),
        completed_at: scan.completed_at.map(codec::ts_to_text),
    }
}

fn freshness_context(
    newest_complete: &Scan,
    newest_attempt: Option<&Scan>,
) -> (Freshness, Option<String>) {
    if let Some(attempt) = newest_attempt {
        let incomplete = matches!(
            attempt.status,
            crate::domain::ScanStatus::Running
                | crate::domain::ScanStatus::Partial
                | crate::domain::ScanStatus::Failed
        );
        if incomplete && attempt_is_newer(attempt, newest_complete) {
            return (
                Freshness::NewerIncomplete,
                Some(format!(
                    "Freshness: A newer scan {} is {}.\nComparing the last two COMPLETE scans; these results may not describe current state.",
                    attempt.id,
                    attempt.status.as_str()
                )),
            );
        }
    }
    (Freshness::LatestComplete, None)
}

fn attempt_is_newer(attempt: &Scan, complete: &Scan) -> bool {
    (attempt.started_at, attempt.id.as_str()) > (complete.started_at, complete.id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::compare_contract::ComparisonContractField;
    use crate::persistence::ScanAnalysisRepo;
    use crate::shared::PICO_VERSION;

    fn provenance_current() -> DiffProvenance {
        let side = DiffSideProvenance {
            pico_version: "0.1.0".to_string(),
            contract: Some(CURRENT_COMPARISON_CONTRACT),
        };
        DiffProvenance {
            from: side.clone(),
            to: side,
        }
    }

    fn finding(
        id: &str,
        fingerprint: &str,
        family: &str,
        severity: &str,
        confidence: &str,
    ) -> DiffFinding {
        DiffFinding {
            id: id.to_string(),
            fingerprint: fingerprint.to_string(),
            family_fingerprint: family.to_string(),
            title: format!("title-{id}"),
            severity: severity.to_string(),
            confidence: confidence.to_string(),
            cause: None,
        }
    }

    fn map_of(findings: Vec<DiffFinding>) -> BTreeMap<String, DiffFinding> {
        let mut map = BTreeMap::new();
        for item in findings {
            map.entry(item.fingerprint.clone()).or_insert(item);
        }
        map
    }

    fn diff_of(from: Vec<DiffFinding>, to: Vec<DiffFinding>) -> FindingDiff {
        compare(
            ScanBrief {
                id: "from".to_string(),
                status: "COMPLETE".to_string(),
                completed_at: None,
            },
            ScanBrief {
                id: "to".to_string(),
                status: "COMPLETE".to_string(),
                completed_at: None,
            },
            None,
            Freshness::LatestComplete,
            None,
            ComparedVia::LatestTwo,
            provenance_current(),
            map_of(from),
            map_of(to),
            GraphDiff::default(),
        )
    }

    #[test]
    fn exact_fingerprint_wins_over_family_match() {
        let from = vec![finding("a", "fp-same", "fam-x", "HIGH", "HIGH")];
        let to = vec![finding("b", "fp-same", "fam-x", "LOW", "LOW")];
        let diff = diff_of(from, to);
        assert_eq!(diff.unchanged.len(), 1);
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
        assert!(diff.uncertain.is_empty());
        assert!(diff.appeared.is_empty());
        assert!(diff.disappeared.is_empty());
    }

    #[test]
    fn severity_only_down_is_weakened_with_delta() {
        let from = vec![finding("a", "fp-old", "fam-1", "HIGH", "MEDIUM")];
        let to = vec![finding("b", "fp-new", "fam-1", "LOW", "MEDIUM")];
        let diff = diff_of(from, to);
        assert!(diff.appeared.is_empty());
        assert!(diff.disappeared.is_empty());
        assert_eq!(diff.weakened.len(), 1);
        assert!(diff.strengthened.is_empty());
        assert!(diff.uncertain.is_empty());
        let change = &diff.weakened[0];
        assert_eq!(change.from.fingerprint, "fp-old");
        assert_eq!(change.to.fingerprint, "fp-new");
        assert_eq!(
            change.deltas,
            vec![FindingRatingDelta {
                field: "severity".to_string(),
                from_value: "HIGH".to_string(),
                to_value: "LOW".to_string(),
            }]
        );
    }

    #[test]
    fn confidence_only_up_is_strengthened() {
        let from = vec![finding("a", "fp-old", "fam-1", "MEDIUM", "LOW")];
        let to = vec![finding("b", "fp-new", "fam-1", "MEDIUM", "HIGH")];
        let diff = diff_of(from, to);
        assert_eq!(diff.strengthened.len(), 1);
        assert!(diff.weakened.is_empty());
        assert!(diff.uncertain.is_empty());
        let change = &diff.strengthened[0];
        assert_eq!(
            change.deltas,
            vec![FindingRatingDelta {
                field: "confidence".to_string(),
                from_value: "LOW".to_string(),
                to_value: "HIGH".to_string(),
            }]
        );
    }

    #[test]
    fn opposing_directions_are_uncertain() {
        // Severity down + confidence up.
        let diff = diff_of(
            vec![finding("a", "fp-old", "fam-1", "HIGH", "LOW")],
            vec![finding("b", "fp-new", "fam-1", "LOW", "HIGH")],
        );
        assert_eq!(diff.uncertain.len(), 1);
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
        let change = &diff.uncertain[0];
        assert_eq!(change.deltas.len(), 2);
        assert_eq!(change.deltas[0].field, "severity");
        assert_eq!(change.deltas[1].field, "confidence");
        // Severity up + confidence down is also uncertain.
        let flipped = diff_of(
            vec![finding("a", "fp-old", "fam-1", "LOW", "HIGH")],
            vec![finding("b", "fp-new", "fam-1", "HIGH", "LOW")],
        );
        assert_eq!(flipped.uncertain.len(), 1);
        assert!(flipped.weakened.is_empty());
        assert!(flipped.strengthened.is_empty());
    }

    #[test]
    fn equal_ratings_with_different_fingerprint_is_uncertain_anomaly() {
        let diff = diff_of(
            vec![finding("a", "fp-old", "fam-1", "HIGH", "HIGH")],
            vec![finding("b", "fp-new", "fam-1", "HIGH", "HIGH")],
        );
        assert_eq!(diff.uncertain.len(), 1);
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
        assert!(diff.uncertain[0].deltas.is_empty());
    }

    #[test]
    fn collision_does_not_pair() {
        let from = vec![
            finding("a1", "fp-old-1", "fam-1", "HIGH", "HIGH"),
            finding("a2", "fp-old-2", "fam-1", "LOW", "LOW"),
        ];
        let to = vec![finding("b", "fp-new", "fam-1", "MEDIUM", "MEDIUM")];
        let diff = diff_of(from, to);
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
        assert!(diff.uncertain.is_empty());
        assert_eq!(diff.disappeared.len(), 2);
        assert_eq!(diff.appeared.len(), 1);
        // Reverse collision (1 old vs 2 new) also never pairs.
        let flipped = diff_of(
            vec![finding("b", "fp-new", "fam-1", "MEDIUM", "MEDIUM")],
            vec![
                finding("a1", "fp-old-1", "fam-1", "HIGH", "HIGH"),
                finding("a2", "fp-old-2", "fam-1", "LOW", "LOW"),
            ],
        );
        assert!(flipped.weakened.is_empty());
        assert!(flipped.strengthened.is_empty());
        assert!(flipped.uncertain.is_empty());
        assert_eq!(flipped.disappeared.len(), 1);
        assert_eq!(flipped.appeared.len(), 2);
    }

    #[test]
    fn legacy_empty_family_never_joins() {
        let diff = diff_of(
            vec![finding("a", "fp-old", "", "HIGH", "HIGH")],
            vec![finding("b", "fp-new", "", "LOW", "LOW")],
        );
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
        assert!(diff.uncertain.is_empty());
        assert_eq!(diff.disappeared.len(), 1);
        assert_eq!(diff.appeared.len(), 1);
    }

    #[test]
    fn reverse_pair_swaps_weakened_and_strengthened() {
        let old = finding("a", "fp-old", "fam-1", "HIGH", "HIGH");
        let new = finding("b", "fp-new", "fam-1", "LOW", "LOW");
        let forward = diff_of(vec![old.clone()], vec![new.clone()]);
        assert_eq!(forward.weakened.len(), 1);
        assert!(forward.strengthened.is_empty());
        let reverse = diff_of(vec![new], vec![old]);
        assert_eq!(reverse.strengthened.len(), 1);
        assert!(reverse.weakened.is_empty());
    }

    #[test]
    fn unknown_ratings_are_uncertain() {
        let diff = diff_of(
            vec![finding("a", "fp-old", "fam-1", "BOGUS", "HIGH")],
            vec![finding("b", "fp-new", "fam-1", "LOW", "HIGH")],
        );
        assert_eq!(diff.uncertain.len(), 1);
        assert!(diff.weakened.is_empty());
        assert!(diff.strengthened.is_empty());
    }

    #[test]
    fn lifecycle_sorting_is_deterministic() {
        let from = vec![
            finding("a2", "fp-old-2", "fam-2", "HIGH", "HIGH"),
            finding("a1", "fp-old-1", "fam-1", "HIGH", "HIGH"),
        ];
        let to = vec![
            finding("b2", "fp-new-2", "fam-2", "LOW", "LOW"),
            finding("b1", "fp-new-1", "fam-1", "LOW", "LOW"),
        ];
        // Insert maps out of order via reversed vectors as well; output must
        // still be sorted by (to.fingerprint, to.id, from.fingerprint, from.id).
        let diff = diff_of(from, to);
        assert_eq!(diff.weakened.len(), 2);
        assert_eq!(diff.weakened[0].to.fingerprint, "fp-new-1");
        assert_eq!(diff.weakened[1].to.fingerprint, "fp-new-2");
    }

    #[test]
    fn counts_are_conserved() {
        let from = vec![
            finding("keep", "fp-same", "fam-keep", "HIGH", "HIGH"),
            finding("gone", "fp-gone", "fam-gone", "HIGH", "HIGH"),
            finding("w-old", "fp-w-old", "fam-w", "HIGH", "HIGH"),
            finding("s-old", "fp-s-old", "fam-s", "LOW", "LOW"),
            finding("u-old", "fp-u-old", "fam-u", "HIGH", "LOW"),
        ];
        let to = vec![
            finding("keep", "fp-same", "fam-keep", "HIGH", "HIGH"),
            finding("fresh", "fp-fresh", "fam-fresh", "HIGH", "HIGH"),
            finding("w-new", "fp-w-new", "fam-w", "LOW", "LOW"),
            finding("s-new", "fp-s-new", "fam-s", "HIGH", "HIGH"),
            finding("u-new", "fp-u-new", "fam-u", "LOW", "HIGH"),
        ];
        let from_count = from.len();
        let to_count = to.len();
        let diff = diff_of(from, to);
        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.disappeared.len(), 1);
        assert_eq!(diff.appeared.len(), 1);
        assert_eq!(diff.weakened.len(), 1);
        assert_eq!(diff.strengthened.len(), 1);
        assert_eq!(diff.uncertain.len(), 1);
        let lifecycle = diff.weakened.len() + diff.strengthened.len() + diff.uncertain.len();
        assert_eq!(
            from_count,
            diff.unchanged.len() + diff.disappeared.len() + lifecycle
        );
        assert_eq!(
            to_count,
            diff.unchanged.len() + diff.appeared.len() + lifecycle
        );
    }

    // Comparison-contract guard decisions (SPRINT-029 §5.4).

    fn guard_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        crate::persistence::db::migrate(&mut conn).unwrap();
        conn
    }

    fn declared(envelope: u32, graph: u64, finding: u32) -> serde_json::Value {
        serde_json::json!({
            "comparison_contract_version": envelope,
            "graph_snapshot_version": graph,
            "finding_version": finding,
        })
    }

    fn seed_guard_scan(
        conn: &Connection,
        metadata: Option<serde_json::Value>,
        analysis_version: &str,
    ) -> Scan {
        let mut scan = Scan::start(PICO_VERSION).unwrap();
        scan.metadata = metadata;
        ScanRepo::new(conn).insert(&scan).unwrap();
        ScanAnalysisRepo::new(conn)
            .upsert(&crate::persistence::ScanAnalysisRecord {
                scan_id: scan.id.clone(),
                analysis_version: analysis_version.to_string(),
                status: "COMPLETE".to_string(),
                overall_disposition: Some("NONE".to_string()),
                influence_path_count: 0,
                authority_path_count: 0,
                active_path_count: 0,
                blocked_path_count: 0,
                unresolved_candidate_count: 0,
                limit_reasons: None,
                diagnostics: None,
                created_at: chrono::Utc::now(),
            })
            .unwrap();
        scan
    }

    fn seed_guard_finding(conn: &Connection, scan_id: &str, version: &str) {
        crate::persistence::FindingRepo::new(conn)
            .insert(&crate::persistence::FindingRecord {
                id: format!("finding-{scan_id}"),
                scan_id: scan_id.to_string(),
                fingerprint: format!("sha256:{scan_id}"),
                family_fingerprint: format!("sha256:fam-{scan_id}"),
                finding_version: version.to_string(),
                finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
                title: "t".to_string(),
                summary: "s".to_string(),
                severity: "LOW".to_string(),
                confidence: "HIGH".to_string(),
                status: "OPEN".to_string(),
                metadata: None,
                created_at: chrono::Utc::now(),
            })
            .unwrap();
    }

    #[test]
    fn guard_proceeds_on_current_equal_tuples() {
        let conn = guard_conn();
        let from = seed_guard_scan(&conn, Some(declared(1, 1, 1)), "1");
        seed_guard_finding(&conn, &from.id, "1");
        let to = seed_guard_scan(&conn, Some(declared(1, 1, 1)), "1");
        seed_guard_finding(&conn, &to.id, "1");
        let decision = evaluate_contract_guard(&conn, &from, &to).unwrap();
        match decision.outcome {
            ComparisonGuardOutcome::Proceed(contract) => {
                assert_eq!(contract, CURRENT_COMPARISON_CONTRACT);
            }
            ComparisonGuardOutcome::NotComparable { .. } => {
                panic!("current tuples must proceed")
            }
        }
        assert_eq!(
            decision.provenance.from.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
        assert_eq!(
            decision.provenance.to.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
    }

    #[test]
    fn guard_unavailable_gaps_run_from_then_to_in_declaration_order() {
        let conn = guard_conn();
        let from = seed_guard_scan(&conn, None, "1");
        // Strip the summary so the FROM side is a genuine legacy scan.
        conn.execute("DELETE FROM scan_analyses WHERE scan_id = ?1", [&from.id])
            .unwrap();
        let to = seed_guard_scan(&conn, Some(declared(1, 1, 1)), "1");
        seed_guard_finding(&conn, &to.id, "1");
        let decision = evaluate_contract_guard(&conn, &from, &to).unwrap();
        match decision.outcome {
            ComparisonGuardOutcome::NotComparable { reason, gaps } => {
                assert_eq!(reason, DiffNotComparableReason::ProvenanceUnavailable);
                assert_eq!(
                    gaps,
                    vec![
                        ComparisonProvenanceGap {
                            side: DiffSide::From,
                            field: ComparisonContractField::GraphSnapshotVersion,
                        },
                        ComparisonProvenanceGap {
                            side: DiffSide::From,
                            field: ComparisonContractField::AnalysisVersion,
                        },
                        ComparisonProvenanceGap {
                            side: DiffSide::From,
                            field: ComparisonContractField::FindingVersion,
                        },
                    ]
                );
            }
            ComparisonGuardOutcome::Proceed(_) => panic!("legacy side must not proceed"),
        }
        assert!(decision.provenance.from.contract.is_none());
        assert_eq!(decision.provenance.from.pico_version, PICO_VERSION);
        assert_eq!(
            decision.provenance.to.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
    }

    #[test]
    fn guard_reports_changed_for_differing_tuples_with_empty_gaps() {
        let conn = guard_conn();
        let from = seed_guard_scan(&conn, Some(declared(1, 1, 1)), "1");
        seed_guard_finding(&conn, &from.id, "1");
        let to = seed_guard_scan(&conn, Some(declared(1, 1, 1)), "2");
        seed_guard_finding(&conn, &to.id, "1");
        let decision = evaluate_contract_guard(&conn, &from, &to).unwrap();
        match decision.outcome {
            ComparisonGuardOutcome::NotComparable { reason, gaps } => {
                assert_eq!(reason, DiffNotComparableReason::ContractChanged);
                assert!(gaps.is_empty());
            }
            ComparisonGuardOutcome::Proceed(_) => panic!("differing tuples must not proceed"),
        }
        assert_eq!(
            decision.provenance.to.contract,
            Some(ComparisonContractVersions {
                comparison_contract_version: 1,
                graph_snapshot_version: 1,
                analysis_version: 2,
                finding_version: 1,
            })
        );
    }

    #[test]
    fn guard_reports_unsupported_for_equal_non_current_tuples() {
        let conn = guard_conn();
        let from = seed_guard_scan(&conn, Some(declared(2, 2, 2)), "2");
        seed_guard_finding(&conn, &from.id, "2");
        let to = seed_guard_scan(&conn, Some(declared(2, 2, 2)), "2");
        seed_guard_finding(&conn, &to.id, "2");
        let decision = evaluate_contract_guard(&conn, &from, &to).unwrap();
        match decision.outcome {
            ComparisonGuardOutcome::NotComparable { reason, gaps } => {
                assert_eq!(reason, DiffNotComparableReason::ContractUnsupported);
                assert!(gaps.is_empty());
            }
            ComparisonGuardOutcome::Proceed(_) => {
                panic!("unsupported tuples must not proceed")
            }
        }
        assert_eq!(
            decision.provenance.from.contract,
            decision.provenance.to.contract
        );
        assert_ne!(
            decision.provenance.from.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
    }
}
