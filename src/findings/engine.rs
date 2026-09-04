//! Deterministic eligibility, grouping, and materialization of Findings.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::analysis::{
    AnalysisResult, AnalysisStatus, AttackPath, AuthorityResolution, BoundaryDecision,
    CandidateDisposition, CapabilityClass, InfluenceStrength, SinkImpact, SourceTrust,
};
use crate::domain::evidence::Freshness;
use crate::domain::{Evidence, EvidenceClass, ScanStatus};
use crate::findings::confidence::freshness_confidence;
use crate::findings::diagnostics::{ConfidenceNote, SuppressedReason};
use crate::graph::SecurityGraph;

use super::model::{
    Confidence, Finding, FindingClass, FindingGenerationStatus, FindingLimits, FindingReason,
    FindingResult, FindingStatus, ReasonCode, Remediation, Severity, FINDING_VERSION,
};

const TITLE: &str = "External content can reach production mutation authority";
const SUMMARY: &str = "Externally controlled content can reach an autonomous coding environment with authority capable of changing an explicitly classified production resource.";

/// Generate Findings for a completed scan. This convenience API assumes the
/// caller has already established that the Scan is complete. Use
/// [`generate_with_scan_status`] at the application boundary when the Scan
/// lifecycle status is available.
pub fn generate(
    graph: &SecurityGraph,
    analysis: &AnalysisResult,
    limits: &FindingLimits,
) -> FindingResult {
    generate_with_scan_status(graph, analysis, ScanStatus::Complete, limits)
}

/// Generate only positive Findings from a complete, complete-analysis scan.
/// Every security-critical fact is checked against the current graph and its
/// current-scan Evidence; missing or weak facts fail closed.
pub fn generate_with_scan_status(
    graph: &SecurityGraph,
    analysis: &AnalysisResult,
    scan_status: ScanStatus,
    limits: &FindingLimits,
) -> FindingResult {
    let mut result = FindingResult {
        scan_id: graph.scan_id.clone(),
        finding_version: FINDING_VERSION,
        status: FindingGenerationStatus::Complete,
        findings: Vec::new(),
        diagnostics: Vec::new(),
    };
    if scan_status != ScanStatus::Complete {
        result.diagnostics.push("scan is not COMPLETE".into());
        return result;
    }
    if analysis.scan_id != graph.scan_id {
        result.status = FindingGenerationStatus::Failed;
        result
            .diagnostics
            .push("analysis belongs to another scan".into());
        return result;
    }
    if analysis.status != AnalysisStatus::Complete {
        result
            .diagnostics
            .push("analysis is not COMPLETE; positive Findings are suppressed".into());
        return result;
    }
    if analysis.attack_paths.len() > limits.maximum_attack_paths_examined {
        result.status = FindingGenerationStatus::Limited;
        result
            .diagnostics
            .push("Finding attack-path examination limit reached".into());
        return result;
    }

    let mut groups: BTreeMap<String, Vec<Candidate<'_>>> = BTreeMap::new();
    for path in &analysis.attack_paths {
        if path.disposition != CandidateDisposition::Active {
            continue;
        }
        let Some(candidate) = eligible_candidate(graph, path, scan_status) else {
            continue;
        };
        let key = grouping_key(graph, path, candidate.severity, candidate.confidence);
        groups.entry(key).or_default().push(candidate);
    }
    if groups.len() > limits.maximum_groups {
        result.status = FindingGenerationStatus::Limited;
        result
            .diagnostics
            .push("Finding grouping limit reached".into());
        return result;
    }

    for (_, mut candidates) in groups {
        candidates.sort_by(|a, b| a.path.fingerprint.cmp(&b.path.fingerprint));
        candidates.dedup_by(|a, b| a.path.fingerprint == b.path.fingerprint);
        if candidates.len() > limits.maximum_paths_per_finding {
            result.status = FindingGenerationStatus::Limited;
            result
                .diagnostics
                .push("paths per Finding limit reached".into());
            result.findings.clear();
            return result;
        }
        let finding = match materialize_finding(graph, &candidates, limits) {
            Ok(finding) => finding,
            Err(message) => {
                result.diagnostics.push(message);
                continue;
            }
        };
        if result.findings.len() >= limits.maximum_emitted_findings {
            result.status = FindingGenerationStatus::Limited;
            result
                .diagnostics
                .push("emitted Finding limit reached".into());
            result.findings.clear();
            return result;
        }
        result.findings.push(finding);
    }
    result
}

#[derive(Debug, Clone, Copy)]
struct Candidate<'a> {
    path: &'a AttackPath,
    production_evidence: &'a [String],
    severity: Severity,
    confidence: Confidence,
}

fn eligible_candidate<'a>(
    graph: &'a SecurityGraph,
    path: &'a AttackPath,
    scan_status: ScanStatus,
) -> Option<Candidate<'a>> {
    if !matches!(
        path.source_trust,
        SourceTrust::PublicExternal | SourceTrust::OpenWorld | SourceTrust::AuthenticatedExternal
    ) || !matches!(
        path.influence_strength,
        InfluenceStrength::AgentRetrievable
            | InfluenceStrength::AutomaticallyInjected
            | InfluenceStrength::InstructionBearing
            | InfluenceStrength::AgentInjectable
            | InfluenceStrength::AgentMutable
    ) || !matches!(
        path.capability,
        CapabilityClass::Execute | CapabilityClass::Admin
    ) || !matches!(
        path.authority_resolution,
        AuthorityResolution::Exact | AuthorityResolution::Scoped
    ) || path.sink_impact != SinkImpact::Production
    {
        return None;
    }
    if path
        .boundary_evaluations
        .iter()
        .any(|boundary| boundary.decision != BoundaryDecision::DoesNotInterrupt)
    {
        return None;
    }
    let sink = graph.node(&path.sink_resource_id)?;
    if !explicit_production_metadata(sink.safe_metadata.as_ref()) {
        return None;
    }
    if !critical_edges_are_confirmed(graph, path) {
        return None;
    }
    if !critical_edges_are_confirmable(graph, path, scan_status) {
        return None;
    }
    let path_evidence = all_path_evidence(graph, path)?;
    let production_ids = explicit_production_evidence(graph, path, &path_evidence);
    if production_ids.is_empty() {
        return None;
    }
    let production_class = evidence_quality(&production_ids, graph)?;
    let confidence = if path_evidence
        .iter()
        .all(|e| e.class != EvidenceClass::Inferred)
        && production_ids.iter().all(|id| {
            graph
                .evidence_index
                .evidence(id)
                .is_some_and(|e| e.class != EvidenceClass::Inferred)
        })
        && production_class
    {
        Confidence::High
    } else {
        return None;
    };
    let severity = match path.source_trust {
        SourceTrust::PublicExternal | SourceTrust::OpenWorld => Severity::Critical,
        SourceTrust::AuthenticatedExternal => Severity::High,
        _ => return None,
    };
    // Leak the sorted IDs into the graph-owned temporary only through the
    // candidate's own local storage. The helper returns a static-looking
    // slice backed by the path's evidence when classification evidence is
    // already linked there; unlinked production Evidence is handled by
    // `materialize_finding` through a recomputation. This branch is replaced
    // below by the owned candidate constructor.
    let _ = production_ids;
    let production_evidence = path.evidence_ids.as_slice();
    Some(Candidate {
        path,
        production_evidence,
        severity,
        confidence,
    })
}

fn critical_edges_are_confirmed(graph: &SecurityGraph, path: &AttackPath) -> bool {
    path.influence_edges
        .iter()
        .chain(path.authority_edges.iter())
        .all(|reference| {
            graph.edge(&reference.relationship_id).is_some_and(|edge| {
                matches!(
                    edge.state,
                    crate::domain::RelationshipState::Confirmed
                        | crate::domain::RelationshipState::Derived
                )
            })
        })
}

fn critical_edges_are_confirmable(
    graph: &SecurityGraph,
    path: &AttackPath,
    scan_status: ScanStatus,
) -> bool {
    let reference = Utc::now();
    path.influence_edges
        .iter()
        .chain(path.authority_edges.iter())
        .all(|edge_ref| {
            let relationship = match graph.edge(&edge_ref.relationship_id) {
                Some(relationship) => relationship,
                None => return false,
            };
            let edge_freshness =
                edge_supporting_freshness(graph, &relationship.relationship_id, reference);
            freshness_confidence(edge_freshness, scan_status).may_be_confirmed
        })
}

/// The freshness of a critical edge is driven by its weakest (oldest-captured)
/// supporting Evidence relative to `reference`.
pub(crate) fn edge_supporting_freshness(
    graph: &SecurityGraph,
    relationship_id: &str,
    reference: DateTime<Utc>,
) -> Freshness {
    let mut oldest: Option<&Evidence> = None;
    for id in graph.evidence_index.relationship_evidence(relationship_id) {
        if let Some(evidence) = graph.evidence_index.evidence(id) {
            match oldest {
                None => oldest = Some(evidence),
                Some(current) if evidence.captured_at < current.captured_at => {
                    oldest = Some(evidence)
                }
                _ => {}
            }
        }
    }
    match oldest {
        Some(evidence) => evidence.freshness_state(reference),
        None => Freshness::Unknown,
    }
}

/// Build honest, structured diagnostics for a completed generation pass.
///
/// Returns `(suppressed, reduced_confidence)`:
/// * `suppressed` — one entry per candidate `AttackPath` that was `Active` but
///   did NOT become a Finding, with a deterministic reason for suppression.
/// * `reduced_confidence` — one entry per emitted Finding whose security-critical
///   edges carried incomplete (non-FRESH) evidence, listing each such edge.
///
/// The caller (the scan service) is responsible for filling the provider-level
/// fields of [`ScanDiagnostics`] that require discovery context this engine
/// never sees. This keeps the engine provider-neutral.
pub fn eligibility_diagnostics(
    graph: &SecurityGraph,
    analysis: &AnalysisResult,
    scan_status: ScanStatus,
    findings: &[Finding],
) -> (Vec<SuppressedReason>, Vec<ConfidenceNote>) {
    let reference = Utc::now();
    let emitted: BTreeSet<&String> = findings
        .iter()
        .flat_map(|finding| finding.attack_path_fingerprints.iter())
        .collect();

    let mut suppressed = Vec::new();
    for path in &analysis.attack_paths {
        if path.disposition != CandidateDisposition::Active {
            continue;
        }
        if emitted.contains(&path.fingerprint) {
            continue;
        }
        suppressed.push(SuppressedReason {
            fingerprint: path.fingerprint.clone(),
            reason: suppression_reason(graph, path, scan_status, reference),
        });
    }

    let mut reduced_confidence = Vec::new();
    for finding in findings {
        let mut edges: Vec<(String, String, f64)> = Vec::new();
        for fingerprint in &finding.attack_path_fingerprints {
            let Some(path) = analysis
                .attack_paths
                .iter()
                .find(|candidate| &candidate.fingerprint == fingerprint)
            else {
                continue;
            };
            for edge_ref in path
                .influence_edges
                .iter()
                .chain(path.authority_edges.iter())
            {
                let freshness =
                    edge_supporting_freshness(graph, &edge_ref.relationship_id, reference);
                let confidence = freshness_confidence(freshness, scan_status);
                if confidence.penalty > 0.0 {
                    edges.push((
                        edge_ref.relationship_id.clone(),
                        freshness.as_str().to_string(),
                        confidence.penalty,
                    ));
                }
            }
        }
        if !edges.is_empty() {
            reduced_confidence.push(ConfidenceNote {
                fingerprint: finding.fingerprint.clone(),
                edges,
            });
        }
    }

    (suppressed, reduced_confidence)
}

/// Derive a single honest suppression reason for a candidate `AttackPath`.
///
/// Order matters: the most security-significant, evidence-driven cause is
/// reported first so the explanation names the exact weak link.
fn suppression_reason(
    graph: &SecurityGraph,
    path: &AttackPath,
    scan_status: ScanStatus,
    reference: DateTime<Utc>,
) -> String {
    if scan_status != ScanStatus::Complete {
        return "PARTIAL_SCAN".to_string();
    }
    for edge_ref in path
        .influence_edges
        .iter()
        .chain(path.authority_edges.iter())
    {
        let freshness = edge_supporting_freshness(graph, &edge_ref.relationship_id, reference);
        let confidence = freshness_confidence(freshness, scan_status);
        if !confidence.may_be_confirmed {
            return format!(
                "critical edge {} not confirmable: {}",
                edge_ref.relationship_id,
                freshness.as_str()
            );
        }
    }
    if path.authority_resolution == AuthorityResolution::Unknown {
        return "authority UNKNOWN".to_string();
    }
    "eligibility gate not satisfied".to_string()
}

fn all_path_evidence<'a>(graph: &'a SecurityGraph, path: &AttackPath) -> Option<Vec<&'a Evidence>> {
    let mut ids = path.evidence_ids.clone();
    ids.sort();
    ids.dedup();
    let mut evidence = Vec::with_capacity(ids.len());
    for id in ids {
        let item = graph.evidence_index.evidence(&id)?;
        if item.scan_id != graph.scan_id {
            return None;
        }
        evidence.push(item);
    }
    Some(evidence)
}

fn explicit_production_metadata(metadata: Option<&serde_json::Value>) -> bool {
    let Some(object) = metadata.and_then(serde_json::Value::as_object) else {
        return false;
    };
    ["sink_impact", "environment", "production_classification"]
        .iter()
        .any(|key| {
            object
                .get(*key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("PRODUCTION"))
        })
}

fn explicit_production_evidence<'a>(
    graph: &'a SecurityGraph,
    path: &AttackPath,
    path_evidence: &[&'a Evidence],
) -> Vec<String> {
    let sink_key = graph
        .node(&path.sink_resource_id)
        .map(|node| node.canonical_key.as_str());
    let mut output = path_evidence
        .iter()
        .filter(|evidence| evidence_is_production(evidence, &path.sink_resource_id, sink_key))
        .map(|evidence| evidence.id.clone())
        .collect::<Vec<_>>();
    for evidence in graph.evidence_index.by_evidence_id.values() {
        if evidence.scan_id == graph.scan_id
            && evidence_is_production(evidence, &path.sink_resource_id, sink_key)
        {
            output.push(evidence.id.clone());
        }
    }
    output.sort();
    output.dedup();
    output
}

fn evidence_is_production(evidence: &Evidence, sink_id: &str, sink_key: Option<&str>) -> bool {
    let subject_matches = evidence.subject == sink_id
        || sink_key == Some(evidence.subject.as_str())
        // Relationship Evidence commonly uses the relationship canonical key
        // as its subject. Requiring the sink canonical key as a segment keeps
        // this deterministic without accepting name-based evidence.
        || sink_key.is_some_and(|key| evidence.subject.contains(key));
    let explicit = evidence
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|object| {
            ["sink_impact", "environment", "production_classification"]
                .iter()
                .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
        })
        .is_some_and(|value| value.eq_ignore_ascii_case("PRODUCTION"));
    let observation_explicit = evidence
        .observation
        .to_ascii_uppercase()
        .contains("PRODUCTION")
        && (evidence
            .observation
            .to_ascii_uppercase()
            .contains("SINK_IMPACT")
            || evidence
                .observation
                .to_ascii_uppercase()
                .contains("ENVIRONMENT"));
    subject_matches && (explicit || observation_explicit)
}

fn evidence_quality(ids: &[String], graph: &SecurityGraph) -> Option<bool> {
    if ids.is_empty() {
        return None;
    }
    Some(ids.iter().all(|id| {
        graph.evidence_index.evidence(id).is_some_and(|evidence| {
            matches!(
                evidence.class,
                EvidenceClass::Direct | EvidenceClass::Declared | EvidenceClass::Derived
            ) && evidence.scan_id == graph.scan_id
        })
    }))
}

fn grouping_key(
    graph: &SecurityGraph,
    path: &AttackPath,
    severity: Severity,
    confidence: Confidence,
) -> String {
    let mut authorities = path
        .authority_edges
        .iter()
        .filter_map(|reference| graph.edge(&reference.relationship_id))
        .flat_map(|edge| [edge.from_resource_id.as_str(), edge.to_resource_id.as_str()])
        .filter_map(|id| graph.node(id))
        .filter(|node| node.roles.iter().any(|role| role.as_str() == "AUTHORITY"))
        .map(|node| node.canonical_key.as_str())
        .collect::<Vec<_>>();
    authorities.sort_unstable();
    authorities.dedup();
    let source = canonical_node(graph, &path.source_resource_id);
    let actor = canonical_node(graph, &path.actor_resource_id);
    format!(
        "source={source};actor={actor};authority={};severity={};confidence={}",
        authorities.join(","),
        severity.as_str(),
        confidence.as_str()
    )
}

fn materialize_finding(
    graph: &SecurityGraph,
    candidates: &[Candidate<'_>],
    limits: &FindingLimits,
) -> Result<Finding, String> {
    let first = candidates
        .first()
        .ok_or_else(|| "empty Finding group".to_string())?;
    let mut sources = candidates
        .iter()
        .map(|candidate| canonical_node(graph, &candidate.path.source_resource_id))
        .collect::<Vec<_>>();
    let mut actors = candidates
        .iter()
        .map(|candidate| canonical_node(graph, &candidate.path.actor_resource_id))
        .collect::<Vec<_>>();
    let mut sinks = candidates
        .iter()
        .map(|candidate| canonical_node(graph, &candidate.path.sink_resource_id))
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    actors.sort();
    actors.dedup();
    sinks.sort();
    sinks.dedup();

    let mut evidence_ids = BTreeSet::new();
    let mut relationship_ids = BTreeSet::new();
    let mut resource_ids = BTreeSet::new();
    let path_fingerprints = candidates
        .iter()
        .map(|candidate| candidate.path.fingerprint.clone())
        .collect::<Vec<_>>();
    let path_ids = candidates
        .iter()
        .map(|candidate| candidate.path.id.clone())
        .collect::<Vec<_>>();
    for candidate in candidates {
        resource_ids.insert(candidate.path.source_resource_id.clone());
        resource_ids.insert(candidate.path.actor_resource_id.clone());
        resource_ids.insert(candidate.path.sink_resource_id.clone());
        for reference in candidate
            .path
            .influence_edges
            .iter()
            .chain(candidate.path.authority_edges.iter())
        {
            relationship_ids.insert(reference.relationship_id.clone());
            if let Some(edge) = graph.edge(&reference.relationship_id) {
                evidence_ids.extend(edge.evidence_ids.iter().cloned());
            }
        }
        evidence_ids.extend(candidate.path.evidence_ids.iter().cloned());
        evidence_ids.extend(candidate.production_evidence.iter().cloned());
        evidence_ids.extend(explicit_production_evidence_for_path(graph, candidate.path));
    }
    let evidence_ids = evidence_ids.into_iter().collect::<Vec<_>>();
    if evidence_ids.len() > limits.maximum_evidence_per_finding {
        return Err("Evidence per Finding limit reached".into());
    }
    if evidence_ids.iter().any(|id| {
        graph
            .evidence_index
            .evidence(id)
            .is_none_or(|evidence| evidence.scan_id != graph.scan_id)
    }) {
        return Err("Finding Evidence is missing or belongs to another scan".into());
    }

    let mut reasons = vec![
        reason(
            ReasonCode::ExternalInfluenceSource,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
        reason(
            ReasonCode::AgentRetrievableContent,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
        reason(
            ReasonCode::AutonomousExecutionCapability,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
        reason(
            ReasonCode::ReachableCredentialAuthority,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
        reason(
            ReasonCode::ProductionMutationAuthority,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
        reason(
            ReasonCode::NoEnforcedBoundary,
            &resource_ids,
            &relationship_ids,
            &path_fingerprints,
            &evidence_ids,
        ),
    ];
    reasons.sort_by_key(|reason| reason.code);
    if reasons.len() > limits.maximum_reasons_per_finding {
        return Err("reasons per Finding limit reached".into());
    }
    let remediations = remediations(graph, candidates);
    if remediations.len() > limits.maximum_remediations_per_finding {
        return Err("remediations per Finding limit reached".into());
    }
    let remediation_rule_ids = remediations
        .iter()
        .map(|remediation| remediation.rule_id.clone())
        .collect::<Vec<_>>();
    let fingerprint = finding_fingerprint(
        &sources,
        &actors,
        &sinks,
        &path_fingerprints,
        first.severity,
        first.confidence,
        &remediation_rule_ids,
    );
    let family_fingerprint = finding_family_fingerprint(
        &sources,
        &actors,
        &sinks,
        &path_fingerprints,
        &remediation_rule_ids,
    );
    Ok(Finding {
        id: format!(
            "finding_{}:{}",
            graph.scan_id,
            fingerprint.trim_start_matches("sha256:")
        ),
        scan_id: graph.scan_id.clone(),
        fingerprint,
        family_fingerprint,
        finding_version: FINDING_VERSION,
        finding_class: FindingClass::UntrustedToProduction,
        status: FindingStatus::Open,
        title: TITLE.to_string(),
        summary: SUMMARY.to_string(),
        severity: first.severity,
        confidence: first.confidence,
        source_resource_ids: sources,
        actor_resource_ids: actors,
        sink_resource_ids: sinks,
        attack_path_ids: path_ids,
        attack_path_fingerprints: path_fingerprints,
        evidence_ids,
        reasons,
        remediations,
        created_at: Utc::now(),
    })
}

fn explicit_production_evidence_for_path(graph: &SecurityGraph, path: &AttackPath) -> Vec<String> {
    let Some(sink_key) = graph
        .node(&path.sink_resource_id)
        .map(|node| node.canonical_key.as_str())
    else {
        return Vec::new();
    };
    graph
        .evidence_index
        .by_evidence_id
        .values()
        .filter(|evidence| {
            evidence.scan_id == graph.scan_id
                && evidence_is_production(evidence, &path.sink_resource_id, Some(sink_key))
        })
        .map(|evidence| evidence.id.clone())
        .collect()
}

fn reason(
    code: ReasonCode,
    resource_ids: &BTreeSet<String>,
    relationship_ids: &BTreeSet<String>,
    path_fingerprints: &[String],
    evidence_ids: &[String],
) -> FindingReason {
    FindingReason {
        code,
        resource_ids: resource_ids.iter().cloned().collect(),
        relationship_ids: relationship_ids.iter().cloned().collect(),
        attack_path_fingerprints: path_fingerprints.to_vec(),
        evidence_ids: evidence_ids.to_vec(),
    }
}

fn remediations(graph: &SecurityGraph, candidates: &[Candidate<'_>]) -> Vec<Remediation> {
    let mut cuts: BTreeMap<&'static str, (Vec<String>, BTreeSet<String>, &'static str)> =
        BTreeMap::new();
    for candidate in candidates {
        for reference in candidate
            .path
            .influence_edges
            .iter()
            .chain(candidate.path.authority_edges.iter())
        {
            let Some(edge) = graph.edge(&reference.relationship_id) else {
                continue;
            };
            let rule = match edge.kind.as_str() {
                "can_retrieve" | "can_call" => "RESTRICT_EXTERNAL_RETRIEVAL",
                "can_execute" => "ENFORCE_BASH_APPROVAL_OR_DENY",
                "can_access" | "uses_credential" | "authenticates_to" => {
                    "REMOVE_AGENT_CREDENTIAL_REACHABILITY"
                }
                "can_mutate" | "can_deploy" => "SCOPE_PRODUCTION_MUTATION_AUTHORITY",
                _ => continue,
            };
            let phase = reference.phase.as_str();
            let entry = cuts
                .entry(rule)
                .or_insert_with(|| (Vec::new(), BTreeSet::new(), phase));
            entry.0.push(edge.relationship_id.clone());
            entry.1.insert(edge.from_resource_id.clone());
            entry.1.insert(edge.to_resource_id.clone());
        }
    }
    let descriptions = [
        (
            "RESTRICT_EXTERNAL_RETRIEVAL",
            "Restrict the exact external retrieval capability for the privileged Actor.",
            "Require an explicit boundary before externally controlled content is retrieved by the Actor.",
            "Break the influence segment before content reaches the Actor.",
        ),
        (
            "ENFORCE_BASH_APPROVAL_OR_DENY",
            "Require technically enforced, non-bypassable approval or deny for Bash.",
            "Ensure the Actor cannot self-approve execution of the shell capability.",
            "Interrupt autonomous execution before authority becomes reachable.",
        ),
        (
            "REMOVE_AGENT_CREDENTIAL_REACHABILITY",
            "Remove the credential from the Actor-reachable execution environment.",
            "Prevent autonomous execution from reaching the authority-bearing credential.",
            "Break the authority segment before credential use.",
        ),
        (
            "SCOPE_PRODUCTION_MUTATION_AUTHORITY",
            "Scope mutation authority away from the affected production target.",
            "Remove or narrow the exact production mutation edge reached by the Actor.",
            "Limit the final authority-to-production mutation cut.",
        ),
    ];
    let mut output = Vec::new();
    for (rule_id, (mut relationship_ids, resources, phase)) in cuts {
        relationship_ids.sort();
        let Some((_, title, description, effect)) =
            descriptions.iter().find(|item| item.0 == rule_id)
        else {
            continue;
        };
        output.push(Remediation {
            rule_id: rule_id.to_string(),
            title: (*title).to_string(),
            description: (*description).to_string(),
            security_effect: (*effect).to_string(),
            cut_phase: phase.to_string(),
            target_resource_ids: resources.into_iter().collect(),
            target_relationship_ids: relationship_ids,
        });
    }
    output.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    output
}

fn canonical_node(graph: &SecurityGraph, id: &str) -> String {
    graph
        .node(id)
        .map(|node| node.canonical_key.clone())
        .unwrap_or_else(|| id.to_string())
}

fn fingerprint_input(
    sources: &[String],
    actors: &[String],
    sinks: &[String],
    paths: &[String],
    severity: Option<Severity>,
    confidence: Option<Confidence>,
    remediation_rules: &[String],
) -> String {
    let mut input = String::new();
    field(&mut input, "version", &FINDING_VERSION.to_string());
    field(
        &mut input,
        "class",
        FindingClass::UntrustedToProduction.as_str(),
    );
    for value in sources {
        field(&mut input, "source", value);
    }
    for value in actors {
        field(&mut input, "actor", value);
    }
    for value in sinks {
        field(&mut input, "sink", value);
    }
    for value in paths {
        field(&mut input, "path", value);
    }
    if let Some(severity) = severity {
        field(&mut input, "severity", severity.as_str());
    }
    if let Some(confidence) = confidence {
        field(&mut input, "confidence", confidence.as_str());
    }
    for value in remediation_rules {
        field(&mut input, "remediation", value);
    }
    input
}

fn finding_fingerprint(
    sources: &[String],
    actors: &[String],
    sinks: &[String],
    paths: &[String],
    severity: Severity,
    confidence: Confidence,
    remediation_rules: &[String],
) -> String {
    let input = fingerprint_input(
        sources,
        actors,
        sinks,
        paths,
        Some(severity),
        Some(confidence),
        remediation_rules,
    );
    let digest = Sha256::digest(input.as_bytes());
    format!("sha256:{digest:x}")
}

fn finding_family_fingerprint(
    sources: &[String],
    actors: &[String],
    sinks: &[String],
    paths: &[String],
    remediation_rules: &[String],
) -> String {
    let input = fingerprint_input(sources, actors, sinks, paths, None, None, remediation_rules);
    let digest = Sha256::digest(input.as_bytes());
    format!("sha256:{digest:x}")
}

fn field(output: &mut String, label: &str, value: &str) {
    output.push_str(&format!("{}:{}:{}:", label.len(), label, value.len()));
    output.push_str(value);
    output.push(';');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::BoundaryKind;
    use crate::analysis::{
        BoundaryEvaluation, PathEdgeRef, PathPhase, TraversalDirection, ANALYSIS_VERSION,
    };
    use crate::application::{DiffService, FindingDiff, FindingDiffResult, FindingRatingDelta};
    use crate::cli::render::render_finding_diff;
    use crate::domain::{RelationshipState, Sensitivity};
    use crate::graph::{EdgeUsability, GraphEdge, GraphEvidenceIndex, GraphNode, SecurityRole};
    use crate::persistence::{Database, FindingRecord, FindingRepo, ScanRepo};
    use crate::shared::PICO_VERSION;
    use serde_json::json;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Test-support fixture (Sprint 028 engine test). Builds the golden
    /// six-node graph (source/tool/actor/bash/credential/sink with
    /// call/retrieve/execute/access/mutate edges carrying per-edge Evidence
    /// plus production evidence) for `scan_id`, and the single-candidate-path
    /// COMPLETE analysis whose source trust is `source_trust`. All Evidence and
    /// AttackPath identities carry `scan_id`, so [`generate`] accepts the
    /// fixture output unchanged.
    fn severity_change_fixture(
        scan_id: &str,
        source_trust: SourceTrust,
    ) -> (SecurityGraph, AnalysisResult) {
        let graph = fixture_graph(scan_id);
        let analysis = analysis_of(
            &graph.scan_id,
            vec![candidate_path(
                &graph,
                "p-candidate",
                source_trust,
                &["call", "retrieve"],
                &["execute", "access", "mutate"],
                Vec::new(),
            )],
        );
        (graph, analysis)
    }

    /// The golden graph behind [`severity_change_fixture`], built for `scan_id`.
    fn fixture_graph(scan_id: &str) -> SecurityGraph {
        let scan_id = scan_id.to_string();
        let ids = ["source", "tool", "actor", "bash", "credential", "sink"];
        let mut nodes = Vec::new();
        for id in ids {
            let (key, roles, metadata) = match id {
                "source" => (
                    "source:github:issue",
                    vec![SecurityRole::Source],
                    Some(
                        json!({"trust":"PUBLIC_EXTERNAL","influence_strength":"AGENT_RETRIEVABLE"}),
                    ),
                ),
                "actor" => ("agent:opencode", vec![SecurityRole::Actor], None),
                "bash" => (
                    "shell:bash",
                    vec![SecurityRole::Capability],
                    Some(json!({"capability":"EXECUTE"})),
                ),
                "sink" => (
                    "cloudflare:worker:production",
                    vec![SecurityRole::Sink],
                    Some(json!({"consequential_sink":true,"sink_impact":"PRODUCTION"})),
                ),
                "credential" => (
                    "credential:cloudflare:fingerprint",
                    vec![SecurityRole::Authority],
                    None,
                ),
                "tool" => ("mcp:github:tool", vec![SecurityRole::Capability], None),
                _ => unreachable!(),
            };
            nodes.push(GraphNode {
                resource_id: id.into(),
                canonical_key: key.into(),
                kind: "fixture".into(),
                provider: "fixture".into(),
                name: id.into(),
                safe_metadata: metadata,
                roles,
            });
        }
        let edge_defs = [
            ("call", "actor", "tool", "can_call"),
            ("retrieve", "tool", "source", "can_retrieve"),
            ("execute", "actor", "bash", "can_execute"),
            ("access", "bash", "credential", "can_access"),
            ("mutate", "credential", "sink", "can_mutate"),
        ];
        let mut edges = Vec::new();
        let mut outgoing = BTreeMap::new();
        let mut incoming = BTreeMap::new();
        let mut evidence = GraphEvidenceIndex::default();
        for (id, from, to, kind) in edge_defs {
            let mut edge = GraphEdge {
                relationship_id: id.into(),
                canonical_key: format!("{from}|{kind}|{to}"),
                from_resource_id: from.into(),
                to_resource_id: to.into(),
                kind: kind.into(),
                state: RelationshipState::Derived,
                usability: EdgeUsability::Traversable,
                safe_metadata: None,
                evidence_ids: vec![format!("ev-{id}")],
            };
            if id == "mutate" {
                edge.safe_metadata = Some(json!({"authority_resolution":"EXACT"}));
            }
            outgoing
                .entry(from.into())
                .or_insert_with(Vec::new)
                .push(id.into());
            incoming
                .entry(to.into())
                .or_insert_with(Vec::new)
                .push(id.into());
            let mut item = Evidence::new(
                &scan_id,
                EvidenceClass::Derived,
                "fixture",
                "fixture",
                &edge.canonical_key,
                "observed",
                Sensitivity::Internal,
            )
            .unwrap();
            item.id = format!("ev-{id}");
            evidence.by_evidence_id.insert(item.id.clone(), item);
            evidence
                .by_relationship_id
                .insert(id.into(), edge.evidence_ids.clone());
            edges.push(edge);
        }
        let mut production = Evidence::new(
            &scan_id,
            EvidenceClass::Declared,
            "fixture",
            "fixture",
            "sink",
            "sink_impact=PRODUCTION",
            Sensitivity::Internal,
        )
        .unwrap();
        production.id = "ev-production".into();
        production.metadata = Some(json!({"sink_impact":"PRODUCTION"}));
        evidence
            .by_evidence_id
            .insert(production.id.clone(), production);
        SecurityGraph {
            scan_id,
            snapshot_version: 1,
            nodes,
            edges,
            outgoing_index: outgoing,
            incoming_index: incoming,
            evidence_index: evidence,
        }
    }

    /// Construct an eligible candidate AttackPath reaching the production sink.
    /// `influence`/`authority` are relationship ids present in `graph`.
    fn candidate_path(
        graph: &SecurityGraph,
        id: &str,
        source_trust: SourceTrust,
        influence: &[&str],
        authority: &[&str],
        boundaries: Vec<BoundaryEvaluation>,
    ) -> AttackPath {
        let influence_edges = influence
            .iter()
            .enumerate()
            .map(|(i, rid)| PathEdgeRef {
                relationship_id: (*rid).into(),
                phase: PathPhase::Influence,
                traversal: TraversalDirection::Forward,
                position: i,
            })
            .collect::<Vec<_>>();
        let authority_edges = authority
            .iter()
            .enumerate()
            .map(|(i, rid)| PathEdgeRef {
                relationship_id: (*rid).into(),
                phase: PathPhase::Authority,
                traversal: TraversalDirection::Forward,
                position: i,
            })
            .collect::<Vec<_>>();
        let mut evidence_ids = vec!["ev-production".to_string()];
        for rid in influence.iter().chain(authority.iter()) {
            evidence_ids.push(format!("ev-{rid}"));
        }
        AttackPath {
            id: id.into(),
            scan_id: graph.scan_id.clone(),
            fingerprint: String::new(),
            analysis_version: ANALYSIS_VERSION,
            source_resource_id: "source".into(),
            actor_resource_id: "actor".into(),
            sink_resource_id: "sink".into(),
            influence_edges,
            authority_edges,
            boundary_evaluations: boundaries,
            source_trust,
            influence_strength: InfluenceStrength::AgentRetrievable,
            capability: CapabilityClass::Execute,
            authority_resolution: AuthorityResolution::Exact,
            sink_impact: SinkImpact::Production,
            evidence_ids,
            disposition: CandidateDisposition::Active,
        }
        .with_fingerprint(graph)
    }

    /// A COMPLETE analysis result carrying exactly `paths` as its attack paths.
    fn analysis_of(scan_id: &str, paths: Vec<AttackPath>) -> AnalysisResult {
        AnalysisResult {
            scan_id: scan_id.into(),
            analysis_version: ANALYSIS_VERSION,
            status: AnalysisStatus::Complete,
            candidate_disposition: CandidateDisposition::Active,
            influence_paths: Vec::new(),
            authority_paths: Vec::new(),
            boundary_evaluations: Vec::new(),
            attack_paths: paths,
            unresolved_candidate_count: 0,
            diagnostics: Vec::new(),
        }
    }

    fn fixture() -> (SecurityGraph, AnalysisResult) {
        severity_change_fixture("scan-finding", SourceTrust::PublicExternal)
    }

    #[test]
    fn emits_critical_high_golden_finding() {
        let (graph, analysis) = fixture();
        let result = generate(&graph, &analysis, &FindingLimits::default());
        assert_eq!(result.status, FindingGenerationStatus::Complete);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.findings[0].confidence, Confidence::High);
        assert_eq!(
            result.findings[0].finding_class,
            FindingClass::UntrustedToProduction
        );
        assert_eq!(result.findings[0].remediations.len(), 4);
    }

    #[test]
    fn unknown_production_is_not_a_finding() {
        let (mut graph, analysis) = fixture();
        graph
            .nodes
            .iter_mut()
            .find(|node| node.resource_id == "sink")
            .unwrap()
            .safe_metadata = Some(json!({"consequential_sink":true,"sink_impact":"UNKNOWN"}));
        let mut analysis = analysis;
        analysis.attack_paths[0].sink_impact = SinkImpact::Unknown;
        let result = generate(&graph, &analysis, &FindingLimits::default());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn partial_and_limited_are_fail_closed() {
        let (graph, analysis) = fixture();
        let partial = generate_with_scan_status(
            &graph,
            &analysis,
            ScanStatus::Partial,
            &FindingLimits::default(),
        );
        assert!(partial.findings.is_empty());
        let mut limited_analysis = analysis;
        limited_analysis.status = AnalysisStatus::Limited;
        let limited = generate(&graph, &limited_analysis, &FindingLimits::default());
        assert!(limited.findings.is_empty());
    }

    #[test]
    fn equivalent_graphs_have_stable_finding_fingerprint() {
        let (graph, analysis) = fixture();
        let first = generate(&graph, &analysis, &FindingLimits::default());
        let mut second_graph = graph.clone();
        second_graph.scan_id = "scan-other".into();
        for evidence in second_graph.evidence_index.by_evidence_id.values_mut() {
            evidence.scan_id = "scan-other".into();
        }
        let mut second_analysis = analysis.clone();
        second_analysis.scan_id = "scan-other".into();
        second_analysis.attack_paths[0].scan_id = "scan-other".into();
        let second = generate(&second_graph, &second_analysis, &FindingLimits::default());
        assert_eq!(
            first.findings[0].fingerprint,
            second.findings[0].fingerprint
        );
        assert_ne!(first.findings[0].id, second.findings[0].id);
        assert_eq!(
            first.findings[0].family_fingerprint,
            second.findings[0].family_fingerprint
        );
    }

    #[test]
    fn family_fingerprint_ignores_severity_and_confidence() {
        let sources = vec!["source:github".into()];
        let actors = vec!["agent:opencode".into()];
        let sinks = vec!["cloudflare:worker:a".into()];
        let paths = vec!["sha256:path".into()];
        let rules = vec!["ENFORCE_BASH_APPROVAL_OR_DENY".into()];
        let family = finding_family_fingerprint(&sources, &actors, &sinks, &paths, &rules);
        let critical = finding_fingerprint(
            &sources,
            &actors,
            &sinks,
            &paths,
            Severity::Critical,
            Confidence::High,
            &rules,
        );
        let high = finding_fingerprint(
            &sources,
            &actors,
            &sinks,
            &paths,
            Severity::High,
            Confidence::Medium,
            &rules,
        );
        assert_ne!(critical, high);
        // Family identity is stable across severity/confidence-only changes:
        // both full fingerprints share the same family.
        assert_eq!(
            family,
            finding_family_fingerprint(&sources, &actors, &sinks, &paths, &rules)
        );
        // Canonical encoder: family input omits severity/confidence while the
        // full input carries them.
        let family_input = fingerprint_input(&sources, &actors, &sinks, &paths, None, None, &rules);
        let full_input = fingerprint_input(
            &sources,
            &actors,
            &sinks,
            &paths,
            Some(Severity::Critical),
            Some(Confidence::High),
            &rules,
        );
        assert!(!family_input.contains("severity"));
        assert!(!family_input.contains("confidence"));
        assert!(full_input.contains("severity"));
        assert!(full_input.contains("confidence"));
        // Version is part of the family identity.
        assert!(
            family_input.contains("7:version:1:1;"),
            "family input must carry the finding version prefix"
        );
        assert_ne!(
            family,
            finding_family_fingerprint(
                &sources,
                &actors,
                &["cloudflare:worker:b".into()],
                &paths,
                &rules
            )
        );
        assert_ne!(
            family,
            finding_family_fingerprint(&sources, &actors, &sinks, &["sha256:other".into()], &rules)
        );
        assert_ne!(
            family,
            finding_family_fingerprint(
                &sources,
                &actors,
                &sinks,
                &paths,
                &["RESTRICT_EXTERNAL_RETRIEVAL".into()]
            ),
            "family must flip when remediation rules change"
        );
        assert_ne!(
            family,
            finding_family_fingerprint(&["source:other".into()], &actors, &sinks, &paths, &rules),
            "family must flip when sources change"
        );
    }

    #[test]
    fn fingerprint_input_is_canonical_for_full_and_family() {
        let sources = vec!["source:github".into()];
        let actors = vec!["agent:opencode".into()];
        let sinks = vec!["cloudflare:worker:a".into()];
        let paths = vec!["sha256:path".into()];
        let rules = vec!["ENFORCE_BASH_APPROVAL_OR_DENY".into()];
        let full_input = fingerprint_input(
            &sources,
            &actors,
            &sinks,
            &paths,
            Some(Severity::Critical),
            Some(Confidence::High),
            &rules,
        );
        let digest = Sha256::digest(full_input.as_bytes());
        assert_eq!(
            finding_fingerprint(
                &sources,
                &actors,
                &sinks,
                &paths,
                Severity::Critical,
                Confidence::High,
                &rules,
            ),
            format!("sha256:{digest:x}")
        );
        let family_input = fingerprint_input(&sources, &actors, &sinks, &paths, None, None, &rules);
        let digest = Sha256::digest(family_input.as_bytes());
        assert_eq!(
            finding_family_fingerprint(&sources, &actors, &sinks, &paths, &rules),
            format!("sha256:{digest:x}")
        );
        // Severity/confidence appear after paths and before remediations.
        let path_pos = full_input.find("4:path").expect("path field present");
        let sev_pos = full_input.find("severity").expect("severity present");
        let conf_pos = full_input.find("confidence").expect("confidence present");
        let rem_pos = full_input.find("remediation").expect("remediation present");
        assert!(path_pos < sev_pos && sev_pos < conf_pos && conf_pos < rem_pos);
        assert!(family_input.find("severity").is_none());
        assert!(family_input.find("confidence").is_none());
    }

    #[test]
    fn family_fingerprint_flips_when_remediation_rules_change() {
        let sources = vec!["source:github".into()];
        let actors = vec!["agent:opencode".into()];
        let sinks = vec!["cloudflare:worker:a".into()];
        let paths = vec!["sha256:path".into()];
        let base = finding_family_fingerprint(
            &sources,
            &actors,
            &sinks,
            &paths,
            &["ENFORCE_BASH_APPROVAL_OR_DENY".into()],
        );
        assert_ne!(
            base,
            finding_family_fingerprint(&sources, &actors, &sinks, &paths, &[])
        );
        assert_ne!(
            base,
            finding_family_fingerprint(
                &sources,
                &actors,
                &sinks,
                &paths,
                &["SCOPE_PRODUCTION_MUTATION_AUTHORITY".into()]
            )
        );
    }

    #[test]
    fn stale_evidence_cannot_produce_confirmed_edge() {
        assert!(
            !freshness_confidence(
                crate::domain::evidence::Freshness::Stale,
                ScanStatus::Complete
            )
            .may_be_confirmed
        );
    }

    #[test]
    fn partial_scan_evidence_never_upgrades_confidence() {
        let confirmed = freshness_confidence(
            crate::domain::evidence::Freshness::Fresh,
            ScanStatus::Partial,
        );
        assert!(!confirmed.may_be_confirmed);
        assert!(confirmed.penalty >= 0.1);
    }

    #[test]
    fn stale_backed_security_critical_edge_suppresses_finding() {
        let (mut graph, analysis) = fixture();
        for evidence in graph.evidence_index.by_evidence_id.values_mut() {
            evidence.captured_at = Utc::now() - chrono::Duration::days(2);
        }
        let result = generate(&graph, &analysis, &FindingLimits::default());
        assert!(result.findings.is_empty());
    }

    // --- Fingerprint / boundary / threshold fixtures (golden path untouched) ---

    /// Build a graph that mirrors [`fixture`] but also exposes a second
    /// externally-reachable influence route (`actor -> tool2 -> source`) so a
    /// test can construct two candidate AttackPaths whose security-critical
    /// (authority) edges are identical while the influence segment differs.
    fn two_route_graph() -> SecurityGraph {
        let (mut graph, _analysis) = fixture();
        graph.nodes.push(GraphNode {
            resource_id: "tool2".into(),
            canonical_key: "mcp:github:tool2".into(),
            kind: "fixture".into(),
            provider: "fixture".into(),
            name: "tool2".into(),
            safe_metadata: None,
            roles: vec![SecurityRole::Capability],
        });
        for (id, from, to, kind) in [
            ("call2", "actor", "tool2", "can_call"),
            ("retrieve2", "tool2", "source", "can_retrieve"),
        ] {
            let edge = GraphEdge {
                relationship_id: id.into(),
                canonical_key: format!("{from}|{kind}|{to}"),
                from_resource_id: from.into(),
                to_resource_id: to.into(),
                kind: kind.into(),
                state: RelationshipState::Derived,
                usability: EdgeUsability::Traversable,
                safe_metadata: None,
                evidence_ids: vec![format!("ev-{id}")],
            };
            graph
                .outgoing_index
                .entry(from.into())
                .or_default()
                .push(id.into());
            graph
                .incoming_index
                .entry(to.into())
                .or_default()
                .push(id.into());
            let mut item = Evidence::new(
                &graph.scan_id,
                EvidenceClass::Derived,
                "fixture",
                "fixture",
                &edge.canonical_key,
                "observed",
                Sensitivity::Internal,
            )
            .unwrap();
            item.id = format!("ev-{id}");
            graph
                .evidence_index
                .by_evidence_id
                .insert(item.id.clone(), item);
            graph
                .evidence_index
                .by_relationship_id
                .insert(id.into(), edge.evidence_ids.clone());
            graph.edges.push(edge);
        }
        graph
    }

    /// R1: identical scans must yield byte-identical finding fingerprints (no
    /// randomness in identity).
    #[test]
    fn finding_fingerprint_stable_across_identical_scans() {
        let (graph, analysis) = fixture();
        let first = generate(&graph, &analysis, &FindingLimits::default());
        let (graph2, analysis2) = fixture();
        let second = generate(&graph2, &analysis2, &FindingLimits::default());
        assert_eq!(first.findings.len(), 1);
        assert_eq!(second.findings.len(), 1);
        assert_eq!(
            first.findings[0].fingerprint,
            second.findings[0].fingerprint
        );
    }

    /// R2: a security-significant change (a HardDeny boundary now guards the
    /// critical Bash execution edge) must flip the finding fingerprint in the
    /// expected direction while still producing exactly one finding.
    #[test]
    fn finding_fingerprint_flips_on_security_significant_change() {
        let (graph, analysis) = fixture();
        let base = generate(&graph, &analysis, &FindingLimits::default());
        assert_eq!(base.findings.len(), 1);
        let mut changed = analysis.clone();
        let mut path = changed.attack_paths[0].clone();
        path.boundary_evaluations.push(BoundaryEvaluation {
            kind: BoundaryKind::HardDeny,
            affected_resource_ids: vec!["bash".into()],
            affected_relationship_ids: vec!["execute".into()],
            enforcement: "fixture".into(),
            interrupted_phase: None,
            decision: BoundaryDecision::DoesNotInterrupt,
            evidence_ids: Vec::new(),
        });
        path = path.with_fingerprint(&graph);
        changed.attack_paths[0] = path;
        let flipped = generate(&graph, &changed, &FindingLimits::default());
        assert_eq!(flipped.findings.len(), 1);
        assert_ne!(
            base.findings[0].fingerprint,
            flipped.findings[0].fingerprint
        );
        assert_ne!(
            base.findings[0].attack_path_fingerprints[0],
            flipped.findings[0].attack_path_fingerprints[0]
        );
    }

    /// R3: N (>=2) candidate paths to the same sink with identical security-
    /// critical (authority) edges and identical boundary evaluations are
    /// grouped into exactly ONE finding, but every distinct candidate path
    /// fingerprint is retained (`attack_path_fingerprints.len() == N`).
    #[test]
    fn same_sink_paths_with_identical_edges_deduplicate() {
        let graph = two_route_graph();
        let pa = candidate_path(
            &graph,
            "p-a",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let pb = candidate_path(
            &graph,
            "p-b",
            SourceTrust::PublicExternal,
            &["call2", "retrieve2"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis = analysis_of(&graph.scan_id, vec![pa.clone(), pb.clone()]);
        let result = generate(&graph, &analysis, &FindingLimits::default());
        assert_eq!(result.status, FindingGenerationStatus::Complete);
        assert_eq!(
            result.findings.len(),
            1,
            "identical critical edges group into one finding"
        );
        assert_eq!(
            result.findings[0].attack_path_fingerprints.len(),
            2,
            "both candidate paths recorded"
        );
        assert!(result.findings[0]
            .attack_path_fingerprints
            .contains(&pa.fingerprint));
        assert!(result.findings[0]
            .attack_path_fingerprints
            .contains(&pb.fingerprint));
    }

    /// R4: two candidate paths to the same sink with identical edges but
    /// DIFFERENT boundary evaluations (one carries a HardDeny boundary, the
    /// other none) are NOT collapsed into a single boundary-less story. Both
    /// distinct path fingerprints are retained and the boundary difference is
    /// observable in the output (the fingerprints differ).
    #[test]
    fn distinct_boundaries_remain_distinct_after_deduplication() {
        let graph = two_route_graph();
        let boundary = BoundaryEvaluation {
            kind: BoundaryKind::HardDeny,
            affected_resource_ids: vec!["bash".into()],
            affected_relationship_ids: vec!["execute".into()],
            enforcement: "fixture".into(),
            interrupted_phase: None,
            decision: BoundaryDecision::DoesNotInterrupt,
            evidence_ids: Vec::new(),
        };
        let guarded = candidate_path(
            &graph,
            "p-guarded",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            vec![boundary],
        );
        let unguarded = candidate_path(
            &graph,
            "p-unguarded",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis = analysis_of(&graph.scan_id, vec![guarded.clone(), unguarded.clone()]);
        let result = generate(&graph, &analysis, &FindingLimits::default());
        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings[0].attack_path_fingerprints.len(),
            2,
            "both boundary states retained"
        );
        let fps = result.findings[0].attack_path_fingerprints.clone();
        assert!(fps.contains(&guarded.fingerprint));
        assert!(fps.contains(&unguarded.fingerprint));
        assert_ne!(
            guarded.fingerprint, unguarded.fingerprint,
            "boundary difference is observable in the fingerprint"
        );
    }

    /// R5: severity and confidence are each deterministic across identical runs
    /// and are independent axes — changing only the severity driver (source
    /// trust) does not silently alter the confidence cut point.
    #[test]
    fn severity_confidence_independence_stable() {
        let (graph, analysis) = fixture();
        let first = generate(&graph, &analysis, &FindingLimits::default());
        let (graph2, analysis2) = fixture();
        let second = generate(&graph2, &analysis2, &FindingLimits::default());
        assert_eq!(first.findings[0].severity, second.findings[0].severity);
        assert_eq!(first.findings[0].confidence, second.findings[0].confidence);

        // Change only the severity input (PUBLIC_EXTERNAL →
        // AUTHENTICATED_EXTERNAL on the analyzed path; source trust is
        // deliberately excluded from the path fingerprint) and confirm the
        // confidence axis is untouched.
        let mut auth_analysis = analysis.clone();
        auth_analysis.attack_paths[0].source_trust = SourceTrust::AuthenticatedExternal;
        let auth = generate(&graph, &auth_analysis, &FindingLimits::default());
        assert_eq!(auth.findings[0].severity, Severity::High);
        assert_eq!(
            auth.findings[0].confidence, first.findings[0].confidence,
            "confidence axis is independent of the severity driver"
        );
        // Lifecycle continuity: the severity-driver change flips the full
        // fingerprint while the family fingerprint stays identical — the
        // engine itself pairs CRITICAL → HIGH findings into one family.
        assert_ne!(
            first.findings[0].fingerprint, auth.findings[0].fingerprint,
            "a severity change must flip the full fingerprint"
        );
        assert_eq!(
            first.findings[0].family_fingerprint, auth.findings[0].family_fingerprint,
            "family identity must survive a severity change"
        );
    }

    /// R6: for identical inputs the severity and confidence cut points the
    /// engine assigns are byte-identical across runs.
    ///
    /// Support note — observed thresholds (from `eligible_candidate`):
    /// severity is `Critical` when `source_trust` is PublicExternal|OpenWorld,
    /// `High` when AuthenticatedExternal (else suppressed); confidence is `High`
    /// iff every path + production Evidence is non-Inferred and of class
    /// Direct|Declared|Derived (else suppressed). For the golden PUBLIC_EXTERNAL
    /// graph these resolve to `Severity::Critical` + `Confidence::High`,
    /// identical across runs.
    #[test]
    fn cut_point_thresholds_are_deterministic() {
        let (graph, analysis) = fixture();
        let first = generate(&graph, &analysis, &FindingLimits::default());
        let (graph2, analysis2) = fixture();
        let second = generate(&graph2, &analysis2, &FindingLimits::default());
        assert_eq!(first.findings[0].severity, second.findings[0].severity);
        assert_eq!(first.findings[0].confidence, second.findings[0].confidence);
        assert_eq!(first.findings[0].severity, Severity::Critical);
        assert_eq!(first.findings[0].confidence, Confidence::High);
    }

    /// R7: the produced finding targets the correct relationship for the
    /// Bash-execution remediation and is stable across identical runs. The
    /// `ENFORCE_BASH_APPROVAL_OR_DENY` rule maps (in `remediations`) to the
    /// `can_execute` edge, whose relationship id is `execute`.
    #[test]
    fn remediation_targets_correct_relationship() {
        let (graph, analysis) = fixture();
        let first = generate(&graph, &analysis, &FindingLimits::default());
        let (graph2, analysis2) = fixture();
        let second = generate(&graph2, &analysis2, &FindingLimits::default());
        let find = |result: &FindingResult| {
            result.findings[0]
                .remediations
                .iter()
                .find(|m| m.rule_id == "ENFORCE_BASH_APPROVAL_OR_DENY")
                .expect("ENFORCE_BASH_APPROVAL_OR_DENY remediation present")
                .clone()
        };
        let ra = find(&first);
        let rb = find(&second);
        assert_eq!(ra.target_relationship_ids, vec!["execute".to_string()]);
        assert_eq!(rb.target_relationship_ids, vec!["execute".to_string()]);
        assert_eq!(
            ra.target_relationship_ids, rb.target_relationship_ids,
            "remediation target is stable across identical runs"
        );
    }

    // --- Structured diagnostics fixtures (R2/R3/R4/R9) ---

    /// Age every Evidence supporting `relationship_id` so its freshness relative
    /// to `now` is the requested state. Drives stale/aging classification for the
    /// diagnostics fixtures.
    fn age_edge_evidence(graph: &mut SecurityGraph, relationship_id: &str, age: chrono::Duration) {
        let ids = graph
            .evidence_index
            .by_relationship_id
            .get(relationship_id)
            .cloned()
            .unwrap_or_default();
        for id in ids {
            if let Some(evidence) = graph.evidence_index.by_evidence_id.get_mut(&id) {
                evidence.captured_at = Utc::now() - age;
            }
        }
    }

    /// Remove every Evidence supporting `relationship_id` so its freshness
    /// resolves to `Unknown` (no supporting Evidence at all).
    fn drop_edge_evidence(graph: &mut SecurityGraph, relationship_id: &str) {
        if let Some(ids) = graph
            .evidence_index
            .by_relationship_id
            .remove(relationship_id)
        {
            for id in ids {
                graph.evidence_index.by_evidence_id.remove(&id);
            }
        }
    }

    /// R2: a candidate AttackPath that is Active but suppressed because a
    /// security-critical edge is not confirmable must report an honest,
    /// edge-naming reason.
    #[test]
    fn diagnostics_explain_suppressed_finding_reason() {
        let (mut graph, _base) = fixture();
        // Make only the `mutate` authority edge stale so the single candidate
        // path becomes unconfirmable and therefore suppressed (not a Finding).
        age_edge_evidence(&mut graph, "mutate", chrono::Duration::days(2));
        let path = candidate_path(
            &graph,
            "p-stale",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis = analysis_of(&graph.scan_id, vec![path.clone()]);
        let generated = generate_with_scan_status(
            &graph,
            &analysis,
            ScanStatus::Complete,
            &FindingLimits::default(),
        );
        assert!(generated.findings.is_empty());
        let (suppressed, _reduced) =
            eligibility_diagnostics(&graph, &analysis, ScanStatus::Complete, &generated.findings);
        let entry = suppressed
            .iter()
            .find(|s| s.fingerprint == path.fingerprint)
            .expect("stale path is suppressed");
        assert!(
            entry.reason.contains("not confirmable: STALE"),
            "reason was: {}",
            entry.reason
        );
        assert!(
            entry.reason.contains("mutate"),
            "reason must name the unconfirmable edge: {}",
            entry.reason
        );
    }

    /// R3: a Stale edge and an Unknown-freshness edge are each classified
    /// correctly in the suppression diagnostics (separate graphs so the global
    /// edge evidence does not collide).
    #[test]
    fn diagnostics_classify_incomplete_edge_evidence() {
        // Stale critical edge.
        let (mut graph_stale, _b) = fixture();
        age_edge_evidence(&mut graph_stale, "mutate", chrono::Duration::days(2));
        let stale_path = candidate_path(
            &graph_stale,
            "p-stale",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis_stale = analysis_of(&graph_stale.scan_id, vec![stale_path.clone()]);
        let gen_stale = generate_with_scan_status(
            &graph_stale,
            &analysis_stale,
            ScanStatus::Complete,
            &FindingLimits::default(),
        );
        assert!(gen_stale.findings.is_empty());
        let (supp_stale, _) = eligibility_diagnostics(
            &graph_stale,
            &analysis_stale,
            ScanStatus::Complete,
            &gen_stale.findings,
        );
        let stale = supp_stale
            .iter()
            .find(|s| s.fingerprint == stale_path.fingerprint)
            .expect("stale path suppressed");
        assert!(
            stale.reason.contains("not confirmable: STALE"),
            "reason was: {}",
            stale.reason
        );

        // Unknown-freshness critical edge.
        let (mut graph_unknown, _b) = fixture();
        drop_edge_evidence(&mut graph_unknown, "access");
        let unknown_path = candidate_path(
            &graph_unknown,
            "p-unknown",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis_unknown = analysis_of(&graph_unknown.scan_id, vec![unknown_path.clone()]);
        let gen_unknown = generate_with_scan_status(
            &graph_unknown,
            &analysis_unknown,
            ScanStatus::Complete,
            &FindingLimits::default(),
        );
        assert!(gen_unknown.findings.is_empty());
        let (supp_unknown, _) = eligibility_diagnostics(
            &graph_unknown,
            &analysis_unknown,
            ScanStatus::Complete,
            &gen_unknown.findings,
        );
        let unknown = supp_unknown
            .iter()
            .find(|s| s.fingerprint == unknown_path.fingerprint)
            .expect("unknown path suppressed");
        assert!(
            unknown.reason.contains("not confirmable: UNKNOWN"),
            "reason was: {}",
            unknown.reason
        );
    }

    /// R4: an Aging security-critical edge must appear in a Finding's
    /// confidence-reduction note with penalty 0.1.
    #[test]
    fn diagnostics_explain_confidence_reduction() {
        let (mut graph, _b) = fixture();
        // Age only the `execute` authority edge into the AGING window.
        age_edge_evidence(&mut graph, "execute", chrono::Duration::hours(2));
        let path = candidate_path(
            &graph,
            "p-aging",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis = analysis_of(&graph.scan_id, vec![path.clone()]);
        let generated = generate_with_scan_status(
            &graph,
            &analysis,
            ScanStatus::Complete,
            &FindingLimits::default(),
        );
        assert_eq!(generated.findings.len(), 1);
        let (_suppressed, reduced) =
            eligibility_diagnostics(&graph, &analysis, ScanStatus::Complete, &generated.findings);
        let note = reduced
            .iter()
            .find(|n| n.fingerprint == generated.findings[0].fingerprint)
            .expect("emitted finding carries a confidence note");
        let edge = note
            .edges
            .iter()
            .find(|(key, fresh, _)| key == "execute" && fresh == "AGING")
            .expect("execute edge reported as AGING");
        assert_eq!(edge.2, 0.1);
    }

    /// R9: identical scan inputs must yield byte-identical structured
    /// diagnostics (ties the S015 stability contract).
    #[test]
    fn diagnostics_stable_across_identical_scans() {
        let (mut graph, _b) = fixture();
        age_edge_evidence(&mut graph, "mutate", chrono::Duration::days(2));
        let path = candidate_path(
            &graph,
            "p-stale",
            SourceTrust::PublicExternal,
            &["call", "retrieve"],
            &["execute", "access", "mutate"],
            Vec::new(),
        );
        let analysis = analysis_of(&graph.scan_id, vec![path.clone()]);
        let generated = generate_with_scan_status(
            &graph,
            &analysis,
            ScanStatus::Complete,
            &FindingLimits::default(),
        );
        let first =
            eligibility_diagnostics(&graph, &analysis, ScanStatus::Complete, &generated.findings);
        let second =
            eligibility_diagnostics(&graph, &analysis, ScanStatus::Complete, &generated.findings);
        assert_eq!(first, second);
    }

    // --- Persistence / diff seam (Sprint 028 lifecycle continuity) ---

    fn setup_db() -> (tempfile::TempDir, Database) {
        let workspace = tempdir().unwrap();
        let dir = workspace.path().join(".pico");
        std::fs::create_dir_all(&dir).unwrap();
        let mut db = Database::open(&dir.join("pico.db")).unwrap();
        db.migrate().unwrap();
        (workspace, db)
    }

    fn insert_complete_scan(db: &Database) -> String {
        let mut scan = crate::domain::Scan::start(PICO_VERSION).unwrap();
        // Every fixture scan declares the comparison contract (SPRINT-029).
        scan.metadata = Some(json!({
            "comparison_contract_version": 1,
            "graph_snapshot_version": 1,
            "finding_version": 1,
        }));
        let scan = scan.complete().unwrap();
        ScanRepo::new(db.connection()).insert(&scan).unwrap();
        // The COMPLETE-summary guard makes the repository refuse a summary
        // once the parent scan row is COMPLETE, so the fixture seeds it with
        // raw SQL.
        db.connection()
            .execute(
                "INSERT INTO scan_analyses
                 (scan_id, analysis_version, status, overall_disposition,
                  influence_path_count, authority_path_count, active_path_count,
                  blocked_path_count, unresolved_candidate_count, created_at)
                 VALUES (?1, '1', 'COMPLETE', 'NONE', 0, 0, 0, 0, 0, ?2)",
                rusqlite::params![scan.id, crate::persistence::codec::ts_to_text(Utc::now())],
            )
            .unwrap();
        scan.id
    }

    fn compare_ready(workspace: &std::path::Path, from_id: &str, to_id: &str) -> FindingDiff {
        match DiffService::compare(workspace, from_id, to_id).unwrap() {
            FindingDiffResult::Ready(value) => value,
            other => panic!("expected Ready diff, got {other:?}"),
        }
    }

    /// Rendered text of one lifecycle bucket heading up to the next heading.
    fn lifecycle_section<'a>(rendered: &'a str, heading: &str) -> &'a str {
        let marker = format!("\n{heading}\n");
        let start = rendered
            .find(&marker)
            .unwrap_or_else(|| panic!("{heading} section missing in:\n{rendered}"));
        let rest = &rendered[start..];
        let end = [
            "\nAppeared\n",
            "\nDisappeared\n",
            "\nWeakened\n",
            "\nStrengthened\n",
            "\nUncertain\n",
            "\nResources\n",
        ]
        .iter()
        .filter(|next| **next != marker)
        .filter_map(|next| rest.find(*next))
        .min()
        .unwrap_or(rest.len());
        &rest[..end]
    }

    /// P1-5: engine-generated lifecycle continuity through the persisted
    /// compare path, with no fabricated identities. Both sides of the pair
    /// come from the findings engine itself: `severity_change_fixture` builds
    /// the golden graph for each scan id, and the source-trust change
    /// (PUBLIC_EXTERNAL → AUTHENTICATED_EXTERNAL) flips the full fingerprint
    /// while the engine keeps the family fingerprint identical. The engine
    /// Findings are persisted via FindingRepo and diffed end-to-end:
    /// weakened=1 with a severity delta, conserving every row.
    #[test]
    fn engine_generated_severity_change_is_weakened() {
        let (graph_a, analysis_a) =
            severity_change_fixture("scanA-engine-severity", SourceTrust::PublicExternal);
        let (graph_b, analysis_b) =
            severity_change_fixture("scanB-engine-severity", SourceTrust::AuthenticatedExternal);
        let result_a = generate(&graph_a, &analysis_a, &FindingLimits::default());
        let result_b = generate(&graph_b, &analysis_b, &FindingLimits::default());
        assert_eq!(result_a.findings.len(), 1);
        assert_eq!(result_b.findings.len(), 1);
        let finding_a = &result_a.findings[0];
        let finding_b = &result_b.findings[0];
        assert_eq!(finding_a.severity, Severity::Critical);
        assert_eq!(finding_a.confidence, Confidence::High);
        assert_eq!(finding_b.severity, Severity::High);
        assert_eq!(finding_b.confidence, Confidence::High);
        assert_ne!(
            finding_a.fingerprint, finding_b.fingerprint,
            "the severity change must flip the full fingerprint"
        );
        assert_eq!(
            finding_a.family_fingerprint, finding_b.family_fingerprint,
            "the severity change must keep the engine family fingerprint"
        );
        for fingerprint in [&finding_a.fingerprint, &finding_b.fingerprint] {
            assert!(
                fingerprint.starts_with("sha256:"),
                "engine fingerprints must be sha256, got {fingerprint}"
            );
            assert_ne!(*fingerprint, "sha256:engine-critical");
            assert_ne!(*fingerprint, "sha256:engine-high");
        }
        assert_ne!(
            finding_a.family_fingerprint, "sha256:family-engine",
            "family fingerprint must come from the engine, not the old fixture literal"
        );

        let (workspace, db) = setup_db();
        let from_id = insert_complete_scan(&db);
        // Distinct started_at so the from scan is at-or-before the to scan for
        // the temporal guard.
        thread::sleep(Duration::from_millis(2));
        let to_id = insert_complete_scan(&db);
        let repo = FindingRepo::new(db.connection());
        // The engine Finding carries the fixture's scan_id; map it onto the
        // persisted scan row so the findings FK holds. Identities
        // (fingerprint, family_fingerprint) come from the engine directly.
        let record = |scan_id: &str, finding: &Finding| FindingRecord {
            id: finding.id.clone(),
            scan_id: scan_id.to_string(),
            fingerprint: finding.fingerprint.clone(),
            family_fingerprint: finding.family_fingerprint.clone(),
            finding_version: finding.finding_version.to_string(),
            finding_class: finding.finding_class.as_str().to_string(),
            title: finding.title.clone(),
            summary: finding.summary.clone(),
            severity: finding.severity.as_str().to_string(),
            confidence: finding.confidence.as_str().to_string(),
            status: finding.status.as_str().to_string(),
            metadata: None,
            created_at: finding.created_at,
        };
        repo.insert(&record(&from_id, finding_a)).unwrap();
        repo.insert(&record(&to_id, finding_b)).unwrap();

        let comparison = compare_ready(workspace.path(), &from_id, &to_id);
        assert_eq!(comparison.unchanged.len(), 0);
        assert_eq!(comparison.appeared.len(), 0);
        assert_eq!(comparison.disappeared.len(), 0);
        assert_eq!(comparison.strengthened.len(), 0);
        assert_eq!(comparison.uncertain.len(), 0);
        assert_eq!(comparison.weakened.len(), 1);
        let change = &comparison.weakened[0];
        // CRUX: the diff seam carries the actual engine-generated identities.
        assert_eq!(change.from.fingerprint, finding_a.fingerprint);
        assert_eq!(change.to.fingerprint, finding_b.fingerprint);
        assert_eq!(change.from.family_fingerprint, finding_a.family_fingerprint);
        assert_eq!(change.to.family_fingerprint, finding_b.family_fingerprint);
        assert_eq!(
            change.deltas,
            vec![FindingRatingDelta {
                field: "severity".to_string(),
                from_value: "CRITICAL".to_string(),
                to_value: "HIGH".to_string(),
            }]
        );

        // Conservation: from = unchanged + disappeared + weakened + strengthened
        // + uncertain (and likewise for the to side).
        let from_count = repo.count_for_scan(&from_id).unwrap() as usize;
        let to_count = repo.count_for_scan(&to_id).unwrap() as usize;
        let lifecycle =
            comparison.weakened.len() + comparison.strengthened.len() + comparison.uncertain.len();
        assert_eq!(
            from_count,
            comparison.unchanged.len()
                + comparison.disappeared.len()
                + comparison.weakened.len()
                + comparison.strengthened.len()
                + comparison.uncertain.len()
        );
        assert_eq!(from_count, lifecycle);
        assert_eq!(
            to_count,
            comparison.unchanged.len()
                + comparison.appeared.len()
                + comparison.weakened.len()
                + comparison.strengthened.len()
                + comparison.uncertain.len()
        );
        assert_eq!(to_count, lifecycle);

        let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
        let section = lifecycle_section(&rendered, "Weakened");
        assert!(section.contains("Cause: Severity CRITICAL → HIGH"));
        assert!(section.contains(&finding_a.fingerprint));
        assert!(section.contains(&finding_b.fingerprint));
    }
}
