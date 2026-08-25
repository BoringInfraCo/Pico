//! Deterministic joining and AttackPath construction.

use std::collections::BTreeSet;

use crate::domain::ScanStatus;
use crate::graph::SecurityGraph;

use super::authority;
use super::boundary;
use super::influence;
use super::model::{
    AnalysisLimits, AnalysisResult, AnalysisStatus, AttackPath, AuthorityResolution,
    CandidateDisposition, CapabilityClass, InfluenceStrength, SegmentDisposition, SourceTrust,
};

pub fn analyze(graph: &SecurityGraph, limits: &AnalysisLimits) -> AnalysisResult {
    analyze_with_scan_status(graph, limits, ScanStatus::Complete)
}

pub fn analyze_with_scan_status(
    graph: &SecurityGraph,
    limits: &AnalysisLimits,
    discovery_status: ScanStatus,
) -> AnalysisResult {
    let influence_result = influence::analyze(graph, limits);
    let authority_result = authority::analyze(graph, limits);
    let mut result = AnalysisResult {
        scan_id: graph.scan_id.clone(),
        analysis_version: super::model::ANALYSIS_VERSION,
        status: if influence_result.limited || authority_result.limited {
            AnalysisStatus::Limited
        } else {
            AnalysisStatus::Complete
        },
        candidate_disposition: CandidateDisposition::None,
        influence_paths: influence_result.paths,
        authority_paths: authority_result.paths,
        boundary_evaluations: Vec::new(),
        attack_paths: Vec::new(),
        unresolved_candidate_count: 0,
        diagnostics: influence_result
            .diagnostics
            .into_iter()
            .chain(authority_result.diagnostics)
            .collect(),
    };

    let mut joins = 0usize;
    let mut unresolved_candidates = 0usize;
    let mut active_candidates = 0usize;
    let mut blocked_candidates = 0usize;
    for influence_path in &result.influence_paths {
        for authority_path in &result.authority_paths {
            if joins >= limits.maximum_candidate_joins {
                result.status = AnalysisStatus::Limited;
                result
                    .diagnostics
                    .push("candidate join limit reached".to_string());
                break;
            }
            if influence_path.actor_resource_id != authority_path.actor_resource_id {
                continue;
            }
            joins += 1;
            let boundaries = boundary::evaluate(graph, influence_path, authority_path);
            result.boundary_evaluations.extend(boundaries.clone());
            let unresolved = influence_path.disposition == SegmentDisposition::Unresolved
                || authority_path.disposition == SegmentDisposition::Unresolved
                || influence_path.source_trust == SourceTrust::Unknown
                || influence_path.influence_strength == InfluenceStrength::Unknown
                || authority_path.capability == CapabilityClass::Unknown
                || !matches!(
                    authority_path.authority_resolution,
                    AuthorityResolution::Exact | AuthorityResolution::Scoped
                )
                || boundaries
                    .iter()
                    .any(|item| item.decision == super::model::BoundaryDecision::Unresolved);
            let blocked = influence_path.disposition == SegmentDisposition::Blocked
                || authority_path.disposition == SegmentDisposition::Blocked
                || boundaries
                    .iter()
                    .any(|item| item.decision == super::model::BoundaryDecision::Interrupts);
            let disposition = if unresolved {
                unresolved_candidates += 1;
                CandidateDisposition::Unresolved
            } else if blocked {
                blocked_candidates += 1;
                CandidateDisposition::Blocked
            } else {
                active_candidates += 1;
                CandidateDisposition::Active
            };
            let mut evidence_ids = influence_path
                .evidence_ids
                .iter()
                .chain(authority_path.evidence_ids.iter())
                .cloned()
                .collect::<Vec<_>>();
            evidence_ids.extend(
                boundaries
                    .iter()
                    .flat_map(|item| item.evidence_ids.iter().cloned()),
            );
            evidence_ids.sort();
            evidence_ids.dedup();
            if evidence_ids
                .iter()
                .any(|id| graph.evidence_index.evidence(id).is_none())
            {
                result.status = AnalysisStatus::Failed;
                result
                    .diagnostics
                    .push("candidate references evidence outside the graph".to_string());
                continue;
            }
            if result.status == AnalysisStatus::Limited
                || discovery_status == ScanStatus::Partial
                || discovery_status == ScanStatus::Failed
            {
                unresolved_candidates += usize::from(disposition != CandidateDisposition::None);
                continue;
            }
            if disposition == CandidateDisposition::Unresolved {
                continue;
            }
            if result.attack_paths.len() >= limits.maximum_emitted_attack_paths {
                result.status = AnalysisStatus::Limited;
                result
                    .diagnostics
                    .push("emitted AttackPath limit reached".to_string());
                continue;
            }
            let mut path = AttackPath {
                id: format!("attack_path_{}", result.attack_paths.len()),
                scan_id: graph.scan_id.clone(),
                fingerprint: String::new(),
                analysis_version: super::model::ANALYSIS_VERSION,
                source_resource_id: influence_path.source_resource_id.clone(),
                actor_resource_id: influence_path.actor_resource_id.clone(),
                sink_resource_id: authority_path.sink_resource_id.clone(),
                influence_edges: influence_path.edges.clone(),
                authority_edges: authority_path.edges.clone(),
                boundary_evaluations: boundaries,
                source_trust: influence_path.source_trust,
                influence_strength: influence_path.influence_strength,
                capability: authority_path.capability,
                authority_resolution: authority_path.authority_resolution,
                sink_impact: authority_path.sink_impact,
                evidence_ids,
                disposition,
            };
            path = path.with_fingerprint(graph);
            path.id = format!(
                "attack_path_{}:{}",
                graph.scan_id,
                path.fingerprint.trim_start_matches("sha256:")
            );
            result.attack_paths.push(path);
        }
    }
    result.boundary_evaluations.sort_by(|a, b| {
        a.affected_relationship_ids
            .cmp(&b.affected_relationship_ids)
            .then(a.kind.cmp(&b.kind))
    });
    result.boundary_evaluations.dedup();
    result
        .attack_paths
        .sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let mut unique = BTreeSet::new();
    result
        .attack_paths
        .retain(|path| unique.insert(path.fingerprint.clone()));
    result.candidate_disposition = if (discovery_status != ScanStatus::Complete
        || result.status == AnalysisStatus::Limited)
        && active_candidates + blocked_candidates + unresolved_candidates > 0
    {
        CandidateDisposition::Unresolved
    } else if active_candidates > 0 {
        CandidateDisposition::Active
    } else if unresolved_candidates > 0 {
        CandidateDisposition::Unresolved
    } else if blocked_candidates > 0 {
        CandidateDisposition::Blocked
    } else {
        CandidateDisposition::None
    };
    result.unresolved_candidate_count = unresolved_candidates;
    if result.status == AnalysisStatus::Limited {
        result.attack_paths.clear();
    }
    result
}
