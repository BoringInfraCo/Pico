//! Provider-neutral boundary evaluation over normalized graph facts.

use std::collections::BTreeSet;

use crate::graph::SecurityGraph;

use super::model::{
    metadata_bool, metadata_string, AuthorityPath, BoundaryDecision, BoundaryEvaluation,
    BoundaryKind, InfluencePath, PathPhase, SegmentDisposition,
};

pub fn evaluate(
    graph: &SecurityGraph,
    influence: &InfluencePath,
    authority: &AuthorityPath,
) -> Vec<BoundaryEvaluation> {
    let mut evaluations = Vec::new();
    let mut seen = BTreeSet::new();
    for path_edge in influence.edges.iter().chain(authority.edges.iter()) {
        let Some(edge) = graph.edge(&path_edge.relationship_id) else {
            continue;
        };
        let metadata = edge.safe_metadata.as_ref();
        let phase = Some(path_edge.phase);
        let (kind, enforcement, decision) = if edge.state
            == crate::domain::RelationshipState::Blocked
        {
            if metadata_string(metadata, "reachability").as_deref() == Some("APPROVAL_GATED") {
                approval_boundary(metadata, phase)
            } else if metadata_string(metadata, "scope_state").as_deref() == Some("OUT_OF_SCOPE") {
                (
                    BoundaryKind::ResourceScope,
                    "PROVEN".into(),
                    BoundaryDecision::Interrupts,
                )
            } else {
                (
                    BoundaryKind::HardDeny,
                    "PROVEN".into(),
                    BoundaryDecision::Interrupts,
                )
            }
        } else if edge.state == crate::domain::RelationshipState::Unknown {
            if metadata_string(metadata, "reachability").as_deref() == Some("APPROVAL_GATED")
                || metadata_string(metadata, "effective_permission").as_deref() == Some("ASK")
            {
                approval_boundary(metadata, phase)
            } else if metadata_string(metadata, "scope_state").as_deref() == Some("UNKNOWN") {
                (
                    BoundaryKind::CredentialScope,
                    "UNKNOWN".into(),
                    BoundaryDecision::Unresolved,
                )
            } else {
                (
                    BoundaryKind::HardDeny,
                    "UNKNOWN".into(),
                    BoundaryDecision::Unresolved,
                )
            }
        } else if metadata_string(metadata, "policy").is_some()
            || metadata_string(metadata, "boundary_kind").as_deref() == Some("SOFT_POLICY")
        {
            (
                BoundaryKind::SoftPolicy,
                "ADVISORY".into(),
                BoundaryDecision::DoesNotInterrupt,
            )
        } else {
            continue;
        };
        if !seen.insert((edge.relationship_id.clone(), kind)) {
            continue;
        }
        evaluations.push(BoundaryEvaluation {
            kind,
            affected_resource_ids: vec![edge.from_resource_id.clone(), edge.to_resource_id.clone()],
            affected_relationship_ids: vec![edge.relationship_id.clone()],
            enforcement,
            interrupted_phase: phase,
            decision,
            evidence_ids: edge.evidence_ids.clone(),
        });
    }
    evaluations.sort_by(|a, b| {
        a.affected_relationship_ids
            .cmp(&b.affected_relationship_ids)
            .then(a.kind.cmp(&b.kind))
    });
    evaluations
}

fn approval_boundary(
    metadata: Option<&serde_json::Value>,
    phase: Option<PathPhase>,
) -> (BoundaryKind, String, BoundaryDecision) {
    let technically_required = metadata_bool(metadata, "approval_required")
        .or_else(|| metadata_bool(metadata, "approval_enforced"))
        .or_else(|| {
            (metadata_string(metadata, "enforcement").as_deref() == Some("TECHNICAL"))
                .then_some(true)
        })
        .unwrap_or(false);
    let cannot_self_approve = metadata_bool(metadata, "cannot_self_approve")
        .or_else(|| metadata_bool(metadata, "actor_self_approval").map(|value| !value))
        .unwrap_or(false);
    let bypass = metadata_bool(metadata, "bypass_possible")
        .or_else(|| {
            (metadata_string(metadata, "bypass_state").as_deref()
                == Some("NONE_WITHIN_SUPPORTED_GRAPH"))
            .then_some(false)
        })
        .unwrap_or(true);
    let runtime_disabled = metadata_bool(metadata, "runtime_disables_approval").unwrap_or(false)
        || metadata_string(metadata, "runtime_gate_state").as_deref() == Some("DISABLED")
        || metadata_string(metadata, "enforcement").as_deref() == Some("DISABLED");
    let decision = if technically_required && cannot_self_approve && !bypass && !runtime_disabled {
        BoundaryDecision::Interrupts
    } else {
        BoundaryDecision::Unresolved
    };
    let _ = phase;
    (BoundaryKind::MandatoryApproval, "UNKNOWN".into(), decision)
}

pub fn segment_is_active(disposition: SegmentDisposition) -> bool {
    disposition == SegmentDisposition::Active
}
