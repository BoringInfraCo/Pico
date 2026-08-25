//! Provider-neutral deterministic security analysis over a validated graph.
//!
//! This module consumes only normalized graph state. It does not inspect
//! adapters, raw environment variables, provider transports, or SQLite.

pub mod attack_path;
pub mod authority;
pub mod boundary;
pub mod influence;
pub mod model;

pub use attack_path::{analyze, analyze_with_scan_status};
pub use model::{
    AnalysisLimits, AnalysisResult, AnalysisStatus, AttackPath, AuthorityPath, AuthorityResolution,
    BoundaryDecision, BoundaryEvaluation, BoundaryKind, CandidateDisposition, CapabilityClass,
    InfluencePath, InfluenceStrength, PathEdgeRef, PathPhase, SegmentDisposition, SinkImpact,
    SourceTrust, TraversalDirection, ANALYSIS_VERSION,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::domain::{Evidence, EvidenceClass, RelationshipState, ScanStatus, Sensitivity};
    use crate::graph::{
        EdgeUsability, GraphEdge, GraphEvidenceIndex, GraphNode, SecurityGraph, SecurityRole,
    };

    use super::*;

    fn node(
        id: &str,
        key: &str,
        roles: Vec<SecurityRole>,
        metadata: Option<serde_json::Value>,
    ) -> GraphNode {
        GraphNode {
            resource_id: id.into(),
            canonical_key: key.into(),
            kind: "fixture".into(),
            provider: "fixture".into(),
            name: key.into(),
            safe_metadata: metadata,
            roles,
        }
    }

    fn edge(
        id: &str,
        key: &str,
        from: &str,
        to: &str,
        kind: &str,
        state: RelationshipState,
    ) -> GraphEdge {
        GraphEdge {
            relationship_id: id.into(),
            canonical_key: key.into(),
            from_resource_id: from.into(),
            to_resource_id: to.into(),
            kind: kind.into(),
            state,
            usability: EdgeUsability::from_state(state),
            safe_metadata: None,
            evidence_ids: vec![format!("ev-{id}")],
        }
    }

    fn golden_graph(last_state: RelationshipState) -> SecurityGraph {
        let nodes = vec![
            node(
                "source",
                "source:github:issue",
                vec![SecurityRole::Source],
                Some(
                    serde_json::json!({"trust":"PUBLIC_EXTERNAL", "influence_strength":"AGENT_RETRIEVABLE"}),
                ),
            ),
            node(
                "tool",
                "mcp:github:tool",
                vec![SecurityRole::Capability],
                None,
            ),
            node("actor", "agent:opencode", vec![SecurityRole::Actor], None),
            node(
                "bash",
                "shell:bash",
                vec![SecurityRole::Capability],
                Some(serde_json::json!({"capability":"EXECUTE"})),
            ),
            node(
                "credential",
                "credential:cloudflare:fingerprint",
                vec![SecurityRole::Authority],
                None,
            ),
            node(
                "worker",
                "cloudflare:worker:account:tag",
                vec![SecurityRole::Sink],
                Some(serde_json::json!({"consequential_sink":true})),
            ),
        ];
        let mut edges = vec![
            edge(
                "call",
                "mcp:github:tool|can_call|agent:opencode",
                "actor",
                "tool",
                "can_call",
                RelationshipState::Derived,
            ),
            edge(
                "retrieve",
                "mcp:github:tool|can_retrieve|source:github:issue",
                "tool",
                "source",
                "can_retrieve",
                RelationshipState::Derived,
            ),
            edge(
                "execute",
                "agent:opencode|can_execute|shell:bash",
                "actor",
                "bash",
                "can_execute",
                RelationshipState::Derived,
            ),
            edge(
                "access",
                "shell:bash|can_access|credential:cloudflare:fingerprint",
                "bash",
                "credential",
                "can_access",
                RelationshipState::Derived,
            ),
            edge(
                "mutate",
                "credential:cloudflare:fingerprint|can_mutate|cloudflare:worker:account:tag",
                "credential",
                "worker",
                "can_mutate",
                last_state,
            ),
        ];
        edges[4].safe_metadata = Some(serde_json::json!({
            "authority_resolution": "EXACT",
            "account_scope_state": "IN_SCOPE"
        }));
        let mut outgoing = BTreeMap::new();
        let mut incoming = BTreeMap::new();
        for item in &edges {
            outgoing
                .entry(item.from_resource_id.clone())
                .or_insert_with(Vec::new)
                .push(item.relationship_id.clone());
            incoming
                .entry(item.to_resource_id.clone())
                .or_insert_with(Vec::new)
                .push(item.relationship_id.clone());
        }
        let mut evidence = GraphEvidenceIndex::default();
        for item in &edges {
            let record = Evidence::new(
                "scan",
                EvidenceClass::Derived,
                "fixture",
                "fixture",
                &item.canonical_key,
                "observed",
                Sensitivity::Internal,
            )
            .unwrap();
            let mut record = record;
            record.id = format!("ev-{}", item.relationship_id);
            evidence.by_evidence_id.insert(record.id.clone(), record);
            evidence
                .by_relationship_id
                .insert(item.relationship_id.clone(), item.evidence_ids.clone());
        }
        SecurityGraph {
            scan_id: "scan".into(),
            snapshot_version: 1,
            nodes,
            edges,
            outgoing_index: outgoing,
            incoming_index: incoming,
            evidence_index: evidence,
        }
    }

    #[test]
    fn projects_active_golden_path_with_stable_canonical_fingerprint() {
        let graph = golden_graph(RelationshipState::Derived);
        let result = analyze(&graph, &AnalysisLimits::default());
        assert_eq!(result.candidate_disposition, CandidateDisposition::Active);
        assert_eq!(result.influence_paths.len(), 1);
        assert_eq!(result.authority_paths.len(), 1);
        assert_eq!(result.attack_paths.len(), 1);
        assert_eq!(
            result.attack_paths[0].disposition,
            CandidateDisposition::Active
        );
        assert!(result.attack_paths[0].fingerprint.starts_with("sha256:"));
        assert!(
            result.attack_paths[0].fingerprint.contains("sha256:")
                || !result.attack_paths[0].fingerprint.is_empty()
        );
    }

    #[test]
    fn blocked_authority_is_retained_as_blocked_candidate() {
        let graph = golden_graph(RelationshipState::Blocked);
        let result = analyze(&graph, &AnalysisLimits::default());
        assert_eq!(result.candidate_disposition, CandidateDisposition::Blocked);
        assert_eq!(result.attack_paths.len(), 1);
        assert_eq!(
            result.attack_paths[0].disposition,
            CandidateDisposition::Blocked
        );
    }

    #[test]
    fn unknown_authority_is_unresolved_and_not_persistable() {
        let graph = golden_graph(RelationshipState::Unknown);
        let result = analyze(&graph, &AnalysisLimits::default());
        assert_eq!(
            result.candidate_disposition,
            CandidateDisposition::Unresolved
        );
        assert!(result.attack_paths.is_empty());
    }

    #[test]
    fn limits_are_explicit_and_distinguishable() {
        let graph = golden_graph(RelationshipState::Derived);
        let limits = AnalysisLimits {
            maximum_depth: 1,
            ..AnalysisLimits::default()
        };
        let result = analyze(&graph, &limits);
        assert_eq!(result.status, AnalysisStatus::Limited);
        assert!(result.attack_paths.is_empty());
    }

    #[test]
    fn partial_scan_downgrades_positive_candidate_to_unresolved() {
        let graph = golden_graph(RelationshipState::Derived);
        let result =
            analyze_with_scan_status(&graph, &AnalysisLimits::default(), ScanStatus::Partial);
        assert_eq!(result.status, AnalysisStatus::Complete);
        assert_eq!(
            result.candidate_disposition,
            CandidateDisposition::Unresolved
        );
        assert_eq!(result.unresolved_candidate_count, 1);
        assert!(result.attack_paths.is_empty());
    }
}
