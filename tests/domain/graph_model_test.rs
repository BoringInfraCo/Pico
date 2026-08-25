//! Provider-neutral graph model invariants.
//!
//! These tests intentionally construct only normalized domain objects.  They
//! do not exercise an adapter or make a network request; projection tests can
//! layer scan/persistence fixtures on top of this contract.

use pico::domain::{Relationship, RelationshipState, Resource};
use pico::graph::model::{EdgeUsability, GraphEdge, GraphNode, SecurityRole};

fn resource(key: &str, kind: &str, provider: &str, name: &str) -> Resource {
    Resource::new(key, kind, provider, name).expect("valid fixture resource")
}

#[test]
fn generic_resource_kinds_map_to_provider_neutral_roles() {
    let cases = [
        ("external_source", SecurityRole::Source),
        ("agent", SecurityRole::Actor),
        ("shell", SecurityRole::Capability),
        ("mcp_tool", SecurityRole::Capability),
        ("credential", SecurityRole::Authority),
        ("approval_gate", SecurityRole::Boundary),
        ("sandbox", SecurityRole::Boundary),
    ];

    for (kind, role) in cases {
        let node = GraphNode::from_resource(&resource(
            &format!("{kind}:fixture"),
            kind,
            "fixture",
            "fixture",
        ));
        assert_eq!(node.roles, vec![role], "role for {kind}");
    }
}

#[test]
fn consequential_sink_is_an_additive_generic_role() {
    let mut worker = resource("worker:fixture", "worker", "cloudflare", "Worker");
    worker.metadata = Some(serde_json::json!({
        "consequential_sink": true,
        "environment": "UNKNOWN",
    }));
    let node = GraphNode::from_resource(&worker);
    assert_eq!(node.roles, vec![SecurityRole::Sink]);
    assert!(!node.roles.iter().any(|role| role.as_str() == "PRODUCTION"));
}

#[test]
fn edge_usability_preserves_relationship_state_semantics() {
    let expected = [
        (RelationshipState::Confirmed, EdgeUsability::Traversable),
        (RelationshipState::Derived, EdgeUsability::Traversable),
        (
            RelationshipState::Inferred,
            EdgeUsability::TraversableWithPenalty,
        ),
        (
            RelationshipState::Unknown,
            EdgeUsability::NonTraversableUnknown,
        ),
        (
            RelationshipState::Blocked,
            EdgeUsability::NonTraversableBlocked,
        ),
    ];

    for (state, usability) in expected {
        assert_eq!(EdgeUsability::from_state(state), usability);
        assert_eq!(
            EdgeUsability::from_state(state).is_traversable(),
            usability.is_traversable()
        );
    }
}

#[test]
fn graph_edge_preserves_direction_and_stable_identity() {
    let relationship = Relationship::new(
        "source:fixture|can_call|actor:fixture",
        "res_source",
        "res_actor",
        "can_call",
        RelationshipState::Derived,
    )
    .expect("valid relationship");
    let edge = GraphEdge::from_relationship(&relationship);

    assert_eq!(edge.relationship_id, relationship.id);
    assert_eq!(edge.canonical_key, "source:fixture|can_call|actor:fixture");
    assert_eq!(edge.from_resource_id, "res_source");
    assert_eq!(edge.to_resource_id, "res_actor");
    assert_eq!(edge.kind, "can_call");
    assert_eq!(edge.state, RelationshipState::Derived);
    assert_eq!(edge.usability, EdgeUsability::Traversable);
}
