//! Relationship endpoint requirements and state round-trips.

use pico::domain::{DomainError, Relationship, RelationshipState};
use std::str::FromStr;

const FROM: &str = "res_agent";
const TO: &str = "res_shell";

#[test]
fn valid_construction_sets_fields() {
    let rel = Relationship::new(
        "agent:opencode:default|can_execute|shell:bash",
        FROM,
        TO,
        "can_execute",
        RelationshipState::Confirmed,
    )
    .expect("valid relationship");
    assert_eq!(
        rel.canonical_key,
        "agent:opencode:default|can_execute|shell:bash"
    );
    assert_eq!(rel.from_resource_id, FROM);
    assert_eq!(rel.to_resource_id, TO);
    assert_eq!(rel.kind, "can_execute");
    assert_eq!(rel.state, RelationshipState::Confirmed);
    assert!(rel.id.starts_with("rel_"));
    assert!(rel.first_observed_at.timestamp() > 0);
    assert_eq!(rel.first_observed_at, rel.last_observed_at);
    assert_eq!(rel.metadata, None);
}

#[test]
fn self_loop_is_rejected() {
    let err = Relationship::new(
        "agent|agent",
        FROM,
        FROM,
        "can_execute",
        RelationshipState::Confirmed,
    )
    .expect_err("self-loop must be rejected");
    assert!(matches!(err, DomainError::InvalidValue(_)));
}

#[test]
fn empty_endpoints_are_rejected() {
    assert!(Relationship::new("k", "", TO, "can_execute", RelationshipState::Confirmed).is_err());
    assert!(Relationship::new("k", "  ", TO, "can_execute", RelationshipState::Confirmed).is_err());
    assert!(Relationship::new("k", FROM, "", "can_execute", RelationshipState::Confirmed).is_err());
    assert!(
        Relationship::new("k", FROM, "  ", "can_execute", RelationshipState::Confirmed).is_err()
    );
}

#[test]
fn empty_canonical_key_and_kind_are_rejected() {
    assert!(Relationship::new("", FROM, TO, "can_execute", RelationshipState::Confirmed).is_err());
    assert!(
        Relationship::new("   ", FROM, TO, "can_execute", RelationshipState::Confirmed).is_err()
    );
    assert!(Relationship::new("k", FROM, TO, "", RelationshipState::Confirmed).is_err());
    assert!(Relationship::new("k", FROM, TO, "  ", RelationshipState::Confirmed).is_err());
}

#[test]
fn all_states_round_trip() {
    for state in [
        RelationshipState::Confirmed,
        RelationshipState::Derived,
        RelationshipState::Inferred,
        RelationshipState::Unknown,
        RelationshipState::Blocked,
    ] {
        assert_eq!(state.as_str(), state.to_string());
        assert_eq!(
            RelationshipState::from_str(state.as_str()).expect("valid state"),
            state
        );
    }
    assert!(RelationshipState::from_str("MAYBE").is_err());
}

#[test]
fn every_state_is_accepted_in_construction() {
    for state in [
        RelationshipState::Confirmed,
        RelationshipState::Derived,
        RelationshipState::Inferred,
        RelationshipState::Unknown,
        RelationshipState::Blocked,
    ] {
        let rel = Relationship::new("k", FROM, TO, "can_execute", state).expect("valid");
        assert_eq!(rel.state, state);
    }
}
