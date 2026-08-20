//! Resource construction and canonical identity.

use pico::domain::{DomainError, Resource};

#[test]
fn same_canonical_key_means_same_entity_with_distinct_ids() {
    let a = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode")
        .expect("valid resource");
    let b = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode")
        .expect("valid resource");
    assert_eq!(a.canonical_key, b.canonical_key);
    assert_eq!(a.kind, b.kind);
    assert_eq!(a.provider, b.provider);
    assert_eq!(a.name, b.name);
    assert_ne!(a.id, b.id);
}

#[test]
fn id_has_res_prefix() {
    let r = Resource::new("shell:bash", "shell", "local", "Bash").expect("valid resource");
    assert!(r.id.starts_with("res_"));
}

#[test]
fn new_resource_records_observation_times() {
    let r = Resource::new("shell:bash", "shell", "local", "Bash").expect("valid resource");
    assert!(r.first_observed_at.timestamp() > 0);
    assert_eq!(r.first_observed_at, r.last_observed_at);
    assert_eq!(r.metadata, None);
}

#[test]
fn empty_fields_are_rejected() {
    assert!(Resource::new("", "agent", "opencode", "OpenCode").is_err());
    assert!(Resource::new("agent:opencode:default", "", "opencode", "OpenCode").is_err());
    assert!(Resource::new("agent:opencode:default", "agent", "", "OpenCode").is_err());
    assert!(Resource::new("agent:opencode:default", "agent", "opencode", "").is_err());
    assert!(Resource::new("   ", "agent", "opencode", "OpenCode").is_err());
    assert!(Resource::new("agent:opencode:default", "  ", "opencode", "OpenCode").is_err());
    assert!(matches!(
        Resource::new("", "agent", "opencode", "OpenCode").expect_err("must be invalid"),
        DomainError::InvalidValue(_)
    ));
}
