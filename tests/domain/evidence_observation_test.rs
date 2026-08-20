//! Evidence and Observation construction, empty-field rejection, and
//! evidence class/sensitivity round-trips.

use pico::domain::{DomainError, Evidence, EvidenceClass, Observation, Sensitivity};
use std::str::FromStr;

#[test]
fn evidence_valid_construction() {
    let ev = Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "opencode_config",
        "~/.config/opencode/opencode.json",
        "permission.bash",
        "allow",
        Sensitivity::Internal,
    )
    .expect("valid evidence");
    assert_eq!(ev.scan_id, "scan_1");
    assert_eq!(ev.class, EvidenceClass::Direct);
    assert_eq!(ev.source_type, "opencode_config");
    assert_eq!(ev.source_locator, "~/.config/opencode/opencode.json");
    assert_eq!(ev.subject, "permission.bash");
    assert_eq!(ev.observation, "allow");
    assert_eq!(ev.sensitivity, Sensitivity::Internal);
    assert!(ev.id.starts_with("ev_"));
    assert!(ev.captured_at.timestamp() > 0);
    assert_eq!(ev.freshness, None);
    assert_eq!(ev.metadata, None);
}

#[test]
fn evidence_empty_fields_are_rejected() {
    assert!(Evidence::new(
        "",
        EvidenceClass::Direct,
        "src",
        "loc",
        "subj",
        "obs",
        Sensitivity::Public
    )
    .is_err());
    assert!(Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "",
        "loc",
        "subj",
        "obs",
        Sensitivity::Public
    )
    .is_err());
    assert!(Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "src",
        "",
        "subj",
        "obs",
        Sensitivity::Public
    )
    .is_err());
    assert!(Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "src",
        "loc",
        "",
        "obs",
        Sensitivity::Public
    )
    .is_err());
    assert!(Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "src",
        "loc",
        "subj",
        "",
        Sensitivity::Public
    )
    .is_err());
    assert!(Evidence::new(
        "scan_1",
        EvidenceClass::Direct,
        "  ",
        "loc",
        "subj",
        "obs",
        Sensitivity::Public
    )
    .is_err());
    assert!(matches!(
        Evidence::new(
            "",
            EvidenceClass::Direct,
            "src",
            "loc",
            "subj",
            "obs",
            Sensitivity::Public
        )
        .expect_err("must be invalid"),
        DomainError::InvalidValue(_)
    ));
}

#[test]
fn evidence_class_round_trips() {
    for class in [
        EvidenceClass::Direct,
        EvidenceClass::Declared,
        EvidenceClass::Derived,
        EvidenceClass::Inferred,
    ] {
        assert_eq!(class.as_str(), class.to_string());
        assert_eq!(
            EvidenceClass::from_str(class.as_str()).expect("valid class"),
            class
        );
    }
    assert!(EvidenceClass::from_str("GUESSED").is_err());
}

#[test]
fn sensitivity_round_trips() {
    for s in [
        Sensitivity::Public,
        Sensitivity::Internal,
        Sensitivity::SensitiveMetadata,
        Sensitivity::Secret,
    ] {
        assert_eq!(
            Sensitivity::from_str(s.as_str()).expect("valid sensitivity"),
            s
        );
    }
    assert!(Sensitivity::from_str("TOP_SECRET").is_err());
}

#[test]
fn observation_valid_construction() {
    let obs = Observation::new("scan_1", "resource", "res_1", "present", "opencode_adapter")
        .expect("valid observation");
    assert_eq!(obs.scan_id, "scan_1");
    assert_eq!(obs.subject_type, "resource");
    assert_eq!(obs.subject_id, "res_1");
    assert_eq!(obs.observation_type, "present");
    assert_eq!(obs.source, "opencode_adapter");
    assert!(obs.id.starts_with("obs_"));
    assert!(obs.observed_at.timestamp() > 0);
    assert_eq!(obs.metadata, None);
}

#[test]
fn observation_empty_fields_are_rejected() {
    assert!(Observation::new("", "resource", "res_1", "present", "src").is_err());
    assert!(Observation::new("scan_1", "", "res_1", "present", "src").is_err());
    assert!(Observation::new("scan_1", "resource", "", "present", "src").is_err());
    assert!(Observation::new("scan_1", "resource", "res_1", "", "src").is_err());
    assert!(Observation::new("scan_1", "resource", "res_1", "present", "").is_err());
    assert!(Observation::new("scan_1", "resource", "  ", "present", "src").is_err());
    assert!(matches!(
        Observation::new("", "resource", "res_1", "present", "src").expect_err("must be invalid"),
        DomainError::InvalidValue(_)
    ));
}
