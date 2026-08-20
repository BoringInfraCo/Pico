//! Scan lifecycle and status/trigger string round-trips.

use pico::domain::{DomainError, Scan, ScanStatus, ScanTrigger};
use pico::shared::PICO_VERSION;
use std::str::FromStr;

#[test]
fn start_creates_running_manual_scan() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    assert_eq!(scan.status, ScanStatus::Running);
    assert_eq!(scan.trigger, ScanTrigger::Manual);
    assert!(scan.started_at.timestamp() > 0);
    assert!(scan.completed_at.is_none());
    assert!(scan.id.starts_with("scan_"));
    assert_eq!(scan.pico_version, PICO_VERSION);
    assert_eq!(scan.scope, None);
    assert_eq!(scan.environment_fingerprint, None);
    assert_eq!(scan.metadata, None);
}

#[test]
fn empty_pico_version_is_rejected() {
    assert!(Scan::start("").is_err());
}

#[test]
fn running_to_complete_is_valid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let done = scan.complete().expect("valid transition");
    assert_eq!(done.status, ScanStatus::Complete);
    assert!(done.completed_at.is_some());
}

#[test]
fn running_to_partial_is_valid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let partial = scan.partial().expect("valid transition");
    assert_eq!(partial.status, ScanStatus::Partial);
    assert!(partial.completed_at.is_some());
}

#[test]
fn running_to_failed_is_valid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let failed = scan.fail().expect("valid transition");
    assert_eq!(failed.status, ScanStatus::Failed);
    assert!(failed.completed_at.is_some());
}

#[test]
fn complete_to_complete_is_invalid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let done = scan.complete().expect("valid transition");
    let err = done.complete().expect_err("must be invalid");
    assert!(matches!(
        err,
        DomainError::InvalidTransition { from, to }
            if from == "COMPLETE" && to == "COMPLETE"
    ));
}

#[test]
fn failed_to_complete_is_invalid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let failed = scan.fail().expect("valid transition");
    let err = failed.complete().expect_err("must be invalid");
    assert!(matches!(
        err,
        DomainError::InvalidTransition { from, to }
            if from == "FAILED" && to == "COMPLETE"
    ));
}

#[test]
fn partial_to_failed_is_invalid() {
    let scan = Scan::start(PICO_VERSION).expect("valid start");
    let partial = scan.partial().expect("valid transition");
    let err = partial.fail().expect_err("must be invalid");
    assert!(matches!(
        err,
        DomainError::InvalidTransition { from, to }
            if from == "PARTIAL" && to == "FAILED"
    ));
}

#[test]
fn status_string_round_trips() {
    for status in [
        ScanStatus::Running,
        ScanStatus::Complete,
        ScanStatus::Partial,
        ScanStatus::Failed,
    ] {
        assert_eq!(status.as_str(), status.to_string());
        assert_eq!(
            ScanStatus::from_str(status.as_str()).expect("valid status"),
            status
        );
    }
    assert!(ScanStatus::from_str("NOPE").is_err());
}

#[test]
fn trigger_string_round_trips() {
    assert_eq!(ScanTrigger::Manual.as_str(), "MANUAL");
    assert_eq!(
        ScanTrigger::from_str(ScanTrigger::Manual.as_str()).expect("valid trigger"),
        ScanTrigger::Manual
    );
    assert!(ScanTrigger::from_str("SCHEDULED").is_err());
}
