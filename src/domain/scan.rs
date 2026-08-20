//! The `Scan` domain type (ARCHITECTURE.md §8).
//!
//! A Scan is a bounded evidence-collection event. It records what Pico
//! inspected and what it learned during one run, and provides the
//! temporal boundary around a coherent environment observation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::DomainError;
use super::ids::new_id;

/// Lifecycle state of a Scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Complete,
    Partial,
    Failed,
}

impl ScanStatus {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Running => "RUNNING",
            ScanStatus::Complete => "COMPLETE",
            ScanStatus::Partial => "PARTIAL",
            ScanStatus::Failed => "FAILED",
        }
    }
}

impl std::str::FromStr for ScanStatus {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RUNNING" => Ok(ScanStatus::Running),
            "COMPLETE" => Ok(ScanStatus::Complete),
            "PARTIAL" => Ok(ScanStatus::Partial),
            "FAILED" => Ok(ScanStatus::Failed),
            other => Err(DomainError::InvalidValue(format!(
                "unknown scan status: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What initiated the Scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTrigger {
    Manual,
}

impl ScanTrigger {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanTrigger::Manual => "MANUAL",
        }
    }
}

impl std::str::FromStr for ScanTrigger {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "MANUAL" => Ok(ScanTrigger::Manual),
            other => Err(DomainError::InvalidValue(format!(
                "unknown scan trigger: {other}"
            ))),
        }
    }
}

/// A bounded evidence-collection event.
///
/// `completed_at`, `scope`, `environment_fingerprint`, and `metadata`
/// may be empty/None when not yet known or not applicable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scan {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub trigger: ScanTrigger,
    pub scope: Option<Value>,
    pub pico_version: String,
    pub environment_fingerprint: Option<String>,
    pub metadata: Option<Value>,
}

impl Scan {
    /// Begin a new Scan in the RUNNING state.
    pub fn start(pico_version: &str) -> Result<Self, DomainError> {
        if pico_version.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "pico_version must not be empty".to_string(),
            ));
        }
        Ok(Scan {
            id: new_id("scan"),
            started_at: Utc::now(),
            completed_at: None,
            status: ScanStatus::Running,
            trigger: ScanTrigger::Manual,
            scope: None,
            pico_version: pico_version.to_string(),
            environment_fingerprint: None,
            metadata: None,
        })
    }

    /// Transition a RUNNING scan to COMPLETE, recording completion time.
    pub fn complete(self) -> Result<Self, DomainError> {
        self.transition(ScanStatus::Complete)
    }

    /// Transition a RUNNING scan to PARTIAL, recording completion time.
    pub fn partial(self) -> Result<Self, DomainError> {
        self.transition(ScanStatus::Partial)
    }

    /// Transition a RUNNING scan to FAILED, recording completion time.
    pub fn fail(self) -> Result<Self, DomainError> {
        self.transition(ScanStatus::Failed)
    }

    fn transition(mut self, to: ScanStatus) -> Result<Self, DomainError> {
        if self.status != ScanStatus::Running {
            return Err(DomainError::InvalidTransition {
                from: self.status.as_str().to_string(),
                to: to.as_str().to_string(),
            });
        }
        self.status = to;
        self.completed_at = Some(Utc::now());
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn start_creates_running_scan() {
        let scan = Scan::start("0.1.0").expect("valid start");
        assert_eq!(scan.status, ScanStatus::Running);
        assert_eq!(scan.trigger, ScanTrigger::Manual);
        assert!(scan.started_at.timestamp() > 0);
        assert!(scan.completed_at.is_none());
        assert!(scan.id.starts_with("scan_"));
    }

    #[test]
    fn empty_pico_version_is_rejected() {
        assert!(Scan::start("").is_err());
        assert!(Scan::start("   ").is_err());
    }

    #[test]
    fn running_to_complete_is_valid() {
        let scan = Scan::start("0.1.0").expect("valid start");
        let done = scan.complete().expect("valid transition");
        assert_eq!(done.status, ScanStatus::Complete);
        assert!(done.completed_at.is_some());
    }

    #[test]
    fn running_to_failed_is_valid() {
        let scan = Scan::start("0.1.0").expect("valid start");
        let failed = scan.fail().expect("valid transition");
        assert_eq!(failed.status, ScanStatus::Failed);
        assert!(failed.completed_at.is_some());
    }

    #[test]
    fn running_to_partial_is_valid() {
        let scan = Scan::start("0.1.0").expect("valid start");
        let partial = scan.partial().expect("valid transition");
        assert_eq!(partial.status, ScanStatus::Partial);
        assert!(partial.completed_at.is_some());
    }

    #[test]
    fn complete_to_complete_is_invalid() {
        let scan = Scan::start("0.1.0").expect("valid start");
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
        let scan = Scan::start("0.1.0").expect("valid start");
        let failed = scan.fail().expect("valid transition");
        let err = failed.complete().expect_err("must be invalid");
        assert!(matches!(
            err,
            DomainError::InvalidTransition { from, to }
                if from == "FAILED" && to == "COMPLETE"
        ));
    }

    #[test]
    fn status_round_trips() {
        for status in [
            ScanStatus::Running,
            ScanStatus::Complete,
            ScanStatus::Partial,
            ScanStatus::Failed,
        ] {
            assert_eq!(ScanStatus::from_str(status.as_str()).unwrap(), status);
        }
        assert!(ScanStatus::from_str("NOPE").is_err());
    }

    #[test]
    fn trigger_round_trips() {
        assert_eq!(
            ScanTrigger::from_str(ScanTrigger::Manual.as_str()).unwrap(),
            ScanTrigger::Manual
        );
        assert!(ScanTrigger::from_str("SCHEDULED").is_err());
    }
}
