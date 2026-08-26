//! The `Evidence` domain type (ARCHITECTURE.md §7).
//!
//! Evidence records why Pico believes a security claim. It is
//! append-oriented: old evidence is never rewritten, only superseded by
//! newer evidence from later scans.
//!
//! Raw secret values must never appear in Evidence.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::DomainError;
use super::ids::new_id;

/// Evidence class (ARCHITECTURE.md §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceClass {
    Direct,
    Declared,
    Derived,
    Inferred,
}

impl EvidenceClass {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceClass::Direct => "DIRECT",
            EvidenceClass::Declared => "DECLARED",
            EvidenceClass::Derived => "DERIVED",
            EvidenceClass::Inferred => "INFERRED",
        }
    }
}

impl std::str::FromStr for EvidenceClass {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "DIRECT" => Ok(EvidenceClass::Direct),
            "DECLARED" => Ok(EvidenceClass::Declared),
            "DERIVED" => Ok(EvidenceClass::Derived),
            "INFERRED" => Ok(EvidenceClass::Inferred),
            other => Err(DomainError::InvalidValue(format!(
                "unknown evidence class: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sensitivity classification of Evidence (ARCHITECTURE.md §7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensitivity {
    Public,
    Internal,
    SensitiveMetadata,
    Secret,
}

impl Sensitivity {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Public => "PUBLIC",
            Sensitivity::Internal => "INTERNAL",
            Sensitivity::SensitiveMetadata => "SENSITIVE_METADATA",
            Sensitivity::Secret => "SECRET",
        }
    }
}

impl std::str::FromStr for Sensitivity {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PUBLIC" => Ok(Sensitivity::Public),
            "INTERNAL" => Ok(Sensitivity::Internal),
            "SENSITIVE_METADATA" => Ok(Sensitivity::SensitiveMetadata),
            "SECRET" => Ok(Sensitivity::Secret),
            other => Err(DomainError::InvalidValue(format!(
                "unknown sensitivity: {other}"
            ))),
        }
    }
}

/// Freshness classification of Evidence (ARCHITECTURE.md §7.5 freshness model).
///
/// The age of `Evidence::captured_at` relative to a reference scan time maps to
/// one of these states. The window bounds below were confirmed with the support
/// note as the default freshness classification thresholds for Sprint 002.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Freshness {
    Fresh,
    Aging,
    Stale,
    Unknown,
}

impl Freshness {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            Freshness::Fresh => "FRESH",
            Freshness::Aging => "AGING",
            Freshness::Stale => "STALE",
            Freshness::Unknown => "UNKNOWN",
        }
    }
}

impl std::str::FromStr for Freshness {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FRESH" => Ok(Freshness::Fresh),
            "AGING" => Ok(Freshness::Aging),
            "STALE" => Ok(Freshness::Stale),
            "UNKNOWN" => Ok(Freshness::Unknown),
            other => Err(DomainError::InvalidValue(format!(
                "unknown freshness: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for Freshness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evidence captured within this many seconds of the reference time is FRESH.
/// (ARCHITECTURE.md §7.5; threshold confirmed via the Sprint 002 support note.)
pub const FRESH_WINDOW_SECS: i64 = 3600;

/// Evidence captured within this many seconds of the reference time is AGING
/// (but past the FRESH window). (ARCHITECTURE.md §7.5; support note threshold.)
pub const AGING_WINDOW_SECS: i64 = 86400;

/// Returns true only when `loc` is non-empty and does not exactly equal any
/// value in `secrets`. Adapter conformance checks use this to guarantee that no
/// raw secret value is ever persisted as provenance (`source_locator`).
pub fn source_locator_is_safe(loc: &str, secrets: &[&str]) -> bool {
    if loc.trim().is_empty() {
        return false;
    }
    !secrets.contains(&loc)
}

/// A record of why Pico believes a security claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub scan_id: String,
    pub class: EvidenceClass,
    pub source_type: String,
    pub source_locator: String,
    pub subject: String,
    pub observation: String,
    pub captured_at: DateTime<Utc>,
    pub freshness: Option<String>,
    pub sensitivity: Sensitivity,
    pub metadata: Option<Value>,
}

impl Evidence {
    /// Construct a new Evidence record, validating required fields.
    pub fn new(
        scan_id: &str,
        class: EvidenceClass,
        source_type: &str,
        source_locator: &str,
        subject: &str,
        observation: &str,
        sensitivity: Sensitivity,
    ) -> Result<Self, DomainError> {
        for (label, value) in [
            ("scan_id", scan_id),
            ("source_type", source_type),
            ("source_locator", source_locator),
            ("subject", subject),
            ("observation", observation),
        ] {
            if value.trim().is_empty() {
                return Err(DomainError::InvalidValue(format!(
                    "{label} must not be empty"
                )));
            }
        }
        Ok(Evidence {
            id: new_id("ev"),
            scan_id: scan_id.to_string(),
            class,
            source_type: source_type.to_string(),
            source_locator: source_locator.to_string(),
            subject: subject.to_string(),
            observation: observation.to_string(),
            captured_at: Utc::now(),
            freshness: None,
            sensitivity,
            metadata: None,
        })
    }

    /// Classify the freshness of this evidence relative to `reference`.
    ///
    /// Age is the signed duration from `captured_at` to `reference`. A negative
    /// age (reference before capture) is `Unknown`. Otherwise the age is
    /// compared against [`FRESH_WINDOW_SECS`] and [`AGING_WINDOW_SECS`]. This
    /// does not read or mutate the stored `freshness` field.
    pub fn freshness_state(&self, reference: DateTime<Utc>) -> Freshness {
        let age_secs = reference
            .signed_duration_since(self.captured_at)
            .num_seconds();
        if age_secs < 0 {
            Freshness::Unknown
        } else if age_secs <= FRESH_WINDOW_SECS {
            Freshness::Fresh
        } else if age_secs <= AGING_WINDOW_SECS {
            Freshness::Aging
        } else {
            Freshness::Stale
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn new_evidence_is_valid() {
        let ev = Evidence::new(
            "scan_1",
            EvidenceClass::Direct,
            "opencode_config",
            "~/.config/opencode/opencode.json",
            "permission.bash",
            "allow",
            Sensitivity::Internal,
        )
        .unwrap();
        assert_eq!(ev.scan_id, "scan_1");
        assert_eq!(ev.class, EvidenceClass::Direct);
        assert_eq!(ev.sensitivity, Sensitivity::Internal);
        assert!(ev.id.starts_with("ev_"));
    }

    #[test]
    fn empty_fields_are_rejected() {
        assert!(Evidence::new(
            "",
            EvidenceClass::Direct,
            "src",
            "loc",
            "subj",
            "obs",
            Sensitivity::Internal
        )
        .is_err());
        assert!(Evidence::new(
            "scan_1",
            EvidenceClass::Direct,
            "src",
            "",
            "subj",
            "obs",
            Sensitivity::Internal
        )
        .is_err());
        assert!(Evidence::new(
            "scan_1",
            EvidenceClass::Direct,
            "src",
            "loc",
            "",
            "obs",
            Sensitivity::Internal
        )
        .is_err());
    }

    #[test]
    fn class_round_trips() {
        for class in [
            EvidenceClass::Direct,
            EvidenceClass::Declared,
            EvidenceClass::Derived,
            EvidenceClass::Inferred,
        ] {
            assert_eq!(EvidenceClass::from_str(class.as_str()).unwrap(), class);
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
            assert_eq!(Sensitivity::from_str(s.as_str()).unwrap(), s);
        }
        assert!(Sensitivity::from_str("TOP_SECRET").is_err());
    }

    #[test]
    fn freshness_round_trips() {
        for f in [
            Freshness::Fresh,
            Freshness::Aging,
            Freshness::Stale,
            Freshness::Unknown,
        ] {
            assert_eq!(Freshness::from_str(f.as_str()).unwrap(), f);
        }
        assert!(Freshness::from_str("REALLY_FRESH").is_err());
    }

    #[test]
    fn evidence_freshness_classification() {
        let base = Utc::now();
        let mut ev = Evidence::new(
            "scan_1",
            EvidenceClass::Direct,
            "opencode_config",
            "~/.config/opencode/opencode.json",
            "permission.bash",
            "allow",
            Sensitivity::Internal,
        )
        .unwrap();
        ev.captured_at = base;

        // Age zero and up to the fresh window => Fresh.
        assert_eq!(ev.freshness_state(base), Freshness::Fresh);
        assert_eq!(
            ev.freshness_state(base + chrono::Duration::seconds(FRESH_WINDOW_SECS)),
            Freshness::Fresh
        );

        // Just past the fresh window => Aging.
        assert_eq!(
            ev.freshness_state(base + chrono::Duration::seconds(FRESH_WINDOW_SECS + 1)),
            Freshness::Aging
        );
        // At the aging boundary => Aging.
        assert_eq!(
            ev.freshness_state(base + chrono::Duration::seconds(AGING_WINDOW_SECS)),
            Freshness::Aging
        );

        // Past the aging window => Stale.
        assert_eq!(
            ev.freshness_state(base + chrono::Duration::seconds(AGING_WINDOW_SECS + 1)),
            Freshness::Stale
        );

        // Reference before capture => Unknown.
        assert_eq!(
            ev.freshness_state(base - chrono::Duration::seconds(10)),
            Freshness::Unknown
        );
    }
}
