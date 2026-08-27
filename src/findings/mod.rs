//! Provider-neutral, deterministic Finding generation.
//!
//! The Finding engine consumes only the normalized graph, current-scan
//! analysis, and current-scan Evidence. It does not perform discovery,
//! provider calls, filesystem reads, or remediation.

mod confidence;
pub mod diagnostics;
mod engine;
mod model;

pub use confidence::{freshness_confidence, EdgeConfidence};
pub use diagnostics::{ConfidenceNote, ProviderDiagnostic, ScanDiagnostics, SuppressedReason};
pub use engine::{eligibility_diagnostics, generate, generate_with_scan_status};
pub use model::{
    Confidence, Finding, FindingClass, FindingGenerationStatus, FindingLimits, FindingReason,
    FindingResult, FindingStatus, ReasonCode, Remediation, Severity, FINDING_VERSION,
};
