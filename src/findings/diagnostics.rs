//! Structured, machine-readable scan diagnostics.
//!
//! These types give CLI/MCP an honest, per-provider and per-finding
//! explanation for *why* a scan produced fewer Findings than its candidate set
//! suggested, or *why* a Finding's confidence was reduced. They are a
//! structured companion to the human-readable `FindingResult::diagnostics`
//! projection and never replace it.
//!
//! All problem text stored here must already be sanitized by the discovery
//! layer; this module only carries provider-supplied messages forward.

use serde::{Deserialize, Serialize};

/// Reachability/probelm status for a single provider in one scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDiagnostic {
    /// Provider name (e.g. `opencode`, `cloudflare`).
    pub name: String,
    /// `true` when the provider reported no problems and was fully reachable.
    pub reachable: bool,
    /// Sanitized provider-supplied problem messages (never raw secret values).
    pub problems: Vec<String>,
}

/// An honest reason a candidate (Active) `AttackPath` did NOT become a Finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedReason {
    /// Fingerprint of the suppressed candidate `AttackPath`.
    pub fingerprint: String,
    /// Human-readable but deterministic reason for suppression.
    pub reason: String,
}

/// A per-finding note explaining which security-critical edges reduced
/// confidence, by how much, and the edge's evidence freshness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceNote {
    /// Fingerprint of the Finding whose confidence was reduced.
    pub fingerprint: String,
    /// `(edge_key, freshness, penalty)` tuples for each edge that reduced confidence.
    pub edges: Vec<(String, String, f64)>,
}

/// Structured diagnostics for one scan, surfaced to CLI/MCP alongside the
/// human-readable `FindingResult::diagnostics` projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanDiagnostics {
    /// Per-provider reachability and sanitized problem list.
    pub provider_statuses: Vec<ProviderDiagnostic>,
    /// `"COMPLETE"` or `"PARTIAL"` — the lifecycle status used for generation.
    pub scan_status: String,
    /// When `scan_status` is `"PARTIAL"`, the provider that caused it (if known).
    pub partial_reason: Option<String>,
    /// Candidate AttackPaths that were Active but did not become Findings.
    pub suppressed: Vec<SuppressedReason>,
    /// Findings whose confidence was reduced by incomplete edge evidence.
    pub reduced_confidence: Vec<ConfidenceNote>,
}

impl ScanDiagnostics {
    /// `true` when no provider problems, no suppression, and no confidence
    /// reduction were recorded. Used by tests and the golden baseline.
    pub fn is_clean(&self) -> bool {
        self.provider_statuses.iter().all(|p| p.reachable)
            && self.partial_reason.is_none()
            && self.suppressed.is_empty()
            && self.reduced_confidence.is_empty()
    }
}
