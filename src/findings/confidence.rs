//! Freshness-aware confidence for security-critical edges (SPRINT-014 R3/R4).
//!
//! Pure, deterministic helpers that translate an edge's evidence freshness and
//! the originating scan's completion status into a penalty and a confirmability
//! gate. The golden path (FRESH evidence + COMPLETE scan) leaves `penalty` at
//! `0.0` and `may_be_confirmed` at `true`, so no existing behavior changes.

use crate::domain::{evidence::Freshness, ScanStatus};

/// The confidence consequence of one security-critical edge's provenance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EdgeConfidence {
    /// Additive penalty applied to the path confidence score (0.0 = none).
    pub penalty: f64,
    /// Whether this edge may be treated as CONFIRMED for Finding eligibility.
    pub may_be_confirmed: bool,
}

/// Classify an edge's confidence consequence from its freshest supporting
/// evidence and the scan completion status.
///
/// Rules (R3/R4):
/// * `Fresh` + `Complete`  => penalty `0.0`, `may_be_confirmed` `true`.
/// * `Aging`               => penalty `0.1`, `may_be_confirmed` `true`.
/// * `Stale`               => penalty `0.3`, `may_be_confirmed` `false`.
/// * `Unknown`             => penalty `0.1`, `may_be_confirmed` `false`.
/// * `Partial` scan status => never upgrades (`may_be_confirmed` `false`) and a
///   penalty of at least `0.1`.
pub fn freshness_confidence(edge_freshness: Freshness, scan_status: ScanStatus) -> EdgeConfidence {
    let base = match edge_freshness {
        Freshness::Fresh => (0.0, true),
        Freshness::Aging => (0.1, true),
        Freshness::Stale => (0.3, false),
        Freshness::Unknown => (0.1, false),
    };
    let partial = scan_status == ScanStatus::Partial;
    let may_be_confirmed = base.1 && !partial;
    let penalty = if partial {
        f64::max(base.0, 0.1)
    } else {
        base.0
    };
    EdgeConfidence {
        penalty,
        may_be_confirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_complete_has_no_penalty_and_confirms() {
        let c = freshness_confidence(Freshness::Fresh, ScanStatus::Complete);
        assert_eq!(c.penalty, 0.0);
        assert!(c.may_be_confirmed);
    }

    #[test]
    fn stale_evidence_cannot_produce_confirmed_edge() {
        let c = freshness_confidence(Freshness::Stale, ScanStatus::Complete);
        assert!(!c.may_be_confirmed);
        assert_eq!(c.penalty, 0.3);
    }

    #[test]
    fn partial_scan_evidence_never_upgrades_confidence() {
        let fresh_partial = freshness_confidence(Freshness::Fresh, ScanStatus::Partial);
        assert!(!fresh_partial.may_be_confirmed);
        assert!(fresh_partial.penalty >= 0.1);

        let aging_partial = freshness_confidence(Freshness::Aging, ScanStatus::Partial);
        assert!(!aging_partial.may_be_confirmed);
        assert!(aging_partial.penalty >= 0.1);

        let stale_partial = freshness_confidence(Freshness::Stale, ScanStatus::Partial);
        assert!(!stale_partial.may_be_confirmed);
        assert_eq!(stale_partial.penalty, 0.3);
    }

    #[test]
    fn unknown_evidence_is_unconfirmable() {
        let c = freshness_confidence(Freshness::Unknown, ScanStatus::Complete);
        assert!(!c.may_be_confirmed);
        assert_eq!(c.penalty, 0.1);
    }

    #[test]
    fn aging_evidence_confirms_with_small_penalty() {
        let c = freshness_confidence(Freshness::Aging, ScanStatus::Complete);
        assert!(c.may_be_confirmed);
        assert_eq!(c.penalty, 0.1);
    }
}
