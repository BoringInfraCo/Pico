//! Application services.
//!
//! Interfaces (CLI) call application services; application services
//! coordinate domain and persistence. See SPRINT-001.md §6 (Interface
//! separation).

pub mod cause;
pub mod compare_contract;
pub mod diff;
pub mod findings;
pub mod graph_diff;
pub mod history;
pub mod init;
pub mod scan;

pub use cause::FindingCause;
pub use compare_contract::{
    validate_pico_version, ComparisonContractField, ComparisonContractVersions,
    ComparisonProvenanceGap, DiffProvenance, DiffSide, DiffSideProvenance,
    COMPARISON_CONTRACT_VERSION, CURRENT_COMPARISON_CONTRACT,
};
pub use diff::{
    ComparedVia, DiffFinding, DiffNotComparable, DiffNotComparableReason, DiffService, FindingDiff,
    FindingDiffResult, FindingLifecycleChange, FindingRatingDelta,
};
pub use findings::{
    finding_navigation_ids, findings_list_guidance, findings_list_state, BoundaryView, Currentness,
    EvidenceView, ExplainedPath, FindingDetail, FindingList, FindingQueryService, FindingSummary,
    FindingsListState, Freshness, GitHubCredentialView, PathStep, ReasonView, RemediationView,
    ResourceView, ScanBrief,
};
pub use graph_diff::{GraphDelta, GraphDiff, GraphSubject, GraphSubjectDiff};
pub use history::{HistoryService, ScanHistory, ScanSummary};
pub use init::{InitResult, InitService};
pub use scan::{AgentBashPosture, ScanResult, ScanService};
