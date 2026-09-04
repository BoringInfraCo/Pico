//! Sprint 025 CLI history and explicit diff fixtures (R1–R8).
//!
//! `pico history` lists all scans with status, finding count, and timestamps.
//! `pico diff <from> <to>` compares Findings between two explicit COMPLETE
//! scans by id.

use std::fs;

use pico::application::{
    ComparedVia, DiffService, FindingDiffResult, HistoryService, InitService, ScanService,
};
use pico::cli::render::{render_finding_diff, render_scan_history};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const ALLOW: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }
    }
  }}
}"#;
const MALFORMED: &str = include_str!("../fixtures/opencode/malformed/opencode.json");

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    InitService::run(workspace.path()).unwrap();
    (workspace, home)
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: script_name.to_string(),
        worker_tag: Some(format!("worker-tag-{script_name}")),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    };
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: discovered.credentials[0].fingerprint.clone(),
        credential_status: Some(CredentialStatus::Active),
        accounts: vec![ObservedAccount {
            account_id: "account-1234567890123456".to_string(),
            name: Some("Synthetic Account".to_string()),
            account_type: Some("standard".to_string()),
            scope: ScopeState::InScope,
            source_locator: "/accounts".to_string(),
        }],
        workers: vec![worker],
        authorities: vec![AuthorityObservation {
            account_id: "account-1234567890123456".to_string(),
            worker_key,
            state: RelationshipState::Derived,
            resolution: AuthorityResolution::Exact,
            permission_state: "WORKERS_SCRIPTS_WRITE".to_string(),
            scope_state: ScopeState::InScope,
            unknown_reasons: Vec::new(),
            granted_permissions: Vec::new(),
            zone_scoped: false,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_named(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace, home, script_name)),
    )
    .unwrap()
}

fn diff_latest(workspace: &std::path::Path) -> FindingDiffResult {
    DiffService::latest(workspace).unwrap()
}

fn diff_explicit(
    workspace: &std::path::Path,
    from: &str,
    to: &str,
) -> FindingDiffResult {
    DiffService::compare(workspace, from, to).unwrap()
}

fn ready(result: FindingDiffResult) -> pico::application::FindingDiff {
    match result {
        FindingDiffResult::Ready(value) => value,
        other => panic!("expected Ready diff, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R1: history lists all scans chronologically
// ---------------------------------------------------------------------------

#[test]
fn history_lists_all_scans_chronologically() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "alpha");
    let second = scan_named(workspace.path(), home.path(), "beta");
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(second.status, ScanStatus::Complete);

    let history = HistoryService::list(workspace.path()).unwrap();
    assert_eq!(history.scans.len(), 2);
    assert_eq!(history.scans[0].id, first.scan_id);
    assert_eq!(history.scans[1].id, second.scan_id);
    assert_eq!(history.scans[0].status, "COMPLETE");
    assert_eq!(history.scans[1].status, "COMPLETE");
    assert_eq!(history.scans[0].finding_count, 1);
    assert_eq!(history.scans[1].finding_count, 1);

    let rendered = render_scan_history(&history);
    assert!(rendered.contains(&first.scan_id));
    assert!(rendered.contains(&second.scan_id));
    assert!(rendered.contains("Newest COMPLETE:"));
    assert!(rendered.contains(&second.scan_id));
}

// ---------------------------------------------------------------------------
// R2: history empty state is scoped
// ---------------------------------------------------------------------------

#[test]
fn history_empty_state_is_scoped() {
    let workspace = tempdir().unwrap();
    InitService::run(workspace.path()).unwrap();

    let history = HistoryService::list(workspace.path()).unwrap();
    assert!(history.scans.is_empty());

    let rendered = render_scan_history(&history);
    assert!(rendered.contains("No scans exist"));
}

// ---------------------------------------------------------------------------
// R3: explicit diff matches latest for the same pair
// ---------------------------------------------------------------------------

#[test]
fn explicit_diff_matches_latest_for_same_pair() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    let second = scan_named(workspace.path(), home.path(), "checkout");

    let latest = ready(diff_latest(workspace.path()));
    let explicit = ready(diff_explicit(workspace.path(), &first.scan_id, &second.scan_id));

    assert_eq!(latest.from.id, explicit.from.id);
    assert_eq!(latest.to.id, explicit.to.id);
    assert_eq!(latest.unchanged, explicit.unchanged);
    assert_eq!(latest.appeared, explicit.appeared);
    assert_eq!(latest.disappeared, explicit.disappeared);
    assert_eq!(explicit.compared_via, ComparedVia::ExplicitPair);
    assert_eq!(latest.compared_via, ComparedVia::LatestTwo);

    let latest_rendered = render_finding_diff(&FindingDiffResult::Ready(latest));
    let explicit_rendered = render_finding_diff(&FindingDiffResult::Ready(explicit));
    assert!(latest_rendered.contains("Compared: LAST TWO COMPLETE SCANS"));
    assert!(latest_rendered.contains("Freshness:"));
    assert!(explicit_rendered.contains("Compared: EXPLICIT PAIR"));
    assert!(
        !explicit_rendered.contains("Freshness:"),
        "explicit pair must not claim latest-complete freshness:\n{explicit_rendered}"
    );
}

// ---------------------------------------------------------------------------
// R4: explicit diff with non-existent scan id is error
// ---------------------------------------------------------------------------

#[test]
fn explicit_diff_nonexistent_scan_is_error() {
    let (workspace, _home) = setup();
    let result = DiffService::compare(workspace.path(), "scan_nonexistent", "scan_also_fake");
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("not found"), "error should mention not found: {msg}");
}

// ---------------------------------------------------------------------------
// R5: explicit diff with PARTIAL scan id is error
// ---------------------------------------------------------------------------

#[test]
fn explicit_diff_partial_scan_is_error() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), MALFORMED);
    let partial = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(partial.status, ScanStatus::Partial);

    let first = DiffService::latest(workspace.path()).unwrap();
    let newest_complete = match &first {
        FindingDiffResult::NeedPrevious { newest_complete, .. } => newest_complete.id.clone(),
        _ => panic!("expected NeedPrevious"),
    };

    let result = DiffService::compare(workspace.path(), &newest_complete, &partial.scan_id);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("PARTIAL"), "error should mention status: {msg}");
}

// ---------------------------------------------------------------------------
// R6: explicit diff with same scan id is error
// ---------------------------------------------------------------------------

#[test]
fn explicit_diff_same_scan_is_error() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");

    let result = DiffService::compare(workspace.path(), &first.scan_id, &first.scan_id);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("itself"),
        "error should mention itself: {msg}"
    );
}

// ---------------------------------------------------------------------------
// R7: explicit diff is deterministic across runs
// ---------------------------------------------------------------------------

#[test]
fn explicit_diff_deterministic_across_runs() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    let second = scan_named(workspace.path(), home.path(), "checkout");

    let a = ready(diff_explicit(workspace.path(), &first.scan_id, &second.scan_id));
    let b = ready(diff_explicit(workspace.path(), &first.scan_id, &second.scan_id));
    assert_eq!(a.unchanged, b.unchanged);
    assert_eq!(a.appeared, b.appeared);
    assert_eq!(a.disappeared, b.disappeared);
}

// ---------------------------------------------------------------------------
// R8: secret sweep — synthetic tokens never appear in history or explicit diff
// ---------------------------------------------------------------------------

#[test]
fn secret_sweep_never_leaks_in_history_or_explicit_diff() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    let second = scan_named(workspace.path(), home.path(), "billing");

    let history = HistoryService::list(workspace.path()).unwrap();
    let history_rendered = render_scan_history(&history);
    assert!(!history_rendered.contains(SECRET_SENTINEL));
    assert!(!history_rendered.contains("synthetic-token"));

    let explicit = ready(diff_explicit(workspace.path(), &first.scan_id, &second.scan_id));
    let diff_rendered = render_finding_diff(&FindingDiffResult::Ready(explicit));
    assert!(!diff_rendered.contains(SECRET_SENTINEL));
    assert!(!diff_rendered.contains("synthetic-token"));
}

// ---------------------------------------------------------------------------
// R9: Sprint 024 regression — latest diff still works
// ---------------------------------------------------------------------------

#[test]
fn sprint024_latest_diff_unchanged() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");

    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.unchanged.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    assert_eq!(comparison.compared_via, ComparedVia::LatestTwo);

    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("No security-significant finding change."));
    assert!(!rendered.contains(SECRET_SENTINEL));
}
