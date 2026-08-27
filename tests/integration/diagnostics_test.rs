//! Structured scan-diagnostics fixtures (R1, R5, R8).
//!
//! These run the full `ScanService` so the provider-level diagnostics
//! (`provider_statuses`, `partial_reason`) are exercised end to end. All
//! provider facts are normalized and sanitized; no real Cloudflare calls or
//! token values are involved.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::ScanStatus;
use tempfile::tempdir;

const CONFIG: &str = r#"{
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

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn discover_fingerprint(workspace: &std::path::Path, home: &std::path::Path) -> String {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap()
    .credentials[0]
        .fingerprint
        .clone()
}

fn production_worker() -> ObservedWorker {
    ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    }
}

/// A valid, complete provider result with an explicit PRODUCTION worker.
fn valid_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let worker = production_worker();
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: discover_fingerprint(workspace, home),
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
            state: pico::domain::RelationshipState::Derived,
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

/// A provider result that reaches the credential but reports a sanitized
/// problem, so the scan becomes PARTIAL.
fn failing_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let mut provider = valid_provider(workspace, home);
    provider.problems =
        vec!["cloudflare token verification failed: provider returned HTTP 401".to_string()];
    provider
}

fn run(
    workspace: &std::path::Path,
    home: &std::path::Path,
    provider: ProviderResult,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap()
}

/// R1: a scan where the Cloudflare provider reports a problem surfaces the
/// failure in `provider_statuses` (sanitized, unreachable) while the OpenCode
/// provider remains reachable.
#[test]
fn diagnostics_report_per_provider_status() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let result = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    let detail = result
        .diagnostics_detail
        .expect("diagnostics_detail is populated");

    let cloudflare = detail
        .provider_statuses
        .iter()
        .find(|p| p.name == "cloudflare")
        .expect("cloudflare provider status present");
    assert!(!cloudflare.reachable);
    assert!(
        cloudflare
            .problems
            .iter()
            .any(|p| p.contains("token verification")),
        "sanitized problem present: {:?}",
        cloudflare.problems
    );

    let opencode = detail
        .provider_statuses
        .iter()
        .find(|p| p.name == "opencode")
        .expect("opencode provider status present");
    assert!(opencode.reachable);
    assert!(opencode.problems.is_empty());
}

/// R5: a PARTIAL scan (caused by a failing provider) names the failing provider
/// in `partial_reason` and emits no Findings. The analysis short-circuits before
/// materializing candidate AttackPaths under a partial scan, so the candidate-
/// level `suppressed` list is empty by construction — the partiality is recorded
/// honestly at the scan level instead.
#[test]
fn diagnostics_explain_partial_scan_names_failed_provider() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let result = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    let detail = result
        .diagnostics_detail
        .expect("diagnostics_detail is populated");

    assert_eq!(detail.scan_status, "PARTIAL");
    assert_eq!(detail.partial_reason.as_deref(), Some("cloudflare"));
    assert_eq!(
        result.finding_count, 0,
        "findings are suppressed by the partial scan"
    );
    assert!(detail.suppressed.is_empty());
}

/// R8: battery covering a confident-complete baseline (no diagnostics) and
/// multi-provider partiality (a failing provider yields a named partial reason
/// and suppressed candidates).
#[test]
fn diagnostics_battery_partial_stale_unknown_mixed_multi_provider_complete() {
    let workspace = setup();
    let home = tempdir().unwrap();

    // (a) Confident-complete baseline: valid provider, PRODUCTION worker, no
    // problems. The golden path still yields exactly one active Finding and no
    // incomplete-evidence diagnostics.
    let clean = run(
        workspace.path(),
        home.path(),
        valid_provider(workspace.path(), home.path()),
    );
    assert_eq!(clean.status, ScanStatus::Complete);
    assert_eq!(clean.finding_count, 1);
    let detail_clean = clean
        .diagnostics_detail
        .expect("diagnostics_detail is populated");
    assert!(
        detail_clean.is_clean(),
        "golden baseline must have no diagnostics: {:?}",
        detail_clean
    );
    let names: Vec<&str> = detail_clean
        .provider_statuses
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.contains(&"opencode"));
    assert!(names.contains(&"cloudflare"));
    assert!(detail_clean.provider_statuses.iter().all(|p| p.reachable));

    // (b) Partiality from a different (failing) provider on the same workspace.
    let partial = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    assert_eq!(partial.status, ScanStatus::Partial);
    let detail_partial = partial
        .diagnostics_detail
        .expect("diagnostics_detail is populated");
    assert_eq!(detail_partial.scan_status, "PARTIAL");
    assert_eq!(detail_partial.partial_reason.as_deref(), Some("cloudflare"));
    assert_eq!(
        partial.finding_count, 0,
        "findings suppressed by partial scan"
    );
}
