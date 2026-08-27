//! Sprint 019 CLI surfacing fixtures (R6 / R10).
//!
//! R6 asserts the `pico scan` diagnostics block renders provider failure,
//! partial scan status, suppressed candidates, and confidence reduction when the
//! scan is not the golden Complete + Fresh path; and that the golden path stays
//! silent (no incomplete-evidence noise). R10 asserts the rendered block never
//! contains a secret-shaped synthetic token and that provider problems never do
//! either, across the partial, stale-edge, and unknown-authority postures.

use std::fs;

use pico::application::{InitService, ScanResult, ScanService};
use pico::cli::render::render_scan_diagnostics;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::RelationshipState;
use pico::findings::diagnostics::{
    ConfidenceNote, ProviderDiagnostic, ScanDiagnostics, SuppressedReason,
};
use tempfile::tempdir;

/// Synthetic secret-shaped token. Placed ONLY in a fixture config file; it must
/// never appear in rendered diagnostics, provider problems, or emitted metadata.
const FAKE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";

fn config_with_token(token: &str) -> String {
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "allow" }}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{token}" }} }} }} }} }}"#
    )
}

fn setup(token: &str) -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        config_with_token(token),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn discover_fingerprint(workspace: &std::path::Path, home: &std::path::Path) -> String {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_TOKEN)];
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

fn valid_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    };
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

/// A provider result that reaches the credential but reports a sanitized problem
/// so the scan becomes PARTIAL. The problem deliberately does NOT include the
/// synthetic token.
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
) -> ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_TOKEN)];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap()
}

/// R6: a PARTIAL scan (failing Cloudflare provider) renders an "Incomplete
/// evidence" block naming the failed provider, the partial reason, and a
/// sanitized problem — without embedding the synthetic token.
#[test]
fn cli_diagnostics_block_surfaces_provider_failure_and_partial_status() {
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    let result = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    let detail = result
        .diagnostics_detail
        .expect("diagnostics_detail populated");
    let block = render_scan_diagnostics(&detail);

    assert!(
        block.contains("Incomplete evidence"),
        "block must carry the diagnostics header:\n{block}"
    );
    assert!(
        block.contains("Provider cloudflare: FAILED"),
        "failed provider must be named:\n{block}"
    );
    assert!(
        block.contains("cloudflare token verification failed"),
        "sanitized problem must be shown:\n{block}"
    );
    assert!(
        block.contains("Scan status: PARTIAL (cloudflare)"),
        "partial reason must name the failing provider:\n{block}"
    );
    assert!(
        !block.contains(FAKE_TOKEN),
        "rendered block must never contain the synthetic token:\n{block}"
    );
}

/// R6: the golden Complete + Fresh path renders nothing — no incomplete-evidence
/// noise is added to the scan summary.
#[test]
fn cli_golden_path_renders_no_diagnostics_noise() {
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    let result = run(
        workspace.path(),
        home.path(),
        valid_provider(workspace.path(), home.path()),
    );
    assert_eq!(
        result.finding_count, 1,
        "golden path yields exactly 1 finding"
    );

    let detail = result
        .diagnostics_detail
        .expect("diagnostics_detail populated");
    let block = render_scan_diagnostics(&detail);
    assert!(
        block.is_empty(),
        "golden path must render no diagnostics block, got:\n{block}"
    );
    for noise in ["FAILED", "Suppressed", "Confidence reduced", "PARTIAL"] {
        assert!(
            !block.contains(noise),
            "golden path block must not contain {noise}:\n{block}"
        );
    }
    assert!(
        !block.contains(FAKE_TOKEN),
        "golden path block must never contain the synthetic token:\n{block}"
    );
}

/// R10: across the partial, stale-edge, and unknown-authority postures the
/// rendered diagnostics block and every provider problem never contain the
/// synthetic token (the token lives only in the fixture config).
#[test]
fn cli_secret_sweep_never_leaks_token_across_postures() {
    // (a) Partial posture: failing provider.
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    let partial = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    let partial_detail = partial.diagnostics_detail.expect("diagnostics populated");
    let partial_block = render_scan_diagnostics(&partial_detail);
    assert!(!partial_block.contains(FAKE_TOKEN));
    for provider in &partial_detail.provider_statuses {
        for problem in &provider.problems {
            assert!(
                !problem.contains(FAKE_TOKEN),
                "provider problem leaked the token: {problem}"
            );
        }
    }

    // (b) Stale-edge + (c) unknown-authority postures: synthesized diagnostics
    // that exercise suppressed candidates and confidence reduction while proving
    // no secret shape is ever embedded in the rendered block.
    let stale = ScanDiagnostics {
        provider_statuses: vec![ProviderDiagnostic {
            name: "opencode".to_string(),
            reachable: true,
            problems: vec![],
        }],
        scan_status: "COMPLETE".to_string(),
        partial_reason: None,
        suppressed: vec![SuppressedReason {
            fingerprint: "sha256:stale-candidate".to_string(),
            reason: "edge evidence is STALE; candidate not confirmed".to_string(),
        }],
        reduced_confidence: vec![ConfidenceNote {
            fingerprint: "sha256:active-finding".to_string(),
            edges: vec![(
                "agent:opencode|can_execute|shell:bash".to_string(),
                "STALE".to_string(),
                0.25,
            )],
        }],
    };
    let stale_block = render_scan_diagnostics(&stale);
    assert!(
        stale_block.contains("Suppressed sha256:stale-candidate"),
        "stale posture must surface suppression:\n{stale_block}"
    );
    assert!(
        stale_block.contains("Confidence reduced sha256:active-finding"),
        "stale posture must surface confidence reduction:\n{stale_block}"
    );
    assert!(!stale_block.contains(FAKE_TOKEN));

    let unknown = ScanDiagnostics {
        provider_statuses: vec![ProviderDiagnostic {
            name: "cloudflare".to_string(),
            reachable: true,
            problems: vec![],
        }],
        scan_status: "COMPLETE".to_string(),
        partial_reason: None,
        suppressed: vec![SuppressedReason {
            fingerprint: "sha256:unknown-authority".to_string(),
            reason: "authority resolution UNKNOWN; candidate not confirmed".to_string(),
        }],
        reduced_confidence: vec![],
    };
    let unknown_block = render_scan_diagnostics(&unknown);
    assert!(
        unknown_block.contains("Suppressed sha256:unknown-authority"),
        "unknown-authority posture must surface suppression:\n{unknown_block}"
    );
    assert!(!unknown_block.contains(FAKE_TOKEN));
}
