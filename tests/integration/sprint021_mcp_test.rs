//! Sprint 021 MCP surfacing fixtures (R7 / R10).
//!
//! R7 asserts the `list_findings` and `get_finding` tool JSON carry a
//! `github_credentials` array — one entry per observed GitHub credential with
//! `credential_type`, `authority_resolution`, `permission_state`, and
//! `unknown_reasons` — for both a live classic-PAT repo-scope probe (EXACT /
//! REPO_WRITE) and the offline path (UNKNOWN + unobservable reason). R10 asserts
//! that across the github postures (classic live repo, read-only, fine-grained,
//! offline) the MCP JSON never contains a synthetic GitHub token value. All
//! scans run through fixture transports / injected normalized results; no
//! network access is involved.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::github::{self, GitHubAuthorityResult};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::mcp::handle_line;
use serde_json::Value;
use std::path::Path;
use tempfile::tempdir;

const GOLDEN_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");

/// Synthetic fake GitHub classic PAT used only to prove it never reaches output.
const GITHUB_PAT: &str = "ghp_TESTFAKE0000000000000000000000000000";
/// Synthetic fake GitHub fine-grained PAT used only to prove it never leaks.
const GITHUB_FINE_GRAINED: &str = "github_pat_TESTFAKE00000000000000000000";
/// Synthetic fake Cloudflare token used for the golden-style provider scan.
const CLOUDFLARE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";

const LIST_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}"#;

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

/// Simulate a successful live scope probe result for a credential type and the
/// observed OAuth scopes.
fn live_result(fingerprint: &str, credential_type: &str, scopes: &[&str]) -> GitHubAuthorityResult {
    let scopes = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<Vec<_>>();
    let (state, resolution, permission_state, unknown_reasons) =
        github::resolve_authority(credential_type, &scopes);
    GitHubAuthorityResult {
        credential_fingerprint: fingerprint.to_string(),
        credential_type: Some(credential_type.to_string()),
        state,
        resolution,
        permission_state: permission_state.to_string(),
        unknown_reasons,
        source_locator: "github:scope_probe:/user".to_string(),
        problems: Vec::new(),
    }
}

/// A Cloudflare provider projection producing the golden-style single active
/// finding, so a scan that mixes a GitHub credential with it keeps the golden
/// finding count while still observing the GitHub authority.
fn cloudflare_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN)];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
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

/// Scan the golden-style config with a Cloudflare provider AND a GitHub
/// credential (token + injected normalized result), keeping the golden finding
/// count while observing the GitHub authority.
fn mixed_scan(
    token: &str,
    github_result: Option<GitHubAuthorityResult>,
) -> (tempfile::TempDir, pico::application::ScanResult) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), GOLDEN_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [
        ("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN),
        ("GITHUB_TOKEN", token),
    ];
    let result = ScanService::run_with_home_and_environment_and_providers(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(cloudflare_provider(workspace.path(), home.path())),
        github_result,
    )
    .unwrap();
    (workspace, result)
}

fn list_payload(workspace: &Path) -> Value {
    let frame = handle_line(LIST_CALL, workspace).expect("list_findings frame");
    let frame: Value = serde_json::from_str(&frame).expect("frame is JSON");
    let inner = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(inner).expect("tool payload JSON")
}

fn get_finding_payload(workspace: &Path, finding_id: &str) -> Value {
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"{finding_id}"}}}}}}"#
    );
    let frame = handle_line(&call, workspace).expect("get_finding frame");
    let frame: Value = serde_json::from_str(&frame).expect("frame is JSON");
    let inner = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(inner).expect("tool payload JSON")
}

/// R7 (live): the `list_findings` and `get_finding` JSON carry `github_credentials`
/// with the credential type and the EXACT authority resolution for a live
/// classic-PAT repo-scope probe.
#[test]
fn github_credentials_surface_in_mcp_list_and_detail_live_exact() {
    let (workspace, scan) = mixed_scan(
        GITHUB_PAT,
        Some(live_result(
            &github::fingerprint(GITHUB_PAT),
            "classic_pat",
            &["repo"],
        )),
    );
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.finding_count, 1,
        "golden-style path stays at 1 finding"
    );

    let list = list_payload(workspace.path());
    let credentials = list["github_credentials"]
        .as_array()
        .expect("github_credentials must be an array");
    assert!(
        !credentials.is_empty(),
        "expected at least one github_credentials entry in:\n{list}"
    );
    assert_eq!(
        credentials[0]["credential_type"],
        serde_json::json!("classic_pat"),
        "list_findings github credential_type must be classic_pat"
    );
    assert_eq!(
        credentials[0]["authority_resolution"],
        serde_json::json!("EXACT"),
        "list_findings github authority_resolution must be EXACT"
    );
    assert_eq!(
        credentials[0]["permission_state"],
        serde_json::json!("REPO_WRITE")
    );
    assert_eq!(credentials[0]["unknown_reasons"], serde_json::json!([]));

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = get_finding_payload(workspace.path(), &list.findings[0].id);
    let credentials = detail["github_credentials"]
        .as_array()
        .expect("github_credentials must be an array");
    assert!(
        !credentials.is_empty(),
        "expected github_credentials in get_finding JSON:\n{detail}"
    );
    assert_eq!(
        credentials[0]["credential_type"],
        serde_json::json!("classic_pat")
    );
    assert_eq!(
        credentials[0]["authority_resolution"],
        serde_json::json!("EXACT")
    );
}

/// R7 (offline): a GitHub credential without a probe resolves UNKNOWN and the
/// MCP JSON carries the unobservable reason instead of a fabricated write.
#[test]
fn github_credentials_surface_in_mcp_list_offline_unknown() {
    let (workspace, scan) = mixed_scan(GITHUB_PAT, None);
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(scan.finding_count, 1);

    let list = list_payload(workspace.path());
    let credentials = list["github_credentials"]
        .as_array()
        .expect("github_credentials must be an array");
    assert!(!credentials.is_empty());
    assert_eq!(
        credentials[0]["authority_resolution"],
        serde_json::json!("UNKNOWN"),
        "offline github authority must be UNKNOWN"
    );
    assert_eq!(
        credentials[0]["unknown_reasons"],
        serde_json::json!(["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE"]),
        "offline github reason must be surfaced"
    );
    assert!(
        !credentials[0]["permission_state"]
            .as_str()
            .unwrap()
            .contains("REPO_WRITE"),
        "offline must never fabricate a write permission state"
    );
}

/// R7 (golden path): a scan without a GitHub credential keeps the golden
/// finding count and the MCP JSON carries an empty `github_credentials` array.
#[test]
fn github_credentials_empty_in_mcp_golden_path() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), GOLDEN_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN)];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(cloudflare_provider(workspace.path(), home.path())),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(
        result.finding_count, 1,
        "golden path must stay at 1 finding"
    );

    let list = list_payload(workspace.path());
    assert_eq!(
        list["github_credentials"],
        serde_json::json!([]),
        "golden path must carry an empty github_credentials array"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = get_finding_payload(workspace.path(), &list.findings[0].id);
    assert_eq!(detail["github_credentials"], serde_json::json!([]));
}

/// R10 (MCP): across the github postures (classic live repo scope, read-only,
/// fine-grained, offline) the `list_findings` and `get_finding` JSON never
/// contain a synthetic GitHub token value.
#[test]
fn r10_mcp_json_never_leaks_github_token_across_postures() {
    let postures: Vec<(&str, Option<GitHubAuthorityResult>)> = vec![
        (
            GITHUB_PAT,
            Some(live_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                &["repo"],
            )),
        ),
        (
            GITHUB_PAT,
            Some(live_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                &["read:user", "read:org"],
            )),
        ),
        (
            GITHUB_FINE_GRAINED,
            Some(live_result(
                &github::fingerprint(GITHUB_FINE_GRAINED),
                "fine_grained_pat",
                &["repo"],
            )),
        ),
        (GITHUB_PAT, None),
    ];
    let mut posture_index = 0;
    for (token, github_result) in postures {
        posture_index += 1;
        let (workspace, scan) = mixed_scan(token, github_result);
        assert_eq!(scan.status, ScanStatus::Complete);
        assert_eq!(scan.finding_count, 1);

        let list = list_payload(workspace.path());
        let list_text = serde_json::to_string(&list).expect("serializable");
        assert!(
            !list_text.contains(GITHUB_PAT) && !list_text.contains(GITHUB_FINE_GRAINED),
            "posture {posture_index}: list_findings JSON leaked a synthetic token:\n{list_text}"
        );

        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        let detail = get_finding_payload(workspace.path(), &list.findings[0].id);
        let detail_text = serde_json::to_string(&detail).expect("serializable");
        assert!(
            !detail_text.contains(GITHUB_PAT) && !detail_text.contains(GITHUB_FINE_GRAINED),
            "posture {posture_index}: get_finding JSON leaked a synthetic token:\n{detail_text}"
        );
    }
}
