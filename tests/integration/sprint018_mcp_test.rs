//! Sprint 018 MCP surfacing fixtures (R7 / R10).
//!
//! R7 asserts the `get_finding` MCP tool JSON carries a `cloudflare_authority`
//! array per explained path recording the credential type, granted permission
//! groups, and the authority resolution tier for each Cloudflare `can_mutate`
//! edge. R10 asserts the JSON never leaks a synthetic Cloudflare token value.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::mcp::handle_line;
use serde_json::Value;
use std::path::Path;
use tempfile::tempdir;

/// Synthetic fake Cloudflare API token (cfut_ => api_token). Never a real secret.
const FAKE_CF_API_TOKEN: &str = "cfut_TESTFAKE000000000000000000000000000000";

fn golden_config(token: &str) -> String {
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "allow" }}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{token}" }} }} }} }} }}"#
    )
}

fn setup_with(config: &str) -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), config).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_CF_API_TOKEN)];
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
            granted_permissions: vec!["Workers Scripts Write".to_string()],
            zone_scoped: false,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_golden() -> (tempfile::TempDir, ScanResult) {
    let workspace = setup_with(&golden_config(FAKE_CF_API_TOKEN));
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_CF_API_TOKEN)];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace.path(), home.path())),
    )
    .unwrap();
    (workspace, result)
}

fn get_finding_payload(workspace: &Path, finding_id: &str) -> Value {
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"{finding_id}"}}}}}}"#
    );
    let frame = handle_line(&line, workspace).expect("request must produce a frame");
    let response: Value = serde_json::from_str(&frame).expect("valid JSON frame");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).expect("tool payload JSON")
}

/// R7: the `get_finding` MCP tool JSON carries the per-Cloudflare-edge authority
/// array with the resolved credential type, granted permission groups, and the
/// authority resolution tier.
#[test]
fn cloudflare_authority_surfaces_in_mcp_get_finding() {
    let (workspace, scan) = scan_golden();
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.finding_count, 1,
        "golden-style path must stay at 1 finding"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let finding_id = list.findings[0].id.clone();
    let payload = get_finding_payload(workspace.path(), &finding_id);

    let mut collected: Vec<(String, Vec<String>, String)> = Vec::new();
    for path in payload["paths"].as_array().expect("paths array") {
        for entry in path["cloudflare_authority"]
            .as_array()
            .expect("cloudflare_authority array")
        {
            collected.push((
                entry["credential_type"].as_str().unwrap().to_string(),
                entry["granted_permissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_string())
                    .collect(),
                entry["authority_resolution"].as_str().unwrap().to_string(),
            ));
        }
    }

    assert!(
        !collected.is_empty(),
        "expected at least one cloudflare_authority entry"
    );
    let entry = &collected[0];
    assert_eq!(entry.0, "api_token", "credential_type must be api_token");
    assert_eq!(
        entry.1,
        vec!["Workers Scripts Write".to_string()],
        "granted_permissions must carry the write group"
    );
    assert_eq!(
        entry.2, "EXACT",
        "authority_resolution must be the EXACT tier"
    );
}

/// R10: the MCP `get_finding` JSON never contains the synthetic Cloudflare token
/// value, only classification facts.
#[test]
fn mcp_get_finding_never_leaks_fake_cloudflare_token() {
    let (workspace, scan) = scan_golden();
    assert_eq!(scan.status, ScanStatus::Complete);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    assert!(!list.findings.is_empty());
    let finding_id = list.findings[0].id.clone();

    let payload = get_finding_payload(workspace.path(), &finding_id);
    let text = serde_json::to_string(&payload).expect("serializable payload");

    assert!(
        !text.contains(FAKE_CF_API_TOKEN),
        "MCP get_finding JSON leaked the synthetic Cloudflare token:\n{text}"
    );
}
