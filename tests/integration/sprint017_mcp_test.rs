//! Sprint 017 MCP surfacing fixtures (R7 / R10).
//!
//! R7 asserts the `get_finding` MCP tool JSON carries a `github_influence`
//! array per explained path with one entry per GitHub MCP tool, recording the
//! tool name, content class, trust, and influence strength for a read tool. R10
//! asserts the JSON never leaks a synthetic GitHub token value. (The write-tool
//! `AGENT_MUTABLE` entry serialization is asserted by the in-crate unit test
//! `safe_explained_path_serializes_github_influence` in `src/mcp/tools.rs`,
//! because a write tool is always surfaced as an interrupting Mutation boundary
//! and therefore never reaches an active explained finding.)

use std::collections::BTreeMap;
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

/// Synthetic fake GitHub token used only to prove it never reaches output.
const FAKE_GITHUB_TOKEN: &str = "ghp_TESTFAKE0000000000000000000000000000";

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
    let environment = [(
        "CLOUDFLARE_API_TOKEN",
        "cfut_TESTFAKE0000000000000000000000000000",
    )];
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

fn scan_golden(token: &str) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup_with(&golden_config(token));
    let home = tempdir().unwrap();
    let environment = [(
        "CLOUDFLARE_API_TOKEN",
        "cfut_TESTFAKE0000000000000000000000000000",
    )];
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

/// Returns the parsed `get_finding` tool payload for a finding ID via the MCP
/// stdio handler (mirrors the Sprint 011 harness framing).
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

/// R7: the `get_finding` MCP tool JSON carries the per-tool GitHub MCP
/// influence entries for the observed read tool (PUBLIC_EXTERNAL /
/// AGENT_INJECTABLE).
#[test]
fn github_influence_surfaces_in_mcp_get_finding() {
    let (workspace, scan) = scan_golden(FAKE_GITHUB_TOKEN);
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.finding_count, 1,
        "golden-style path must stay at 1 finding"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let finding_id = list.findings[0].id.clone();
    let payload = get_finding_payload(workspace.path(), &finding_id);

    let mut found: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    for path in payload["paths"].as_array().expect("paths array") {
        for entry in path["github_influence"]
            .as_array()
            .expect("github_influence array")
        {
            found.insert(
                entry["tool_name"].as_str().unwrap().to_string(),
                (
                    entry["content_class"].as_str().unwrap().to_string(),
                    entry["trust"].as_str().unwrap().to_string(),
                    entry["influence_strength"].as_str().unwrap().to_string(),
                ),
            );
        }
    }

    let read = found
        .get("issue_read")
        .expect("issue_read influence entry present");
    assert_eq!(
        read,
        &(
            "github:public:issue-content".to_string(),
            "PUBLIC_EXTERNAL".to_string(),
            "AGENT_INJECTABLE".to_string()
        ),
        "read tool must surface PUBLIC_EXTERNAL / AGENT_INJECTABLE"
    );
}

/// R10: the MCP `get_finding` JSON never contains the synthetic GitHub token
/// value, only classification facts.
#[test]
fn mcp_get_finding_never_leaks_fake_github_token() {
    let (workspace, scan) = scan_golden(FAKE_GITHUB_TOKEN);
    assert_eq!(scan.status, ScanStatus::Complete);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    assert!(!list.findings.is_empty());
    let finding_id = list.findings[0].id.clone();

    let payload = get_finding_payload(workspace.path(), &finding_id);
    let text = serde_json::to_string(&payload).expect("serializable payload");

    assert!(
        !text.contains(FAKE_GITHUB_TOKEN),
        "MCP get_finding JSON leaked the fake GitHub token:\n{text}"
    );
}
