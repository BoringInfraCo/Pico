//! Sprint 016 MCP surfacing fixtures (R7).
//!
//! R7 asserts the `get_finding` tool JSON includes the structured
//! `effective_bash_capability` field (and `bash_boundary`) for the resolved
//! OpenCode Bash postures. Only AUTO_ALLOW and SANDBOXED yield an active
//! finding, so the end-to-end MCP call is exercised for SANDBOXED; the
//! structured-field correctness for every resolved state is asserted directly
//! in `src/mcp/tools.rs` (the MCP mirror owns the serialized field).

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::mcp::handle_line;
use serde_json::{json, Value};
use tempfile::tempdir;

const GET_CALL: &str = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_finding","arguments":{"id":"PLACEHOLDER"}}}"#;

fn opencode_config(permission_bash: &str, sandbox: bool) -> String {
    let sandbox_field = if sandbox { r#", "sandbox": true"# } else { "" };
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "{permission_bash}" }}{sandbox_field}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }} }} }} }} }}"#
    )
}

fn setup_with(config: &str) -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), config).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
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
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_with_bash(permission_bash: &str, sandbox: bool) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup_with(&opencode_config(permission_bash, sandbox));
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
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

fn payload_of(text: &str) -> Value {
    let frame: Value = serde_json::from_str(text).expect("frame is JSON");
    let inner = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(inner).expect("tool payload JSON")
}

#[test]
fn mcp_get_finding_includes_effective_bash_capability_for_sandbox() {
    let (workspace, scan) = scan_with_bash("allow", true);
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(scan.finding_count, 1);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let finding_id = list.findings[0].id.clone();
    let call = GET_CALL.replace("PLACEHOLDER", &finding_id);
    let frame = handle_line(&call, workspace.path()).expect("get_finding frame");
    let detail = payload_of(&frame);

    let path = &detail["paths"][0];
    assert_eq!(
        path["effective_bash_capability"],
        json!("SANDBOXED"),
        "MCP get_finding must surface the SANDBOXED effective Bash capability"
    );
    assert_eq!(
        path["bash_boundary"],
        json!("SANDBOX"),
        "MCP get_finding must surface the Sandbox interrupting boundary"
    );
}
