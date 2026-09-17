//! Sprint 042 MCP list-parity fixtures (SPRINT-042.md §2.3).
//!
//! Drives the injected Cloudflare provider seam together with a **synthetic**
//! OpenCode-shaped runtime store (never the real `~/.local/share/opencode`), so
//! the `list_findings` payload's per-Finding `observed_execution` array can be
//! asserted end-to-end: a Finding resting on runtime evidence surfaces the
//! observation basis, and a Finding without it carries an empty array that is
//! always present. The list and detail surfaces are asserted to agree for the
//! same Finding.

use std::fs;
use std::path::Path;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::RelationshipState;
use pico::mcp::handle_line;
use rusqlite::params;
use serde_json::Value;
use tempfile::tempdir;

/// Synthetic secret-shaped token placed only in a fixture config; it must never
/// appear in the MCP payload.
const FAKE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";
/// Synthetic content sentinel for forbidden runtime-store fields.
const RUNTIME_SENTINEL: &str = "SENTINEL_S042_MCP";
/// The canonical golden-path capability relationship key.
const GOLDEN_KEY: &str = "agent:opencode|can_execute|shell:bash";

const CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "cfut_TESTFAKE0000000000000000000000000000" }
    }
  }}
}"#;

fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    (workspace, home)
}

fn discover_fingerprint(workspace: &Path, home: &Path) -> String {
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

fn valid_provider(workspace: &Path, home: &Path) -> ProviderResult {
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

/// Minimal OpenCode-shaped store with 38 applied migrations (the supported
/// version) carrying one fresh completed `bash` invocation scoped to the
/// workspace. Forbidden fields carry the sentinel so the leak sweep is
/// meaningful.
fn seed_supported_runtime_store(home: &Path, workspace: &Path) {
    let dir = home.join(".local/share/opencode");
    fs::create_dir_all(&dir).unwrap();
    let conn = rusqlite::Connection::open(dir.join("opencode.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, title TEXT);
         CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT,
                            time_created INTEGER, data TEXT);
         CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER);
         CREATE TABLE credential (id TEXT PRIMARY KEY, token TEXT);",
    )
    .unwrap();
    for index in 0..38 {
        conn.execute(
            "INSERT INTO migration (id, time_completed) VALUES (?1, ?2)",
            params![format!("migration_{index:04}"), 0i64],
        )
        .unwrap();
    }
    let directory = workspace
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    conn.execute(
        "INSERT INTO session (id, directory, title) VALUES ('ses_1', ?1, ?2)",
        params![directory, RUNTIME_SENTINEL],
    )
    .unwrap();
    let at_ms = chrono::Utc::now().timestamp_millis() - 60_000;
    let data = serde_json::json!({
        "type": "tool",
        "tool": "bash",
        "callID": "call_1",
        "state": { "status": "completed", "input": { "note": RUNTIME_SENTINEL }, "output": RUNTIME_SENTINEL },
    });
    conn.execute(
        "INSERT INTO part (id, message_id, session_id, time_created, data)
         VALUES ('p1', 'msg_1', 'ses_1', ?1, ?2)",
        params![at_ms, data.to_string()],
    )
    .unwrap();
}

fn run_scan(workspace: &Path, home: &Path, runtime_enabled: bool) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_TOKEN)];
    ScanService::run_with_runtime_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(valid_provider(workspace, home)),
        runtime_enabled,
    )
    .unwrap()
}

fn call_payload(workspace: &Path, line: &str) -> Value {
    let frame = handle_line(line, workspace).expect("request must produce a frame");
    let response: Value = serde_json::from_str(&frame).expect("valid JSON frame");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).expect("tool payload JSON")
}

fn list_payload(workspace: &Path) -> Value {
    call_payload(
        workspace,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings"}}"#,
    )
}

fn get_payload(workspace: &Path, finding_id: &str) -> Value {
    call_payload(
        workspace,
        &format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"{finding_id}"}}}}}}"#
        ),
    )
}

/// A Finding resting on runtime evidence surfaces the observation basis in the
/// MCP `list_findings` payload, and the list agrees with `get_finding` for the
/// same Finding (SPRINT-042 §2.3 acceptance).
#[test]
fn s042_mcp_list_findings_surfaces_runtime_observation_basis() {
    let (workspace, home) = setup();
    seed_supported_runtime_store(home.path(), workspace.path());
    let result = run_scan(workspace.path(), home.path(), true);
    assert_eq!(result.finding_count, 1, "golden-path finding expected");

    let payload = list_payload(workspace.path());
    let summary = &payload["findings"][0];
    let observed = summary["observed_execution"]
        .as_array()
        .expect("observed_execution must always be present as an array");
    assert_eq!(
        observed.len(),
        1,
        "a Finding resting on runtime evidence must surface one basis entry; got {summary}"
    );
    assert_eq!(
        observed[0]["relationship_key"],
        serde_json::json!(GOLDEN_KEY)
    );
    assert_eq!(
        observed[0]["basis"],
        serde_json::json!("OBSERVED_EXECUTION")
    );
    assert_eq!(observed[0]["freshness"], serde_json::json!("FRESH"));
    assert!(
        observed[0]["evidence_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "basis entry must carry the supporting evidence id"
    );

    // The list and detail surfaces agree for the same Finding.
    let finding_id = summary["id"].as_str().unwrap();
    let detail = get_payload(workspace.path(), finding_id);
    assert_eq!(
        summary["observed_execution"], detail["observed_execution"],
        "the list and detail must carry the same observation basis"
    );

    let text = serde_json::to_string(&payload).expect("serializable payload");
    assert!(
        !text.contains(RUNTIME_SENTINEL) && !text.contains(FAKE_TOKEN),
        "MCP payload leaked a synthetic sentinel:\n{text}"
    );
}

/// A Finding without runtime evidence carries an empty `observed_execution`
/// array that is still present, so an agent can never read omission as absence
/// of observation (SPRINT-042 §2.1/§2.3).
#[test]
fn s042_mcp_list_findings_without_runtime_has_empty_observed_execution() {
    let (workspace, home) = setup();
    seed_supported_runtime_store(home.path(), workspace.path());
    let result = run_scan(workspace.path(), home.path(), false);
    assert_eq!(result.finding_count, 1, "golden-path finding expected");

    let payload = list_payload(workspace.path());
    let summary = &payload["findings"][0];
    assert!(
        summary.get("observed_execution").is_some(),
        "observed_execution must be present even when nothing was observed: {summary}"
    );
    assert_eq!(
        summary["observed_execution"],
        serde_json::json!([]),
        "a Finding without runtime evidence must carry an empty array"
    );
}
