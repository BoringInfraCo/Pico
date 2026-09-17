//! Sprint 019 MCP surfacing fixtures (R7 / R10).
//!
//! R7 asserts the `list_findings` MCP tool JSON carries a `diagnostics` object
//! mirroring `ScanDiagnostics` with `provider_statuses`, `scan_status`,
//! `partial_reason`, `suppressed`, and `reduced_confidence` for the partial
//! (incomplete-evidence) case. R10 asserts the JSON never leaks a synthetic
//! secret-shaped token, including across the provider-problem posture.

use std::fs;

use pico::application::{InitService, ScanResult, ScanService};
use pico::cli::render::render_scan_diagnostics;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::RelationshipState;
use pico::mcp::handle_line;
use serde_json::Value;
use std::path::Path;
use tempfile::tempdir;

/// Synthetic secret-shaped token. Placed ONLY in a fixture config file; it must
/// never appear in the MCP diagnostics JSON or provider problems.
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

fn list_findings_payload(workspace: &Path) -> Value {
    let line =
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings"}}"#;
    let frame = handle_line(line, workspace).expect("request must produce a frame");
    let response: Value = serde_json::from_str(&frame).expect("valid JSON frame");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).expect("tool payload JSON")
}

/// R7: the `list_findings` MCP tool JSON carries a `diagnostics` object with the
/// complete structured surface for a PARTIAL (incomplete-evidence) scan.
#[test]
fn mcp_list_findings_surfaces_diagnostics_object() {
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    let result = run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    assert_eq!(result.status, pico::domain::ScanStatus::Partial);

    let payload = list_findings_payload(workspace.path());
    let diagnostics = payload
        .get("diagnostics")
        .expect("diagnostics field must be present in list_findings payload");

    assert!(
        diagnostics.get("provider_statuses").is_some(),
        "diagnostics must include provider_statuses"
    );
    assert!(
        diagnostics.get("scan_status").is_some(),
        "diagnostics must include scan_status"
    );
    assert!(
        diagnostics.get("partial_reason").is_some(),
        "diagnostics must include partial_reason"
    );
    assert!(
        diagnostics.get("suppressed").is_some(),
        "diagnostics must include suppressed"
    );
    assert!(
        diagnostics.get("reduced_confidence").is_some(),
        "diagnostics must include reduced_confidence"
    );

    assert_eq!(diagnostics["scan_status"], serde_json::json!("PARTIAL"));
    assert_eq!(
        diagnostics["partial_reason"],
        serde_json::json!("cloudflare")
    );

    let providers = diagnostics["provider_statuses"]
        .as_array()
        .expect("provider_statuses is an array");
    let cloudflare = providers
        .iter()
        .find(|p| p["name"] == serde_json::json!("cloudflare"))
        .expect("cloudflare provider status present");
    assert_eq!(cloudflare["reachable"], serde_json::json!(false));
    assert!(
        cloudflare["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p.as_str().unwrap().contains("token verification")),
        "sanitized cloudflare problem present: {cloudflare}"
    );

    let text = serde_json::to_string(&payload).expect("serializable payload");
    assert!(
        !text.contains(FAKE_TOKEN),
        "MCP diagnostics JSON leaked the synthetic token:\n{text}"
    );
}

/// R7: a golden Complete + Fresh scan still surfaces a `diagnostics` object, and
/// it is clean (no failed providers, no suppression, no confidence reduction).
#[test]
fn mcp_golden_scan_diagnostics_remain_clean() {
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

    let payload = list_findings_payload(workspace.path());
    let diagnostics = payload
        .get("diagnostics")
        .expect("diagnostics field present in golden payload");
    assert!(
        diagnostics["provider_statuses"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["reachable"] == serde_json::json!(true)),
        "golden diagnostics must show all providers reachable: {diagnostics}"
    );
    assert_eq!(diagnostics["scan_status"], serde_json::json!("COMPLETE"));
    assert_eq!(diagnostics["partial_reason"], serde_json::json!(null));
    assert!(diagnostics["suppressed"].as_array().unwrap().is_empty());
    assert!(diagnostics["reduced_confidence"]
        .as_array()
        .unwrap()
        .is_empty());

    let text = serde_json::to_string(&payload).expect("serializable payload");
    assert!(
        !text.contains(FAKE_TOKEN),
        "golden MCP diagnostics JSON leaked the synthetic token:\n{text}"
    );
}

/// Synthetic content sentinel for the runtime source store. It is placed only in
/// forbidden fields (`session.title`, `message.data`, `part.data.$.state.input`)
/// and must never reach the MCP payload.
const RUNTIME_SENTINEL: &str = "SENTINEL_S040_MCP";

/// Build a synthetic OpenCode-shaped store whose migration version is outside
/// Pico's supported range, so the opt-in runtime read fails closed and records
/// an honest `UNSUPPORTED` limitation. Forbidden tables/fields carry the
/// sentinel so the MCP sweep is meaningful.
fn seed_unsupported_runtime_store(home: &Path) {
    let dir = home.join(".local/share/opencode");
    fs::create_dir_all(&dir).unwrap();
    let conn = rusqlite::Connection::open(dir.join("opencode.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, time_created INTEGER, title TEXT);
         CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, data TEXT);
         CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER);
         CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO migration (id, time_completed) VALUES ('39', 0)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO session (id, directory, time_created, title) VALUES ('s1', '/tmp', 0, ?1)",
        [RUNTIME_SENTINEL],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO message (id, session_id, data) VALUES ('m1', 's1', ?1)",
        [RUNTIME_SENTINEL],
    )
    .unwrap();
    let data = format!(
        "{{\"type\":\"tool\",\"tool\":\"bash\",\"state\":{{\"input\":\"{RUNTIME_SENTINEL}\"}}}}"
    );
    conn.execute(
        "INSERT INTO part (id, session_id, time_created, data) VALUES ('p1', 's1', 0, ?1)",
        [data],
    )
    .unwrap();
}

/// The opt-in runtime limitation is projected over MCP with the same
/// `state`/`reason`/`migrations` the CLI renders. The CLI has no `findings`
/// JSON transport, so parity is asserted against the application DTO the CLI
/// renders from (and which is persisted) plus the CLI's rendered text: both
/// transports agree for the same diagnostics input.
#[test]
fn mcp_list_findings_surfaces_runtime_limitation_and_matches_cli() {
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    seed_unsupported_runtime_store(home.path());

    let result = ScanService::run_with_runtime(workspace.path(), Some(home.path()), true)
        .expect("opt-in runtime scan succeeds");
    let diagnostics = result
        .diagnostics_detail
        .as_ref()
        .expect("scan diagnostics are always populated");
    let expected = diagnostics
        .runtime
        .as_ref()
        .expect("an unsupported runtime store must record a limitation");
    assert_eq!(expected.state, "UNSUPPORTED");
    assert_eq!(expected.migrations, Some(39));

    // The CLI renders the same fact as human text ...
    let cli_text = render_scan_diagnostics(diagnostics);
    assert!(
        cli_text.contains("Runtime evidence: UNSUPPORTED"),
        "CLI must render the runtime limitation: {cli_text}"
    );
    assert!(
        cli_text.contains("observed migrations: 39"),
        "CLI must render the observed migration count: {cli_text}"
    );

    // ... and the decoded MCP payload exposes the same structured limitation.
    let payload = list_findings_payload(workspace.path());
    let runtime = payload["diagnostics"]
        .get("runtime")
        .expect("MCP must project the runtime limitation, not imply a clean runtime read");
    assert_eq!(runtime["state"], serde_json::json!("UNSUPPORTED"));
    assert_eq!(runtime["migrations"], serde_json::json!(39));
    assert_eq!(
        runtime,
        &serde_json::to_value(expected).expect("serializable runtime diagnostic"),
        "MCP runtime projection must equal the application DTO the CLI renders"
    );

    let text = serde_json::to_string(&payload).expect("serializable payload");
    assert!(
        !text.contains(RUNTIME_SENTINEL),
        "MCP payload leaked the runtime sentinel:\n{text}"
    );
}

/// R10: the provider problems embedded in the MCP diagnostics object never
/// contain the synthetic token (the token lives only in the fixture config).
#[test]
fn mcp_diagnostics_provider_problems_never_leak_token() {
    let workspace = setup(FAKE_TOKEN);
    let home = tempdir().unwrap();
    run(
        workspace.path(),
        home.path(),
        failing_provider(workspace.path(), home.path()),
    );
    let payload = list_findings_payload(workspace.path());
    let diagnostics = payload.get("diagnostics").expect("diagnostics present");
    for provider in diagnostics["provider_statuses"].as_array().unwrap() {
        for problem in provider["problems"].as_array().unwrap() {
            assert!(
                !problem.as_str().unwrap().contains(FAKE_TOKEN),
                "provider problem leaked the token: {problem}"
            );
        }
    }
}
