//! Sprint 011 MCP golden-workspace fixtures.
//!
//! These drive the two read-only tools over the controlled Sprint 010
//! provider seam and assert parity with `FindingQueryService` DTOs, exact
//! freshness/history/empty-state semantics, sentinel absence, control-
//! character containment, byte determinism, zero writes, and clean EOF
//! shutdown of the spawned binary. No network or provider call is involved.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::mcp::handle_line;
use pico::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    FindingPathRecord, FindingRepo, ResourceRepo, ScanRepo,
};
use pico::shared::PICO_VERSION;
use serde_json::{json, Value};
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const AUTH_HEADER_SENTINEL: &str = "TEST_AUTH_HEADER_SHOULD_NOT_APPEAR";
const INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
const INITIALIZED_NOTIFICATION: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const PING: &str = r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#;
const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
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

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    sink_impact: Option<&str>,
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
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: sink_impact.map(str::to_string),
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

fn scan_with_classification(
    classification: Option<&str>,
    script_name: &str,
) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            classification,
            script_name,
        )),
    )
    .unwrap();
    (workspace, result)
}

fn rescan_golden(workspace: &std::path::Path) -> ScanResult {
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace,
            home.path(),
            Some("PRODUCTION"),
            "checkout",
        )),
    )
    .unwrap()
}

fn open_rw(workspace: &std::path::Path) -> Database {
    Database::open_existing(&workspace.join(".pico").join("pico.db")).unwrap()
}

fn insert_newer_attempt(workspace: &std::path::Path, status: &str) -> String {
    let db = open_rw(workspace);
    let repo = ScanRepo::new(db.connection());
    let attempt = match status {
        "RUNNING" => pico::domain::Scan::start(pico::shared::PICO_VERSION).unwrap(),
        "PARTIAL" => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .partial()
            .unwrap(),
        "FAILED" => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .fail()
            .unwrap(),
        _ => panic!("unknown attempt status"),
    };
    repo.insert(&attempt).unwrap();
    drop(db);
    attempt.id
}

struct GoldenIds {
    scan_id: String,
    finding_id: String,
    path_id: String,
    source_id: String,
    actor_id: String,
    sink_id: String,
}

fn golden_ids(workspace: &std::path::Path) -> GoldenIds {
    let db = open_rw(workspace);
    let scan_id: String = db
        .connection()
        .query_row(
            "SELECT id FROM scans WHERE status = 'COMPLETE' ORDER BY started_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let finding_id: String = db
        .connection()
        .query_row("SELECT id FROM findings LIMIT 1", [], |row| row.get(0))
        .unwrap();
    let (path_id, source_id, actor_id, sink_id): (String, String, String, String) = db
        .connection()
        .query_row(
            "SELECT id, source_resource_id, actor_resource_id, sink_resource_id
             FROM attack_paths LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0).unwrap(),
                    row.get(1).unwrap(),
                    row.get(2).unwrap(),
                    row.get(3).unwrap(),
                ))
            },
        )
        .unwrap();
    drop(db);
    GoldenIds {
        scan_id,
        finding_id,
        path_id,
        source_id,
        actor_id,
        sink_id,
    }
}

/// Adds a second ACTIVE PRODUCTION path reusing every golden-path edge and
/// evidence row verbatim, so both paths end at the same Sink resource.
fn insert_same_sink_path(workspace: &std::path::Path, golden: &GoldenIds) {
    let new_path_id = format!("attack_path_mirror_{}", golden.scan_id);
    let db = open_rw(workspace);
    let paths = AttackPathRepo::new(db.connection());
    paths
        .insert(&AttackPathRecord {
            id: new_path_id.clone(),
            scan_id: golden.scan_id.clone(),
            fingerprint: "sha256:mirror-path-digest".to_string(),
            analysis_version: "1".to_string(),
            source_resource_id: golden.source_id.clone(),
            actor_resource_id: golden.actor_id.clone(),
            sink_resource_id: golden.sink_id.clone(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_RETRIEVABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            boundary_metadata: Some(json!([])),
            created_at: chrono::Utc::now(),
        })
        .unwrap();
    for edge in paths.list_edges(&golden.path_id).unwrap() {
        paths
            .insert_edge(&AttackPathEdgeRecord {
                attack_path_id: new_path_id.clone(),
                relationship_id: edge.relationship_id,
                position: edge.position,
                phase: edge.phase,
                traversal: edge.traversal,
            })
            .unwrap();
    }
    for item in paths.list_evidence(&golden.path_id).unwrap() {
        paths
            .insert_evidence(&AttackPathEvidenceRecord {
                attack_path_id: new_path_id.clone(),
                evidence_id: item.evidence_id,
                position: item.position,
                support_role: item.support_role,
            })
            .unwrap();
    }
    FindingRepo::new(db.connection())
        .insert_path(&FindingPathRecord {
            finding_id: golden.finding_id.clone(),
            attack_path_id: new_path_id,
            position: 1,
        })
        .unwrap();
}

fn list_call(id: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"list_findings"}}}}"#
    )
}

fn get_call(id: u64, finding_id: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"{finding_id}"}}}}}}"#
    )
}

fn handled(workspace: &Path, line: &str) -> Value {
    let text = handle_line(line, workspace).expect("request must produce a frame");
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("non-frame response {text:?}: {error}"))
}

fn raw_response(workspace: &Path, line: &str) -> String {
    handle_line(line, workspace).expect("request must produce a frame")
}

fn payload_of(frame: &Value) -> Value {
    let text = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(text).expect("tool payload JSON")
}

#[test]
fn golden_session_serves_list_and_detail_matching_the_query_service() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();

    let init = handled(ws, INITIALIZE);
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(init["result"]["serverInfo"]["name"], "pico");
    assert_eq!(init["result"]["serverInfo"]["version"], PICO_VERSION);

    assert_eq!(handled(ws, PING)["result"], json!({}));

    let tools = handled(ws, TOOLS_LIST)["result"]["tools"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "list_findings");
    assert_eq!(tools[1]["name"], "get_finding");
    for tool in &tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
    }

    let list_frame = handled(ws, &list_call(4));
    let payload = payload_of(&list_frame);
    let expected_list =
        serde_json::to_value(FindingQueryService::list_latest(ws).unwrap()).unwrap();
    let mut flattened = payload.as_object().expect("object payload").clone();
    let state = flattened.remove("state").expect("state field");
    let guidance = flattened.remove("guidance").expect("guidance field");
    assert_eq!(Value::Object(flattened), expected_list);

    assert_eq!(state, json!("RESULTS_AVAILABLE"));
    assert_eq!(
        guidance,
        json!(["Run get_finding with a listed ID to inspect it."])
    );
    assert_eq!(payload["freshness"], json!("LATEST_COMPLETE"));

    let finding_id = payload["findings"][0]["id"].as_str().unwrap().to_string();
    let detail_frame = handled(ws, &get_call(5, &finding_id));
    let detail = payload_of(&detail_frame);
    assert_eq!(
        detail,
        serde_json::to_value(FindingQueryService::get(ws, &finding_id).unwrap()).unwrap()
    );

    let reasons = detail["reasons"].as_array().unwrap();
    assert_eq!(reasons.len(), 6);
    let codes: Vec<&str> = reasons
        .iter()
        .map(|reason| reason["code"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        [
            "EXTERNAL_INFLUENCE_SOURCE",
            "AGENT_RETRIEVABLE_CONTENT",
            "AUTONOMOUS_EXECUTION_CAPABILITY",
            "REACHABLE_CREDENTIAL_AUTHORITY",
            "PRODUCTION_MUTATION_AUTHORITY",
            "NO_ENFORCED_BOUNDARY",
        ]
    );
    for (position, reason) in reasons.iter().enumerate() {
        assert_eq!(reason["position"], position);
        assert!(!reason["explanation"].as_str().unwrap().is_empty());
    }

    let path = &detail["paths"][0];
    let steps = path["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 5);
    let phases: Vec<&str> = steps
        .iter()
        .map(|step| step["phase"].as_str().unwrap())
        .collect();
    let traversals: Vec<&str> = steps
        .iter()
        .map(|step| step["traversal"].as_str().unwrap())
        .collect();
    assert_eq!(
        phases,
        [
            "INFLUENCE",
            "INFLUENCE",
            "AUTHORITY",
            "AUTHORITY",
            "AUTHORITY"
        ]
    );
    assert_eq!(
        traversals,
        ["REVERSE", "REVERSE", "FORWARD", "FORWARD", "FORWARD"]
    );

    assert_eq!(
        steps[0]["from_resource"]["id"], path["source_resource_id"],
        "chain starts at the declared source"
    );
    for pair in steps.windows(2) {
        assert_eq!(pair[0]["to_resource"]["id"], pair[1]["from_resource"]["id"]);
    }
    assert_eq!(
        steps.last().unwrap()["to_resource"]["id"],
        path["sink_resource_id"],
        "chain ends at the declared sink"
    );
    for (index, step) in steps.iter().enumerate() {
        assert!(
            !step["evidence_ids"].as_array().unwrap().is_empty(),
            "step {index} carries evidence"
        );
    }

    assert_eq!(
        detail["boundary_summary"],
        json!("No proven enforced boundary recorded for this scan interrupts this path.")
    );
    assert!(detail["scope_note"]
        .as_str()
        .unwrap()
        .contains("potential exposure"));
    assert_eq!(
        detail["remediation_note"],
        json!("Recommendations only. Pico did not apply these changes.")
    );
    let rule_ids: Vec<&str> = detail["remediations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|remediation| remediation["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        rule_ids,
        [
            "ENFORCE_BASH_APPROVAL_OR_DENY",
            "REMOVE_AGENT_CREDENTIAL_REACHABILITY",
            "RESTRICT_EXTERNAL_RETRIEVAL",
            "SCOPE_PRODUCTION_MUTATION_AUTHORITY",
        ]
    );
}

#[test]
fn newer_incomplete_attempts_surface_the_exact_freshness_warning() {
    for status in ["RUNNING", "PARTIAL", "FAILED"] {
        let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
        let ws = workspace.path();
        let attempt_id = insert_newer_attempt(ws, status);

        let payload = payload_of(&handled(ws, &list_call(4)));
        assert_eq!(payload["freshness"], json!("NEWER_INCOMPLETE_ATTEMPT"));
        let warning = format!(
            "Freshness: A newer scan {attempt_id} is {status}.\\x0AShowing the last COMPLETE scan; these results may not describe current state."
        );
        assert_eq!(payload["freshness_warning"], json!(warning));

        let finding_id = payload["findings"][0]["id"].as_str().unwrap();
        let detail = payload_of(&handled(ws, &get_call(5, finding_id)));
        assert_eq!(detail["freshness_warning"], json!(warning));
    }
}

#[test]
fn historical_finding_keeps_snapshot_names_through_get_finding() {
    let (workspace, first) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();
    let second = rescan_golden(ws);
    assert_ne!(first.scan_id, second.scan_id);

    let first_finding_id: String = {
        let db = open_rw(ws);
        db.connection()
            .query_row(
                "SELECT id FROM findings WHERE scan_id = ?1",
                [first.scan_id.as_str()],
                |row| row.get(0),
            )
            .unwrap()
    };

    let db = open_rw(ws);
    let resources = ResourceRepo::new(db.connection());
    let worker_key = "cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456";
    let mut worker = resources.get_by_canonical_key(worker_key).unwrap().unwrap();
    worker.name = "Renamed Worker".to_string();
    resources.upsert(&worker).unwrap();
    drop(db);

    let detail = payload_of(&handled(ws, &get_call(4, &first_finding_id)));
    assert_eq!(
        detail["currentness"],
        json!({ "HISTORICAL": { "newer_complete_scan_id": second.scan_id } })
    );
    let sink_step = detail["paths"][0]["steps"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(sink_step["to_resource"]["name"], json!("checkout"));
    assert_ne!(sink_step["to_resource"]["name"], json!("Renamed Worker"));

    let current_payload = payload_of(&handled(ws, &list_call(5)));
    assert_eq!(
        current_payload["selected_scan"]["id"],
        json!(second.scan_id)
    );
    let current_id = current_payload["findings"][0]["id"].as_str().unwrap();
    let current = payload_of(&handled(ws, &get_call(6, current_id)));
    assert_eq!(current["currentness"], json!("LATEST_COMPLETE"));
    let current_sink = current["paths"][0]["steps"]
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_ne!(current_sink["to_resource"]["name"], json!("Renamed Worker"));
    assert_eq!(current_sink["to_resource"]["name"], json!("checkout"));
}

#[test]
fn empty_states_carry_distinct_non_all_clear_guidance() {
    let initialized = tempdir().unwrap();
    InitService::run(initialized.path()).unwrap();
    let no_scans = payload_of(&handled(initialized.path(), &list_call(1)));
    assert_eq!(no_scans["state"], json!("NO_SCANS"));
    assert_eq!(
        no_scans["guidance"],
        json!([
            "No scans have been run yet in this workspace.",
            "Run `pico scan` to discover the paths agents create.",
        ])
    );

    let empty = tempdir().unwrap();
    InitService::run(empty.path()).unwrap();
    let scan = ScanService::run_with_home(empty.path(), None).unwrap();
    assert_eq!(scan.status, ScanStatus::Complete);
    let zero = payload_of(&handled(empty.path(), &list_call(2)));
    assert_eq!(zero["state"], json!("RESULTS_AVAILABLE"));
    assert!(zero["findings"].as_array().unwrap().is_empty());
    assert_eq!(
        zero["guidance"],
        json!(["No Findings were produced for this COMPLETE scan within Pico's supported scope."])
    );

    let attempts = tempdir().unwrap();
    InitService::run(attempts.path()).unwrap();
    let db = open_rw(attempts.path());
    let repo = ScanRepo::new(db.connection());
    repo.insert(&pico::domain::Scan::start(PICO_VERSION).unwrap())
        .unwrap();
    repo.insert(
        &pico::domain::Scan::start(PICO_VERSION)
            .unwrap()
            .partial()
            .unwrap(),
    )
    .unwrap();
    drop(db);
    let incomplete = payload_of(&handled(attempts.path(), &list_call(3)));
    assert_eq!(incomplete["state"], json!("NO_COMPLETE_SCAN"));
    assert_eq!(
        incomplete["newest_scan_attempt"]["status"],
        json!("PARTIAL")
    );
    assert!(incomplete["selected_scan"].is_null());
    assert_eq!(
        incomplete["guidance"],
        json!([
            "No COMPLETE scan exists in this workspace.",
            "This is not an all-clear; no authoritative scan exists.",
        ])
    );
}

#[test]
fn two_paths_reaching_one_sink_surface_through_both_tools() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();
    let golden = golden_ids(ws);
    insert_same_sink_path(ws, &golden);

    let payload = payload_of(&handled(ws, &list_call(4)));
    assert_eq!(payload["findings"][0]["attack_path_count"], json!(2));
    assert_eq!(payload["findings"][0]["affected_sink_count"], json!(1));

    let finding_id = payload["findings"][0]["id"].as_str().unwrap();
    let detail = payload_of(&handled(ws, &get_call(5, finding_id)));
    let paths = detail["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 2);
    assert_ne!(paths[0]["id"], paths[1]["id"]);
    for path in paths {
        assert_eq!(path["sink_resource_id"], json!(golden.sink_id));
    }
    assert_eq!(paths[0]["sink_resource_id"], paths[1]["sink_resource_id"]);
}

#[test]
fn secret_sentinels_never_appear_across_the_golden_session() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();

    let mut transcript = String::new();
    for line in [INITIALIZE, INITIALIZED_NOTIFICATION, PING, TOOLS_LIST] {
        if let Some(response) = handle_line(line, ws) {
            transcript.push_str(&response);
        }
    }
    let list_text = raw_response(ws, &list_call(4));
    transcript.push_str(&list_text);
    let payload = payload_of(&serde_json::from_str::<Value>(&list_text).unwrap());
    let finding_id = payload["findings"][0]["id"].as_str().unwrap();
    transcript.push_str(&raw_response(ws, &get_call(5, finding_id)));

    assert!(!transcript.contains(SECRET_SENTINEL));
    assert!(!transcript.contains(AUTH_HEADER_SENTINEL));
}

#[test]
fn control_characters_cannot_break_the_json_envelope() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();
    let finding_id = {
        let payload = payload_of(&handled(ws, &list_call(1)));
        payload["findings"][0]["id"].as_str().unwrap().to_string()
    };

    let spoofed = "\u{1b}[31mX\u{1b}[0m\nline2".to_string();
    {
        let db = open_rw(ws);
        db.connection()
            .execute("UPDATE findings SET title = ?1", [&spoofed])
            .unwrap();
    }

    let frame = raw_response(ws, &get_call(2, &finding_id));
    assert!(!frame.contains('\n'), "one single-line frame");
    assert!(!frame.contains('\u{1b}'), "no raw ESC byte in the frame");
    let parsed: Value = serde_json::from_str(&frame).expect("valid JSON frame");
    let text = parsed["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("\\\\x1B[31mX\\\\x1B[0m"),
        "DEBUG text was: {text}"
    );
    assert!(text.contains("\\\\x0Aline2"));
    let payload: Value = serde_json::from_str(text).expect("inner tool payload is valid JSON");
    assert_eq!(
        payload["title"],
        json!("\\x1B[31mX\\x1B[0m\\x0Aline2"),
        "decoded title is the terminal-safe escaped form"
    );
}

#[test]
fn sessions_are_byte_deterministic_and_write_nothing() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let ws = workspace.path();
    let db_path = ws.join(".pico").join("pico.db");
    let before = fs::read(&db_path).unwrap();

    let _init = handled(ws, INITIALIZE);
    let _ping = handled(ws, PING);
    let _tools = handled(ws, TOOLS_LIST);
    let finding_id = {
        let payload = payload_of(&handled(ws, &list_call(4)));
        payload["findings"][0]["id"].as_str().unwrap().to_string()
    };

    let list_first = raw_response(ws, &list_call(7));
    let list_second = raw_response(ws, &list_call(7));
    assert_eq!(list_first, list_second);
    let detail_first = raw_response(ws, &get_call(8, &finding_id));
    let detail_second = raw_response(ws, &get_call(8, &finding_id));
    assert_eq!(detail_first, detail_second);

    let after = fs::read(&db_path).unwrap();
    assert_eq!(before, after, "sessions perform zero database writes");
}

#[test]
fn spawned_binary_exits_cleanly_on_immediate_eof() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pico"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "expected exit code 0");
    assert!(
        output.stdout.is_empty(),
        "EOF without requests produces no frames"
    );
}
