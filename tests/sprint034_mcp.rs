//! Public history/diff parity through the actual CLI and MCP transports.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use pico::application::{InitService, PruneService, ScanService};
use pico::discovery::EnvironmentReachability;
use pico::domain::Scan;
use pico::mcp::{handle_line, tools};
use pico::persistence::{Database, ScanRepo};
use pico::shared::PICO_VERSION;
use serde_json::{json, Value};

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    InitService::run(dir.path()).unwrap();
    fs::write(
        dir.path().join("opencode.json"),
        r#"{"permission":{"bash":"allow"}}"#,
    )
    .unwrap();
    dir
}

fn scan(path: &Path) -> String {
    let home = tempfile::tempdir().unwrap();
    ScanService::run_with_home_and_environment(
        path,
        Some(home.path()),
        Some(&[]),
        EnvironmentReachability::Unknown,
    )
    .unwrap()
    .scan_id
}

fn call(path: &Path, name: &str, args: Option<Value>) -> Value {
    let mut request = json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":name}});
    if let Some(args) = args {
        request["params"]["arguments"] = args;
    }
    serde_json::from_str(&handle_line(&request.to_string(), path).unwrap()).unwrap()
}

fn cli(path: &Path, args: &[&str]) -> (bool, Value) {
    let result = Command::new(env!("CARGO_BIN_EXE_pico"))
        .args(args)
        .arg("--json")
        .current_dir(path)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&result.stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON: {e}; {:?}", result));
    (result.status.success(), value)
}

fn parity(path: &Path, name: &str, args: Value, cli_args: &[&str], success: bool) -> Value {
    let frame = call(path, name, Some(args));
    assert!(frame.get("error").is_none(), "{frame}");
    let payload: Value =
        serde_json::from_str(frame["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    let (ok, expected) = cli(path, cli_args);
    assert_eq!(ok, success);
    assert_eq!(payload, expected);
    assert_eq!(frame["result"]["isError"] == true, !success);
    payload
}

#[test]
fn descriptors_preserve_original_tools_and_append_read_only_queries() {
    let descriptors = tools::descriptors();
    assert_eq!(descriptors.len(), 4);
    assert_eq!(
        descriptors[0],
        json!({
            "name":"list_findings", "description":"List security Findings from the newest COMPLETE scan in this workspace.",
            "inputSchema":{"type":"object","properties":{},"additionalProperties":false}, "annotations":{"readOnlyHint":true}
        })
    );
    assert_eq!(
        descriptors[1],
        json!({
            "name":"get_finding", "description":"Get one persisted security Finding by its exact ID.",
            "inputSchema":{"type":"object","properties":{"id":{"type":"string","minLength":1}},"required":["id"],"additionalProperties":false},
            "annotations":{"readOnlyHint":true}
        })
    );
    assert_eq!(descriptors[2]["name"], "list_history");
    assert_eq!(descriptors[3]["name"], "diff_scans");
    for descriptor in &descriptors[2..] {
        assert_eq!(descriptor["annotations"]["readOnlyHint"], true);
        assert_eq!(descriptor["inputSchema"]["additionalProperties"], false);
    }
}

#[test]
fn history_and_diff_have_cli_parity_for_empty_one_and_ready_states() {
    let dir = workspace();
    for count in 0..=2 {
        let before = fs::read(dir.path().join(".pico/pico.db")).unwrap();
        parity(dir.path(), "list_history", json!({}), &["history"], true);
        let first = parity(dir.path(), "diff_scans", json!({}), &["diff"], true);
        let repeated = parity(dir.path(), "diff_scans", json!({}), &["diff"], true);
        assert_eq!(first, repeated);
        assert_eq!(fs::read(dir.path().join(".pico/pico.db")).unwrap(), before);
        if count < 2 {
            scan(dir.path());
        }
    }
}

#[test]
fn explicit_queries_and_pruned_missing_incomplete_reversed_ids_have_parity() {
    let dir = workspace();
    let oldest = scan(dir.path());
    let middle = scan(dir.path());
    let newest = scan(dir.path());
    parity(
        dir.path(),
        "diff_scans",
        json!({"from":oldest,"to":newest}),
        &["diff", &oldest, &newest],
        true,
    );
    for (from, to) in [(&newest, &oldest), (&newest, &newest)] {
        parity(
            dir.path(),
            "diff_scans",
            json!({"from":from,"to":to}),
            &["diff", from, to],
            false,
        );
    }
    PruneService::run(dir.path(), Some(2)).unwrap();
    parity(
        dir.path(),
        "diff_scans",
        json!({"from":oldest,"to":newest}),
        &["diff", &oldest, &newest],
        false,
    );
    parity(
        dir.path(),
        "diff_scans",
        json!({"from":middle,"to":newest}),
        &["diff", &middle, &newest],
        true,
    );
    let db = Database::open_existing(&dir.path().join(".pico/pico.db")).unwrap();
    let partial = Scan::start(PICO_VERSION).unwrap().partial().unwrap();
    ScanRepo::new(db.connection()).insert(&partial).unwrap();
    parity(
        dir.path(),
        "diff_scans",
        json!({"from":newest,"to":partial.id}),
        &["diff", &newest, &partial.id],
        false,
    );
    parity(dir.path(), "diff_scans", json!({}), &["diff"], true);
}

#[test]
fn contract_mismatch_is_a_successful_typed_result_in_both_transports() {
    let dir = workspace();
    let older = scan(dir.path());
    let newer = scan(dir.path());
    let db = Database::open_existing(&dir.path().join(".pico/pico.db")).unwrap();
    let mut row = ScanRepo::new(db.connection()).get(&newer).unwrap().unwrap();
    row.metadata.as_mut().unwrap()["comparison_contract_version"] = json!(999);
    ScanRepo::new(db.connection()).update(&row).unwrap();
    let result = parity(
        dir.path(),
        "diff_scans",
        json!({"from":older,"to":newer}),
        &["diff", &older, &newer],
        true,
    );
    assert_eq!(result["status"], "not_comparable");
}

#[test]
fn strict_parameters_fail_before_state_access_without_echoing_input() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["list_history", "diff_scans"] {
        for args in [
            Value::Null,
            json!([]),
            json!("SECRET_SENTINEL\u{1b}"),
            json!({"workspace":"SECRET_SENTINEL"}),
        ] {
            let frame = call(dir.path(), name, Some(args));
            assert_eq!(frame["error"]["code"], -32602);
            assert!(!frame.to_string().contains("SECRET_SENTINEL"));
        }
    }
    for args in [
        json!({"from":"SECRET_SENTINEL"}),
        json!({"to":"x"}),
        json!({"from":" ","to":"x"}),
        json!({"from":3,"to":"x"}),
        json!({"from":"x","to":"y","keep":2}),
    ] {
        assert_eq!(
            call(dir.path(), "diff_scans", Some(args))["error"]["code"],
            -32602
        );
    }
    assert!(!dir.path().join(".pico").exists());
}

#[test]
fn errors_are_redacted_and_missing_state_or_schema_is_read_only() {
    let dir = tempfile::tempdir().unwrap();
    parity(dir.path(), "list_history", json!({}), &["history"], false);
    parity(dir.path(), "diff_scans", json!({}), &["diff"], false);
    assert!(!dir.path().join(".pico").exists());
    InitService::run(dir.path()).unwrap();
    let result = parity(
        dir.path(),
        "diff_scans",
        json!({"from":"SECRET_SENTINEL\u{1b}","to":"x"}),
        &["diff", "SECRET_SENTINEL\u{1b}", "x"],
        false,
    );
    assert!(!result.to_string().contains("SECRET_SENTINEL"));
    let db = Database::open_existing(&dir.path().join(".pico/pico.db")).unwrap();
    db.connection()
        .pragma_update(None, "user_version", 999)
        .unwrap();
    let before = fs::read(dir.path().join(".pico/pico.db")).unwrap();
    parity(dir.path(), "list_history", json!({}), &["history"], false);
    parity(dir.path(), "diff_scans", json!({}), &["diff"], false);
    assert_eq!(fs::read(dir.path().join(".pico/pico.db")).unwrap(), before);
}

#[test]
fn stdio_new_queries_remain_json_rpc_frames_and_exit_on_eof() {
    let dir = workspace();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pico"))
        .arg("mcp")
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for (id, name) in [(1, "list_history"), (2, "diff_scans")] {
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name}})
        )
        .unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let frames: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(frames.len(), 2);
    for frame in frames {
        assert_eq!(frame["jsonrpc"], "2.0");
        assert!(frame["result"]["content"][0]["text"].is_string());
    }
}
