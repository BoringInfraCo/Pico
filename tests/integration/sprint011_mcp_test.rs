//! Sprint 011 MCP protocol fixtures.
//!
//! These cover the stdio framing, JSON-RPC envelope handling, handshake
//! negotiation, tool descriptors, and the NO_SCANS dispatch path through an
//! initialized but scan-free workspace. Golden-workspace dispatch is Stage
//! 2 work. No network, provider, or write surface is involved.

use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use serde_json::{json, Value};

use pico::application::InitService;
use pico::mcp::{handle_line, run_session, MAX_REQUEST_LINE_BYTES};
use pico::shared::PICO_VERSION;

const INITIALIZE: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#;
const INITIALIZED_NOTIFICATION: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const TOOLS_LIST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
const PING: &str = r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#;

/// Serializes the single test allowed to change the process directory,
/// because run_session resolves the workspace from the cwd.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static CWD_LOCK: Mutex<()> = Mutex::new(());
    CWD_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn initialized_workspace() -> tempfile::TempDir {
    let workspace = tempfile::tempdir().unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn scripted(script: &str) -> String {
    let mut output = Vec::new();
    run_session(&mut Cursor::new(script.to_string()), &mut output).unwrap();
    String::from_utf8(output).unwrap()
}

fn scripted_at(workspace: &Path, script: &str) -> String {
    let previous = std::env::current_dir().unwrap();
    std::env::set_current_dir(workspace).unwrap();
    let out = scripted(script);
    std::env::set_current_dir(previous).unwrap();
    out
}

fn frames(output: &str) -> Vec<Value> {
    let mut parsed = Vec::new();
    for line in output.lines() {
        let frame: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("non-frame output line {line:?}: {error}"));
        assert_eq!(frame["jsonrpc"], "2.0");
        parsed.push(frame);
    }
    parsed
}

fn handled(workspace: &Path, line: &str) -> Option<Value> {
    handle_line(line, workspace).map(|text| {
        let frame: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("non-frame response {text:?}: {error}"));
        frame
    })
}

fn list_payload_text(frame: &Value) -> String {
    frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_string()
}

#[test]
fn golden_stdio_session_completes_initialize_tools_list_and_list_findings() {
    let _guard = cwd_lock();
    let workspace = initialized_workspace();
    let list_call =
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings"}}"#;
    let script =
        format!("{INITIALIZE}\n{INITIALIZED_NOTIFICATION}\n{PING}\n{TOOLS_LIST}\n{list_call}\n");
    let out = scripted_at(workspace.path(), &script);

    let session = frames(&out);
    assert_eq!(session.len(), 4, "the notification produces no frame");

    assert_eq!(session[0]["id"], 1);
    assert_eq!(session[0]["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(session[0]["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(session[0]["result"]["serverInfo"]["name"], "pico");
    assert_eq!(session[0]["result"]["serverInfo"]["version"], PICO_VERSION);

    assert_eq!(session[1]["id"], 3);
    assert_eq!(session[1]["result"], json!({}));

    let tools = session[2]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "list_findings");
    assert_eq!(tools[1]["name"], "get_finding");
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["inputSchema"]["additionalProperties"], false);
    }
    assert_eq!(tools[1]["inputSchema"]["required"][0], "id");

    let payload: Value =
        serde_json::from_str(list_payload_text(&session[3]).as_str()).expect("payload JSON");
    assert_eq!(payload["state"], "NO_SCANS");
    assert_eq!(
        payload["guidance"],
        json!([
            "No scans have been run yet in this workspace.",
            "Run `pico scan` to discover the paths agents create.",
        ])
    );
    assert_eq!(payload["freshness"], "LATEST_COMPLETE");
    assert!(payload["selected_scan"].is_null());
    assert!(payload["findings"].as_array().unwrap().is_empty());
}

#[test]
fn unsupported_requested_versions_fall_back_to_the_latest_supported() {
    for requested in ["1999-01-01", "2999-12-31"] {
        let script = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{requested}"}}}}"#
        );
        let session = frames(&scripted(&format!("{script}\n")));
        assert_eq!(
            session[0]["result"]["protocolVersion"],
            pico::mcp::protocol::LATEST_PROTOCOL_VERSION
        );
        assert_eq!(session[0]["result"]["serverInfo"]["version"], PICO_VERSION);
    }
}

#[test]
fn handled_sequence_preserves_order_and_repeats_are_byte_identical_with_zero_writes() {
    let workspace = initialized_workspace();
    let db_path = workspace.path().join(".pico").join("pico.db");
    let before = fs::read(&db_path).unwrap();

    let list_call =
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_findings"}}"#;
    let first = handled(workspace.path(), INITIALIZE).unwrap();
    let second = handled(workspace.path(), TOOLS_LIST).unwrap();
    let third = handled(workspace.path(), list_call).unwrap();
    let fourth = handled(workspace.path(), list_call).unwrap();

    let ids: Vec<Value> = [first, second, third.clone(), fourth.clone()]
        .iter()
        .map(|frame| frame["id"].clone())
        .collect();
    assert_eq!(ids, vec![json!(1), json!(2), json!(4), json!(4)]);
    assert_eq!(list_payload_text(&third), list_payload_text(&fourth));

    let payload: Value =
        serde_json::from_str(list_payload_text(&third).as_str()).expect("payload JSON");
    assert_eq!(payload["state"], "NO_SCANS");
    assert_eq!(
        payload["guidance"],
        json!([
            "No scans have been run yet in this workspace.",
            "Run `pico scan` to discover the paths agents create.",
        ])
    );

    let after = fs::read(&db_path).unwrap();
    assert_eq!(before, after, "sessions perform zero database writes");
}

#[test]
fn negative_protocol_battery_survives_one_session() {
    // None of these frames reaches the query layer, so any workspace state
    // (here: initialized and scan-free) must stay untouched.
    let _workspace = initialized_workspace();
    let script = concat!(
        "{\"broken\",\n",
        "[1, 2, 3]\n",
        r#"{"id":8,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"get_finding","arguments":{"id":"   "}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"scan"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":11,"method":"sampling/createMessage"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        "\n",
    );
    let session = frames(&scripted(script));
    assert_eq!(session.len(), 7, "only requests are answered");
    assert_eq!(session[0]["error"]["code"], -32700);
    assert!(session[0]["id"].is_null());

    assert_eq!(session[1]["error"]["code"], -32600);
    assert!(session[1]["id"].is_null());

    assert_eq!(session[2]["error"]["code"], -32600);
    assert_eq!(session[2]["id"], 8);

    assert_eq!(session[3]["error"]["code"], -32602);
    assert_eq!(
        session[3]["error"]["message"],
        "a non-empty Finding ID is required"
    );

    assert_eq!(session[4]["error"]["code"], -32602);
    assert_eq!(session[4]["error"]["message"], "unknown tool: scan");

    assert_eq!(session[5]["error"]["code"], -32601);

    assert_eq!(session[6]["result"], json!({}));
    assert!(session[6]["id"].is_null(), "null ids are echoed verbatim");
}

#[test]
fn oversized_request_lines_are_bounded_and_recoverable() {
    let oversized = format!(
        "{{\"filler\":\"{}\"}}\n",
        "x".repeat(MAX_REQUEST_LINE_BYTES + 1)
    );
    let script = format!("{{\"filler\":2}}\n{oversized}{PING}\n");
    let session = frames(&scripted(&script));
    assert_eq!(session.len(), 3);

    assert_eq!(
        session[0]["error"]["code"], -32600,
        "missing envelope fields"
    );
    assert!(session[0]["id"].is_null());

    assert_eq!(session[1]["error"]["code"], -32600);
    assert_eq!(
        session[1]["error"]["message"],
        "request line exceeds maximum allowed length"
    );
    assert!(session[1]["id"].is_null());

    assert_eq!(session[2]["id"], 3);
    assert_eq!(session[2]["result"], json!({}));
}

#[test]
fn responses_preserve_request_order_ids_and_output_carries_only_frames() {
    let script = concat!(
        r#"{"jsonrpc":"2.0","id":"alpha","method":"ping"}"#,
        "\n",
        "\n",
        r#"{"jsonrpc":"2.0","id":[7],"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":99,"method":"nope"}"#,
        "\n",
    );
    let out = scripted(script);
    assert!(
        !out.contains("\n\n"),
        "blank input lines must not become blank output lines"
    );
    let session = frames(&out);
    let ids: Vec<Value> = session.iter().map(|frame| frame["id"].clone()).collect();
    assert_eq!(
        ids,
        vec![json!("alpha"), json!([7]), json!(99)],
        "responses preserve request ids and order"
    );
}

#[test]
fn eof_ends_the_session_cleanly_with_no_output() {
    let out = scripted("");
    assert_eq!(out, "");
}

#[test]
fn mcp_sources_are_structurally_free_of_scan_and_provider_machinery() {
    let mcp_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("mcp");
    let mut sources = String::new();
    for entry in fs::read_dir(&mcp_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            sources.push_str(&fs::read_to_string(&path).unwrap());
        }
    }
    for token in ["ScanService", "discover_with_environment", "ProviderResult"] {
        assert!(
            !sources.contains(token),
            "{token} must be unreachable from src/mcp"
        );
    }
}
