//! Minimal read-only MCP server over stdio (SPRINT-011.md §5-§7).
//!
//! Owns framing, envelope validation, method routing, and panic
//! containment only. Every tool call flows into FindingQueryService; no
//! scan, provider, network, or write surface is reachable from here.

pub mod protocol;
pub mod tools;

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::shared::PicoError;

/// Maximum accepted request line length in bytes (SPRINT-011.md §16).
/// Longer lines are discarded through their newline and answered once.
pub const MAX_REQUEST_LINE_BYTES: usize = 1_048_576;

/// Runs the stdio MCP session with the current directory as workspace.
pub fn run() -> Result<(), PicoError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    run_session(&mut input, &mut output).map_err(|error| PicoError::io(error.to_string()))
}

/// Runs one framed session until stdin EOF.
///
/// Responses are newline-delimited JSON-RPC frames on the output stream,
/// one per request, in request order. Notifications and blank lines
/// produce no frame. An unrecoverable output failure returns `Err`.
pub fn run_session(input: &mut dyn BufRead, output: &mut dyn Write) -> io::Result<()> {
    loop {
        match read_raw_line(input)? {
            RawLine::Eof => return Ok(()),
            RawLine::Oversized => write_frame(
                output,
                protocol::error_response(
                    Value::Null,
                    protocol::INVALID_REQUEST,
                    "request line exceeds maximum allowed length",
                )
                .to_string()
                .as_str(),
            )?,
            RawLine::Line(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let workspace = current_workspace();
                if let Some(response) = handle_line(&line, &workspace) {
                    write_frame(output, response.as_str())?;
                }
            }
        }
    }
}

/// Handles one request line purely: returns the response frame text, or
/// `None` when the frame must not be answered (notifications, blank lines).
pub fn handle_line(line: &str, workspace: &Path) -> Option<String> {
    if line.trim().is_empty() {
        return None;
    }
    let incoming = match protocol::parse(line) {
        Ok(incoming) => incoming,
        Err((id, code, message)) => {
            return Some(protocol::error_response(id, code, message).to_string())
        }
    };
    match incoming {
        protocol::Incoming::Notification { .. } => None,
        protocol::Incoming::Request { id, method, params } => {
            let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                dispatch(&method, &params, id.clone(), workspace)
            }))
            .unwrap_or_else(|_| {
                protocol::error_response(
                    id,
                    protocol::INTERNAL_ERROR,
                    protocol::INTERNAL_ERROR_MESSAGE,
                )
            });
            Some(response.to_string())
        }
    }
}

fn dispatch(method: &str, params: &Value, id: Value, workspace: &Path) -> Value {
    match method {
        "initialize" => protocol::result_response(id, protocol::initialize_result(params)),
        "ping" => protocol::result_response(id, json!({})),
        "tools/list" => protocol::result_response(id, json!({ "tools": tools::descriptors() })),
        "tools/call" => match tools::call(params, workspace) {
            Ok(result) => protocol::result_response(id, result),
            Err(error) => protocol::error_response(id, error.code, &error.message),
        },
        other => protocol::error_response(
            id,
            protocol::METHOD_NOT_FOUND,
            &format!("method not found: {other}"),
        ),
    }
}

enum RawLine {
    Eof,
    Line(String),
    Oversized,
}

fn read_raw_line(input: &mut dyn BufRead) -> io::Result<RawLine> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut oversized = false;
    let mut byte = [0u8; 1];
    loop {
        if input.read(&mut byte)? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            if oversized {
                return Ok(RawLine::Oversized);
            }
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return Ok(RawLine::Line(decode(bytes)));
        }
        if bytes.len() < MAX_REQUEST_LINE_BYTES {
            bytes.push(byte[0]);
        } else {
            oversized = true;
        }
    }
    if oversized {
        return Ok(RawLine::Oversized);
    }
    if bytes.is_empty() {
        Ok(RawLine::Eof)
    } else {
        Ok(RawLine::Line(decode(bytes)))
    }
}

fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8_lossy(&bytes).into_owned()
}

fn current_workspace() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn write_frame(output: &mut dyn Write, frame: &str) -> io::Result<()> {
    output.write_all(frame.as_bytes())?;
    output.write_all(b"\n")?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::application::InitService;
    use crate::shared::PICO_VERSION;

    fn initialized_workspace() -> tempfile::TempDir {
        let workspace = tempfile::tempdir().unwrap();
        InitService::run(workspace.path()).unwrap();
        workspace
    }

    fn response_of(line: &str, workspace: &Path) -> Option<Value> {
        handle_line(line, workspace).map(|text| serde_json::from_str(&text).unwrap())
    }

    #[test]
    fn initialize_echoes_supported_protocol_versions() {
        for version in ["2025-06-18", "2025-03-26", "2024-11-05"] {
            let workspace = initialized_workspace();
            let frame = response_of(
                &format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{version}"}}}}"#
                ),
                workspace.path(),
            )
            .unwrap();
            assert_eq!(frame["result"]["protocolVersion"], version);
            assert_eq!(frame["id"], 1);
        }
    }

    #[test]
    fn initialize_falls_back_to_latest_for_unsupported_versions() {
        let workspace = initialized_workspace();
        let frame = response_of(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(
            frame["result"]["protocolVersion"],
            protocol::LATEST_PROTOCOL_VERSION
        );
        let missing = response_of(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(
            missing["result"]["protocolVersion"],
            protocol::LATEST_PROTOCOL_VERSION
        );
    }

    #[test]
    fn initialize_reports_pico_server_info_and_tools_capability() {
        let workspace = initialized_workspace();
        let frame = response_of(
            r#"{"jsonrpc":"2.0","id":null,"method":"initialize","params":{}}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(frame["result"]["serverInfo"]["name"], "pico");
        assert_eq!(frame["result"]["serverInfo"]["version"], PICO_VERSION);
        assert_eq!(frame["result"]["capabilities"]["tools"], json!({}));
        assert!(frame["id"].is_null());
    }

    #[test]
    fn initialized_notification_produces_no_frame() {
        let workspace = initialized_workspace();
        assert_eq!(
            handle_line(
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                workspace.path()
            ),
            None
        );
        assert_eq!(
            handle_line(
                r#"{"jsonrpc":"2.0","method":"other/notification"}"#,
                workspace.path()
            ),
            None
        );
    }

    #[test]
    fn ping_returns_an_empty_result() {
        let workspace = initialized_workspace();
        let frame = response_of(
            r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(frame["result"], json!({}));
    }

    #[test]
    fn request_ids_of_any_json_type_are_echoed_exactly() {
        let workspace = initialized_workspace();
        for (id_literal, expected) in [
            ("null", serde_json::json!(null)),
            ("42", serde_json::json!(42)),
            ("\"abc\"", serde_json::json!("abc")),
            ("[1]", serde_json::json!([1])),
        ] {
            let frame = response_of(
                &format!(r#"{{"jsonrpc":"2.0","id":{id_literal},"method":"ping"}}"#),
                workspace.path(),
            )
            .unwrap();
            assert_eq!(frame["id"], expected);
        }
    }

    #[test]
    fn tools_list_exposes_exactly_two_read_only_tools_in_stable_order() {
        let workspace = initialized_workspace();
        let frame = response_of(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            workspace.path(),
        )
        .unwrap();
        let tools = frame["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "list_findings");
        assert_eq!(tools[1]["name"], "get_finding");
        for tool in tools {
            assert_eq!(tool["annotations"]["readOnlyHint"], true);
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
        assert_eq!(tools[1]["inputSchema"]["required"][0], "id");
        assert_eq!(
            tools[1]["inputSchema"]["properties"]["id"]["type"],
            "string"
        );
    }

    #[test]
    fn list_findings_on_a_scan_free_workspace_yields_the_no_scans_state() {
        let workspace = initialized_workspace();
        let frame = response_of(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{}}}"#,
            workspace.path(),
        )
        .unwrap();
        let text = frame["result"]["content"][0]["text"].as_str().unwrap();
        let payload: Value = serde_json::from_str(text).unwrap();
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
        assert_eq!(frame["result"]["content"][0]["type"], "text");
    }

    #[test]
    fn list_findings_accepts_missing_or_non_object_arguments() {
        let workspace = initialized_workspace();
        for params in [
            r#"{"name":"list_findings"}"#,
            r#"{"name":"list_findings","arguments":42}"#,
        ] {
            let frame = response_of(
                &format!(r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{params}}}"#),
                workspace.path(),
            )
            .unwrap();
            assert!(frame["result"]["content"][0]["text"].is_string());
        }
    }

    #[test]
    fn blank_get_finding_ids_map_to_invalid_params() {
        let workspace = initialized_workspace();
        for id in ["", "   "] {
            let frame = response_of(
                &format!(
                    r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"get_finding","arguments":{{"id":"{id}"}}}}}}"#
                ),
                workspace.path(),
            )
            .unwrap();
            assert_eq!(frame["error"]["code"], -32602);
            assert_eq!(
                frame["error"]["message"],
                "a non-empty Finding ID is required"
            );
        }
    }

    #[test]
    fn unknown_tools_and_methods_fail_safely() {
        let workspace = initialized_workspace();
        let unknown_tool = response_of(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scan"}}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(unknown_tool["error"]["code"], -32602);
        assert_eq!(unknown_tool["error"]["message"], "unknown tool: scan");

        let unknown_method = response_of(
            r#"{"jsonrpc":"2.0","id":6,"method":"resources/list"}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(unknown_method["error"]["code"], -32601);
        assert_eq!(
            unknown_method["error"]["message"],
            "method not found: resources/list"
        );
    }

    #[test]
    fn malformed_frames_yield_errors_without_touching_the_application() {
        let workspace = initialized_workspace();
        let parse_error = response_of("{not json", workspace.path()).unwrap();
        assert_eq!(parse_error["error"]["code"], -32700);
        assert!(parse_error["id"].is_null());

        let array_frame = response_of("[1,2,3]", workspace.path()).unwrap();
        assert_eq!(array_frame["error"]["code"], -32600);
        assert!(array_frame["id"].is_null());

        let scalar_frame = response_of("42", workspace.path()).unwrap();
        assert_eq!(scalar_frame["error"]["code"], -32600);

        let missing_jsonrpc = response_of(r#"{"id":9,"method":"ping"}"#, workspace.path()).unwrap();
        assert_eq!(missing_jsonrpc["error"]["code"], -32600);
        assert_eq!(missing_jsonrpc["id"], 9);

        let wrong_version = response_of(
            r#"{"jsonrpc":"1.0","id":10,"method":"ping"}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(wrong_version["error"]["code"], -32600);

        let missing_method = response_of(r#"{"jsonrpc":"2.0","id":11}"#, workspace.path()).unwrap();
        assert_eq!(missing_method["error"]["code"], -32600);

        let blank = handle_line("   \n", workspace.path());
        assert_eq!(blank, None);
    }

    #[test]
    fn repeated_list_findings_calls_are_byte_identical() {
        let workspace = initialized_workspace();
        let first = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings"}}"#,
            workspace.path(),
        )
        .unwrap();
        let second = handle_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings"}}"#,
            workspace.path(),
        )
        .unwrap();
        assert_eq!(first, second);
    }

    fn scripted(script: &str) -> String {
        let mut output = Vec::new();
        run_session(&mut Cursor::new(script.to_string()), &mut output).unwrap();
        String::from_utf8(output).unwrap()
    }

    #[test]
    fn oversized_lines_yield_one_error_and_the_session_continues() {
        let oversized = format!(
            "{{\"filler\":\"{}\"}}\n",
            "x".repeat(MAX_REQUEST_LINE_BYTES + 1)
        );
        let script = format!("{oversized}{{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"ping\"}}\n");
        let out = scripted(&script);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["error"]["code"], -32600);
        assert_eq!(
            first["error"]["message"],
            "request line exceeds maximum allowed length"
        );
        assert!(first["id"].is_null());
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["result"], json!({}));
        assert_eq!(second["id"], 21);
    }

    #[test]
    fn a_line_at_exact_maximum_is_parsed_normally() {
        let prefix = r#"{"jsonrpc":"2.0","id":1,"method":"ping","pad":""#;
        let suffix = r#""}"#;
        let line = format!(
            "{prefix}{}{suffix}",
            "x".repeat(MAX_REQUEST_LINE_BYTES - prefix.len() - suffix.len())
        );
        assert_eq!(line.len(), MAX_REQUEST_LINE_BYTES);
        let out = scripted(&format!("{line}\n"));
        let frame: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert_eq!(frame["id"], 1);
    }

    #[test]
    fn malformed_input_between_requests_keeps_the_session_alive() {
        let script = concat!(
            "{broken\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n",
        );
        let out = scripted(script);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["error"]["code"], -32700);
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["id"], 1);
    }
}
