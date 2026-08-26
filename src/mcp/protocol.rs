//! JSON-RPC 2.0 envelope parsing and response construction for the MCP
//! stdio surface (SPRINT-011.md §6).
//!
//! Contains no application logic: envelope classification, protocol-version
//! negotiation, and fixed error-code mapping only.

use serde_json::{json, Value};

use crate::shared::PICO_VERSION;

/// Malformed JSON that could not be decoded.
pub const PARSE_ERROR: i64 = -32700;
/// A frame that is not a valid JSON-RPC 2.0 envelope.
pub const INVALID_REQUEST: i64 = -32600;
/// A method outside the supported subset.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Invalid tool parameters or unknown tool.
pub const INVALID_PARAMS: i64 = -32602;
/// A handler panicked; the session continues.
pub const INTERNAL_ERROR: i64 = -32603;
/// An application failure reported by FindingQueryService.
pub const APPLICATION_ERROR: i64 = -32000;

pub const INTERNAL_ERROR_MESSAGE: &str = "internal error";

pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// A classified incoming frame.
pub enum Incoming {
    /// A request carrying an id of any JSON type, echoed verbatim.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// An id-less notification; never answered.
    Notification { method: String },
}

/// Parses one decoded line into a request or notification.
///
/// Errors carry the echoed id (when one was present), the JSON-RPC code,
/// and the fixed safe message.
pub fn parse(line: &str) -> Result<Incoming, (Value, i64, &'static str)> {
    let frame: Value =
        serde_json::from_str(line).map_err(|_| (Value::Null, PARSE_ERROR, "parse error"))?;
    let object = frame
        .as_object()
        .ok_or((Value::Null, INVALID_REQUEST, "invalid request"))?;
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((id, INVALID_REQUEST, "invalid request"));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Err((id, INVALID_REQUEST, "invalid request"));
    };
    let method = method.to_string();
    if object.contains_key("id") {
        Ok(Incoming::Request {
            id,
            method,
            params: object.get("params").cloned().unwrap_or(Value::Null),
        })
    } else {
        Ok(Incoming::Notification { method })
    }
}

/// Builds a success response echoing the exact request id.
pub fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Builds an error response echoing the exact request id.
pub fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Builds the initialize handshake result under the documented negotiation:
/// echo a supported requested version, otherwise fall back to the latest.
pub fn initialize_result(params: &Value) -> Value {
    let requested = params.get("protocolVersion").and_then(Value::as_str);
    let negotiated = match requested {
        Some(version) if SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => version,
        _ => LATEST_PROTOCOL_VERSION,
    };
    json!({
        "protocolVersion": negotiated,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "pico", "version": PICO_VERSION },
    })
}
