//! The JSON-RPC 2.0 framing `mcp-serve` speaks, and nothing more.
//!
//! MCP's stdio transport is "messages are individual JSON-RPC requests,
//! notifications, or responses, delimited by newlines, and MUST NOT contain
//! embedded newlines" (MCP 2025-06-18, *Transports* § stdio). That is small
//! enough to write out, and writing it out is what keeps this server free of
//! an SDK dependency for a surface of six tools.

use serde_json::{json, Value};

/// The protocol revision this server implements.
pub(crate) const PROTOCOL_VERSION: &str = "2025-06-18";

/// Revisions whose `initialize` this server answers in kind. A client that
/// asks for one of these gets it back; anything else gets
/// [`PROTOCOL_VERSION`], which is the spec's "respond with the latest
/// version you support" rule.
const KNOWN_PROTOCOL_VERSIONS: [&str; 3] = [PROTOCOL_VERSION, "2025-03-26", "2024-11-05"];

/// The version to answer `initialize` with, given what the client asked for.
pub(crate) fn negotiated_version(requested: Option<&str>) -> &'static str {
    requested
        .and_then(|r| KNOWN_PROTOCOL_VERSIONS.into_iter().find(|k| *k == r))
        .unwrap_or(PROTOCOL_VERSION)
}

/// JSON-RPC error codes, as the MCP spec uses them.
pub(crate) const PARSE_ERROR: i64 = -32700;
pub(crate) const INVALID_REQUEST: i64 = -32600;
pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
/// Unknown tool, or arguments that are not the shape the tool declared.
pub(crate) const INVALID_PARAMS: i64 = -32602;

/// One decoded message from the client.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// A notification carries no id, so it is never answered.
    Notification { method: String },
}

/// Decode one line from stdin.
///
/// `Err(Some(response))` is the error to write back; `Err(None)` is a line
/// with nothing to answer — a blank line, or a response to a request this
/// server never made.
pub(crate) fn decode(line: &str) -> Result<Incoming, Option<Value>> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(None);
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return Err(Some(error(
                Value::Null,
                PARSE_ERROR,
                format!("invalid JSON: {e}"),
            )))
        }
    };

    // A response to a request this server never made. It is not ours to
    // answer: this server sends notifications, never requests, so replying
    // would put an unpaired message on the channel.
    if value.get("result").is_some() || value.get("error").is_some() {
        return Err(None);
    }

    let id = value.get("id").cloned().filter(|v| !v.is_null());
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return match id {
            Some(id) => Err(Some(error(
                id,
                INVALID_REQUEST,
                "not a JSON-RPC request: no method".to_string(),
            ))),
            None => Err(None),
        };
    };
    let params = value.get("params").cloned().unwrap_or_else(|| json!({}));

    match id {
        Some(id) => Ok(Incoming::Request {
            id,
            method: method.to_string(),
            params,
        }),
        None => Ok(Incoming::Notification {
            method: method.to_string(),
        }),
    }
}

/// A successful response to `id`.
pub(crate) fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// An error response to `id`.
pub(crate) fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

/// A notification, which has no id and is never answered.
pub(crate) fn notification(method: &str) -> Value {
    json!({ "jsonrpc": "2.0", "method": method })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_decodes_to_its_id_method_and_params() {
        let decoded = decode(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1}}"#);
        assert_eq!(
            decoded,
            Ok(Incoming::Request {
                id: json!(1),
                method: "ping".into(),
                params: json!({"a": 1}),
            })
        );
    }

    /// A string id is as valid as a number, and must come back unchanged.
    #[test]
    fn an_id_is_echoed_in_whatever_type_it_arrived_as() {
        let Ok(Incoming::Request { id, .. }) = decode(r#"{"id":"abc","method":"ping"}"#) else {
            panic!("expected a request");
        };
        assert_eq!(result(id, json!({}))["id"], json!("abc"));
    }

    /// Missing `params` is an empty object, not a failure: `ping` and
    /// `tools/list` are routinely sent without any.
    #[test]
    fn absent_params_default_to_an_empty_object() {
        let Ok(Incoming::Request { params, .. }) = decode(r#"{"id":1,"method":"tools/list"}"#)
        else {
            panic!("expected a request");
        };
        assert_eq!(params, json!({}));
    }

    #[test]
    fn a_message_without_an_id_is_a_notification() {
        assert_eq!(
            decode(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Ok(Incoming::Notification {
                method: "notifications/initialized".into()
            })
        );
    }

    /// A null id is the absent id, per JSON-RPC.
    #[test]
    fn a_null_id_is_a_notification() {
        assert!(matches!(
            decode(r#"{"jsonrpc":"2.0","id":null,"method":"notifications/x"}"#),
            Ok(Incoming::Notification { .. })
        ));
    }

    #[test]
    fn unparseable_json_is_a_parse_error_with_a_null_id() {
        let Err(Some(response)) = decode("{not json") else {
            panic!("expected an error response");
        };
        assert_eq!(response["error"]["code"], PARSE_ERROR);
        assert_eq!(response["id"], Value::Null);
    }

    /// A blank line is skipped rather than answered: an empty line is not a
    /// message, and a parse error for one would be noise on the channel.
    #[test]
    fn a_blank_line_is_ignored() {
        assert_eq!(decode("   "), Err(None));
    }

    /// A response to something this server never asked is not ours to
    /// answer; answering it would put an unpaired message on the channel.
    #[test]
    fn a_response_from_the_client_is_ignored() {
        assert_eq!(decode(r#"{"jsonrpc":"2.0","id":9,"result":{}}"#), Err(None));
        assert_eq!(
            decode(r#"{"jsonrpc":"2.0","id":9,"error":{"code":-1,"message":"x"}}"#),
            Err(None)
        );
    }

    /// Something with an id that is neither a request nor a response gets
    /// the JSON-RPC answer for exactly that.
    #[test]
    fn an_identified_message_with_no_method_is_an_invalid_request() {
        let Err(Some(response)) = decode(r#"{"jsonrpc":"2.0","id":9,"parms":{}}"#) else {
            panic!("expected an error response");
        };
        assert_eq!(response["error"]["code"], INVALID_REQUEST);
        assert_eq!(response["id"], json!(9));
    }

    #[test]
    fn the_negotiated_version_echoes_a_known_request_and_otherwise_says_ours() {
        assert_eq!(negotiated_version(Some("2025-06-18")), "2025-06-18");
        assert_eq!(negotiated_version(Some("2024-11-05")), "2024-11-05");
        assert_eq!(negotiated_version(Some("1999-01-01")), PROTOCOL_VERSION);
        assert_eq!(negotiated_version(None), PROTOCOL_VERSION);
    }

    /// The transport forbids an embedded newline in a message, and a tool
    /// result routinely carries one in its text. `serde_json` escapes it;
    /// this is the test that says so, because the whole framing rests on it.
    #[test]
    fn a_rendered_message_is_one_line_however_many_the_payload_has() {
        let rendered = serde_json::to_string(&result(
            json!(1),
            json!({"content": [{"type": "text", "text": "first\nsecond"}]}),
        ))
        .unwrap();
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        assert!(rendered.contains("first\\nsecond"), "{rendered}");
    }
}
