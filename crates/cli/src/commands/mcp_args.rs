//! Argument resolution for `agentcordon mcp-call`.
//!
//! Pure functions (file IO and stdin injected as `Read`) so the parsing and
//! merging behavior is unit-testable without spinning up the CLI binary.

use std::io::Read;

use crate::error::{CliError, ExitCode};

/// Resolve a `--args-json` spec into a JSON value.
///
/// `spec` is the literal argument passed by the user. `"-"` means read from
/// `stdin`. Other forms are added in later red-green cycles.
pub fn resolve_args_json<R: Read>(
    spec: &str,
    stdin: &mut R,
) -> Result<serde_json::Value, CliError> {
    let raw = if spec == "-" {
        let mut buf = String::new();
        stdin
            .read_to_string(&mut buf)
            .map_err(|e| CliError::general(format!("failed to read stdin: {e}")))?;
        buf
    } else if let Some(path) = spec.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| CliError::general(format!("failed to read {path}: {e}")))?
    } else {
        return Err(CliError::general(format!(
            "unsupported --args-json spec: {spec} (use @<path> or -)"
        )));
    };

    parse_args_object(&raw)
}

fn parse_args_object(raw: &str) -> Result<serde_json::Value, CliError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| CliError::general(format!("invalid JSON for --args-json: {e}")))?;

    if !value.is_object() {
        return Err(CliError::general(
            "--args-json must be a JSON object (the MCP tools/call arguments)".to_string(),
        ));
    }
    Ok(value)
}

/// Coerce a `--arg KEY=VALUE` string into a JSON value, matching the prior
/// auto-detection behavior of the CLI (int → float → bool → string).
fn coerce_kv_value(value: &str) -> serde_json::Value {
    if let Ok(n) = value.parse::<i64>() {
        serde_json::Value::Number(n.into())
    } else if let Ok(n) = value.parse::<f64>() {
        serde_json::Number::from_f64(n)
            .map(serde_json::Value::Number)
            .unwrap_or_else(|| serde_json::Value::String(value.to_string()))
    } else if value == "true" {
        serde_json::Value::Bool(true)
    } else if value == "false" {
        serde_json::Value::Bool(false)
    } else {
        serde_json::Value::String(value.to_string())
    }
}

/// Build the final MCP `arguments` object by overlaying `--arg KEY=VALUE`
/// entries on top of the optional `--args-json` body.
///
/// `--arg` always wins on conflict — agents can override individual fields of
/// a large pre-built body without re-serializing the whole object.
pub fn build_arguments(
    args_json: Option<serde_json::Value>,
    arg_kv: &[String],
) -> Result<serde_json::Value, CliError> {
    let mut obj = match args_json {
        Some(serde_json::Value::Object(m)) => m,
        Some(_) => {
            return Err(CliError::general(
                "--args-json must be a JSON object (the MCP tools/call arguments)".to_string(),
            ));
        }
        None => serde_json::Map::new(),
    };

    for arg in arg_kv {
        let (key, value) = arg.split_once('=').ok_or_else(|| {
            CliError::general(format!(
                "invalid argument format: {arg} (expected KEY=VALUE)"
            ))
        })?;
        obj.insert(key.to_string(), coerce_kv_value(value));
    }

    Ok(serde_json::Value::Object(obj))
}

/// Category of failure surfaced to an agent caller of `mcp-call`.
///
/// Stable wire identifiers per issue #26; agents branch on these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Caller-side problem: bad JSON, missing required field, wrong shape.
    ValidationError,
    /// The MCP tool was reached but returned an `isError: true` result.
    ToolError,
    /// Broker/transport problem (broker down, network, HTTP 5xx).
    TransportError,
    /// Authentication/authorization failure (HTTP 401/403).
    Unauthorized,
}

impl ErrorKind {
    fn as_wire(&self) -> &'static str {
        match self {
            ErrorKind::ValidationError => "validation_error",
            ErrorKind::ToolError => "tool_error",
            ErrorKind::TransportError => "transport_error",
            ErrorKind::Unauthorized => "unauthorized",
        }
    }
}

/// Map a `CliError` exit code to the agent-facing `ErrorKind`.
pub fn classify_cli_error(err: &CliError) -> ErrorKind {
    match err.code {
        ExitCode::AuthFailed | ExitCode::AuthorizationDenied => ErrorKind::Unauthorized,
        ExitCode::BrokerNotRunning | ExitCode::UpstreamError => ErrorKind::TransportError,
        ExitCode::NotRegistered
        | ExitCode::GeneralError
        | ExitCode::NoCredentialMatch
        | ExitCode::Success => ErrorKind::ValidationError,
    }
}

/// Build the agent-facing JSON error envelope (issue #26).
///
/// Stable wire shape: `{"error": {"kind", "tool", "message", "details"?}}`.
pub fn build_error_envelope(
    kind: ErrorKind,
    tool: Option<&str>,
    message: &str,
    details: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut err = serde_json::Map::new();
    err.insert(
        "kind".to_string(),
        serde_json::Value::String(kind.as_wire().to_string()),
    );
    if let Some(t) = tool {
        err.insert("tool".to_string(), serde_json::Value::String(t.to_string()));
    }
    err.insert(
        "message".to_string(),
        serde_json::Value::String(message.to_string()),
    );
    if let Some(d) = details {
        err.insert("details".to_string(), d);
    }
    serde_json::json!({ "error": serde_json::Value::Object(err) })
}

/// Filter a list of `{server, tool, ...}` JSON objects by optional server / tool name.
///
/// Used by `mcp-tools --schema` so an agent can scope the schema dump to one
/// server or one tool without parsing the full set.
pub fn filter_tools<'a>(
    tools: &'a [serde_json::Value],
    server: Option<&str>,
    tool: Option<&str>,
) -> Vec<&'a serde_json::Value> {
    tools
        .iter()
        .filter(|t| match server {
            Some(s) => t.get("server").and_then(|v| v.as_str()) == Some(s),
            None => true,
        })
        .filter(|t| match tool {
            Some(s) => t.get("tool").and_then(|v| v.as_str()) == Some(s),
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_auth_failed_maps_to_unauthorized() {
        let e = CliError::auth_failed("401 Unauthorized: bad token");
        assert_eq!(classify_cli_error(&e), ErrorKind::Unauthorized);
    }

    #[test]
    fn classify_authorization_denied_maps_to_unauthorized() {
        let e = CliError::authorization_denied("403 Forbidden: scope missing");
        assert_eq!(classify_cli_error(&e), ErrorKind::Unauthorized);
    }

    #[test]
    fn classify_broker_not_running_maps_to_transport() {
        let e = CliError::broker_not_running();
        assert_eq!(classify_cli_error(&e), ErrorKind::TransportError);
    }

    #[test]
    fn classify_upstream_error_maps_to_transport() {
        let e = CliError::upstream_error("502 Bad Gateway");
        assert_eq!(classify_cli_error(&e), ErrorKind::TransportError);
    }

    #[test]
    fn classify_general_error_maps_to_validation() {
        let e = CliError::general("invalid argument format");
        assert_eq!(classify_cli_error(&e), ErrorKind::ValidationError);
    }

    #[test]
    fn build_error_envelope_matches_spec_shape() {
        let env = build_error_envelope(
            ErrorKind::ValidationError,
            Some("push_files"),
            "--args-json must be a JSON object",
            None,
        );
        assert_eq!(
            env,
            serde_json::json!({
                "error": {
                    "kind": "validation_error",
                    "tool": "push_files",
                    "message": "--args-json must be a JSON object"
                }
            })
        );
    }

    #[test]
    fn args_json_dash_reads_object_from_stdin() {
        let mut stdin = std::io::Cursor::new(br#"{"hello":"world"}"#);
        let v = resolve_args_json("-", &mut stdin).unwrap();
        assert_eq!(v, serde_json::json!({"hello": "world"}));
    }

    fn sample_tools() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"server": "github", "tool": "push_files", "input_schema": {"type": "object"}}),
            serde_json::json!({"server": "github", "tool": "create_pr", "input_schema": {"type": "object"}}),
            serde_json::json!({"server": "notion",  "tool": "search",     "input_schema": {"type": "object"}}),
        ]
    }

    #[test]
    fn filter_tools_by_server_returns_only_that_servers_entries() {
        let tools = sample_tools();
        let result = filter_tools(&tools, Some("github"), None);
        assert_eq!(result.len(), 2);
        assert!(result
            .iter()
            .all(|t| t["server"].as_str() == Some("github")));
    }

    #[test]
    fn build_arguments_preserves_nested_arrays_unflattened() {
        // The push_files example from issue #26: an array of objects that the
        // old --arg KEY=VALUE flow stringified into a single quoted blob.
        let args_json = serde_json::json!({
            "owner": "a",
            "repo": "b",
            "files": [
                {"path": "x", "content": "1"},
                {"path": "y", "content": "2"}
            ]
        });
        let result = build_arguments(Some(args_json.clone()), &[]).unwrap();
        assert_eq!(result, args_json);
        assert_eq!(result["files"].as_array().unwrap().len(), 2);
        assert_eq!(result["files"][0]["path"], "x");
    }

    #[test]
    fn build_arguments_arg_kv_takes_precedence_over_args_json() {
        let args_json = serde_json::json!({"a": 1, "b": "x"});
        let arg_kv = vec!["b=overridden".to_string()];
        let result = build_arguments(Some(args_json), &arg_kv).unwrap();
        assert_eq!(result, serde_json::json!({"a": 1, "b": "overridden"}));
    }

    #[test]
    fn args_json_array_is_rejected_not_an_object() {
        let mut stdin = std::io::Cursor::new(br#"[1,2,3]"#);
        let err = resolve_args_json("-", &mut stdin).unwrap_err();
        assert!(
            err.message.contains("must be a JSON object"),
            "expected 'must be a JSON object' in error, got: {}",
            err.message
        );
    }

    #[test]
    fn args_json_at_path_reads_object_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("args.json");
        std::fs::write(&path, br#"{"k":"v","n":42}"#).unwrap();
        let spec = format!("@{}", path.display());
        let v = resolve_args_json(&spec, &mut std::io::empty()).unwrap();
        assert_eq!(v, serde_json::json!({"k":"v","n":42}));
    }
}
