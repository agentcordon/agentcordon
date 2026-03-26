use axum::{routing::post, Json, Router};
use serde::Serialize;

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/mcp/proxy", post(mcp_proxy))
}

// --- Response types (kept for reference and tests) ---

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

/// Build a JSON-RPC error response.
fn jsonrpc_error(
    id: serde_json::Value,
    code: i32,
    message: impl Into<String>,
) -> Json<JsonRpcResponse> {
    Json(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
        }),
        id,
    })
}

/// MCP proxy has been deprecated — all MCP traffic now goes through the device.
///
/// Returns a 410 Gone-equivalent JSON-RPC error directing callers to the device endpoint.
async fn mcp_proxy(Json(req): Json<serde_json::Value>) -> Json<JsonRpcResponse> {
    let request_id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);

    jsonrpc_error(
        request_id,
        -32099,
        "MCP proxy has moved to the device. Send MCP requests to your device's /mcp/proxy endpoint.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_error_format() {
        let resp = jsonrpc_error(serde_json::Value::Number(1.into()), -32600, "bad request");
        assert_eq!(resp.0.jsonrpc, "2.0");
        assert!(resp.0.error.is_some());
        assert!(resp.0.result.is_none());
        let err = resp.0.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "bad request");
    }
}
