//! Enrollment endpoint documentation (workspace registration flow).

use serde_json::json;

use super::{string_param, EndpointDoc};
use crate::config::AppConfig;

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>, config: &AppConfig) {
    // -----------------------------------------------------------------------
    // Enrollment v2 (Device Flow) — PREFERRED
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/enroll".to_string(),
        description: format!(
            "Initiate workspace enrollment. {}. Returns a session token for polling and an approval URL for the admin to open in their browser.",
            if config.enrollment_enabled { "Enrollment is currently ENABLED" } else { "Enrollment is currently DISABLED" }
        ),
        auth_required: false,
        request_body: Some(json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "description": "Requested agent name (1-128 characters, must not contain <>&'\" characters)" },
                "description": { "type": "string", "description": "Optional agent description" },
                "tags": { "type": "array", "items": { "type": "string" }, "description": "Requested tags" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "session_token": { "type": "string", "description": "64-char hex token for polling status" },
                "approval_url": { "type": "string", "description": "URL for admin to open in browser for approval" },
                "approval_code": { "type": "string", "description": "Human-readable code (e.g. HAWK-7829) for verification" },
                "poll_url": { "type": "string", "description": "URL to poll for status" },
                "expires_in": { "type": "integer", "description": "Seconds until session expires" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["forbidden".to_string(), "bad_request".to_string(), "too_many_requests".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/enroll/session/{session_token}/status".to_string(),
        description: "Poll enrollment session status. No auth required. On first poll after approval, returns the agent_id and transitions to 'claimed'.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["pending", "approved", "claimed", "denied", "expired"] },
                "agent_id": { "type": "string", "format": "uuid", "nullable": true },
                "token_endpoint": { "type": "string", "nullable": true }
            }
        })),
        query_params: None,
        path_params: Some(vec![string_param("session_token", "Session token (64 hex chars)", true)]),
        error_codes: vec!["not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/enroll/approve".to_string(),
        description: "Approve an enrollment session. Requires admin role. Creates the agent, which the device can then claim on its next poll.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["approval_ref"],
            "properties": {
                "approval_ref": { "type": "string", "description": "Approval reference from the enrollment session" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "approved": { "type": "boolean" },
                "agent_id": { "type": "string", "format": "uuid" },
                "agent_name": { "type": "string" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/enroll/deny".to_string(),
        description: "Deny an enrollment session. Requires admin role.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["approval_ref"],
            "properties": {
                "approval_ref": { "type": "string", "description": "Approval reference from the enrollment session" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": { "denied": { "type": "boolean" } }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/enroll/sessions".to_string(),
        description: "List pending enrollment sessions. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "approval_ref": { "type": "string" },
                    "approval_code": { "type": "string" },
                    "agent_name": { "type": "string" },
                    "agent_description": { "type": "string", "nullable": true },
                    "agent_tags": { "type": "array", "items": { "type": "string" } },
                    "status": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "expires_at": { "type": "string", "format": "date-time" },
                    "client_ip": { "type": "string", "nullable": true }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });
}
