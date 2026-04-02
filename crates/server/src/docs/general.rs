//! General endpoint documentation: health, auth, audit, demo, proxy,
//! device SSE, self-referential docs, and admin endpoints.

use serde_json::json;

use super::{integer_param, string_param, uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // -----------------------------------------------------------------------
    // Health
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/health".to_string(),
        description: "Health check endpoint. Returns 200 if the server is running.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": { "status": { "type": "string", "enum": ["ok"] } }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![],
    });

    // -----------------------------------------------------------------------
    // Auth
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/auth/whoami".to_string(),
        description: "Return the authenticated agent's identity. Useful for verifying authentication and inspecting tags.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "description": { "type": "string", "nullable": true },
                "tags": { "type": "array", "items": { "type": "string" } },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });

    // -----------------------------------------------------------------------
    // Audit
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/audit".to_string(),
        description: "List audit events. Admins can see all events. Non-admins can only filter by credential resources they own.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "timestamp": { "type": "string", "format": "date-time" },
                    "correlation_id": { "type": "string" },
                    "event_type": { "type": "string" },
                    "agent_id": { "type": "string", "format": "uuid", "nullable": true },
                    "agent_name": { "type": "string", "nullable": true },
                    "action": { "type": "string" },
                    "resource_type": { "type": "string" },
                    "resource_id": { "type": "string", "nullable": true },
                    "decision": { "type": "string" },
                    "decision_reason": { "type": "string", "nullable": true },
                    "metadata": { "type": "object" }
                }
            }
        })),
        query_params: Some(vec![
            integer_param("limit", "Maximum number of events to return (default: 50)"),
            integer_param("offset", "Number of events to skip (default: 0)"),
            string_param("resource_type", "Filter by resource type (e.g., 'credential', 'agent')", false),
            string_param("resource_id", "Filter by resource ID (UUID)", false),
            string_param("source", "Filter by source: 'device', 'server', or 'all' (default: all)", false),
            string_param("action", "Filter by action name (e.g., 'create', 'delete')", false),
            string_param("decision", "Filter by decision (e.g., 'permit', 'forbid')", false),
            string_param("event_type", "Filter by event type (e.g., 'agent_created', 'credential_created')", false),
            string_param("agent_id", "Filter by workspace ID (UUID)", false),
            string_param("agent_name", "Filter by agent name", false),
            string_param("user_id", "Filter by user ID", false),
            string_param("device_id", "Filter by device ID (UUID)", false),
        ]),
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/audit/{id}".to_string(),
        description: "Get a single audit event by ID with full detail. Requires view_audit policy permission.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "timestamp": { "type": "string", "format": "date-time" },
                "correlation_id": { "type": "string" },
                "event_type": { "type": "string" },
                "agent_id": { "type": "string", "format": "uuid", "nullable": true },
                "agent_name": { "type": "string", "nullable": true },
                "user_id": { "type": "string", "nullable": true },
                "user_name": { "type": "string", "nullable": true },
                "action": { "type": "string" },
                "resource_type": { "type": "string" },
                "resource_id": { "type": "string", "nullable": true },
                "decision": { "type": "string" },
                "decision_reason": { "type": "string", "nullable": true },
                "metadata": { "type": "object" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Audit event UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    // -----------------------------------------------------------------------
    // Device SSE Events
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/devices/events".to_string(),
        description: "SSE event stream for device push notifications. Authenticated via device JWT. Streams events relevant to the authenticated device. Events include: mcp_config_changed, agent_status_changed, credential_rotated, workspace_revoked, policy_changed, permission_changed. The policy_changed event is emitted when a Cedar policy is created, updated, or deleted, enabling devices to immediately re-sync their policy set. The permission_changed event is emitted when a credential permission is granted, revoked, or set for an agent.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "text/event-stream",
            "description": "Server-Sent Events stream",
            "event_types": {
                "mcp_config_changed": {
                    "description": "MCP server configuration created/updated/deleted",
                    "payload": { "device_id": "uuid|null", "server_name": "string" }
                },
                "agent_status_changed": {
                    "description": "Agent enabled/disabled",
                    "payload": { "device_id": "uuid", "agent_id": "uuid" }
                },
                "credential_rotated": {
                    "description": "Credential secret rotated",
                    "payload": { "credential_name": "string" }
                },
                "workspace_revoked": {
                    "description": "Workspace identity revoked",
                    "payload": { "workspace_identity_id": "uuid", "pk_hash": "string" }
                },
                "policy_changed": {
                    "description": "Cedar policy created/updated/deleted — triggers immediate sync_policies() on device",
                    "payload": { "policy_name": "string" }
                },
                "permission_changed": {
                    "description": "Credential permission granted/revoked/set for an agent — triggers permission cache invalidation on device",
                    "payload": { "agent_id": "uuid" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });

    // -----------------------------------------------------------------------
    // Docs (self-referential)
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/docs".to_string(),
        description: "Get comprehensive machine-readable API documentation. No authentication required. Returns raw JSON (not wrapped in the standard ApiResponse envelope).".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "description": "Full API documentation including server info, auth methods, all endpoints, error format, and proxy guide."
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/docs/quickstart".to_string(),
        description: "Get a concise getting-started guide for agents. No authentication required. Returns raw JSON (not wrapped in the standard ApiResponse envelope). Covers authentication, proxy usage, and error handling.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "authentication": { "type": "object", "description": "How to authenticate" },
                "proxy": { "type": "object", "description": "How to use the credential proxy" },
                "errors": { "type": "object", "description": "Error format and codes" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![],
    });

    // -----------------------------------------------------------------------
    // Admin
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/admin/rotate-key".to_string(),
        description: "Re-encrypt all stored credentials under the current encryption key. Use after rotating the AGTCRDN_ENCRYPTION_KEY environment variable. Requires admin user (Cedar policy: rotate_encryption_key on System). Agent JWTs are rejected.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "re_encrypted_count": { "type": "integer", "description": "Number of credentials successfully re-encrypted" },
                "total_credentials": { "type": "integer", "description": "Total credentials processed" },
                "errors": { "type": "array", "items": { "type": "string" }, "description": "Per-credential error messages (if any)" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });
}
