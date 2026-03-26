//! Agent CRUD endpoint documentation.

use serde_json::json;

use super::{uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/agents".to_string(),
        description: "Create a new agent. Requires admin role. Returns the agent object. Note: agents are normally created via enrollment, not this endpoint.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "description": "Agent display name" },
                "description": { "type": "string", "description": "Optional description" },
                "tags": { "type": "array", "items": { "type": "string" }, "description": "Tags to assign (e.g., ['admin'])" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "agent": {
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
                },
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/agents".to_string(),
        description: "List all agents.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
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
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/agents/{id}".to_string(),
        description: "Get a single agent by ID.".to_string(),
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
        path_params: Some(vec![uuid_param("id", "Agent UUID")]),
        error_codes: vec!["unauthorized".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/agents/{id}".to_string(),
        description: "Update an agent. Requires admin role. Can update name, description, tags, and enabled status.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "description": { "type": "string" },
                "tags": { "type": "array", "items": { "type": "string" } },
                "enabled": { "type": "boolean" }
            }
        })),
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
        path_params: Some(vec![uuid_param("id", "Agent UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/agents/{id}".to_string(),
        description: "Delete an agent. Requires admin role. Cannot delete yourself.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Agent UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "conflict".to_string(),
        ],
    });
}
