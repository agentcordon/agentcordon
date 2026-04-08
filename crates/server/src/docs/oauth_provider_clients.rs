//! MCP OAuth Apps endpoint documentation.

use serde_json::json;

use super::{uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // POST /api/v1/oauth-provider-clients
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/oauth-provider-clients".to_string(),
        description: "Create an MCP OAuth App configuration. Server-wide admin setting \
            for OAuth2 app registrations (client_id/client_secret) used by MCP marketplace \
            templates. Requires manage_mcp_servers policy. Client secret is encrypted at rest."
            .to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["template_key", "name", "client_id", "client_secret", "authorize_url", "token_url"],
            "properties": {
                "template_key": { "type": "string", "description": "MCP template key (e.g., 'notion'). One app per template." },
                "name": { "type": "string", "description": "Display name (e.g., 'Notion OAuth App')" },
                "client_id": { "type": "string", "description": "OAuth2 client ID from the service provider" },
                "client_secret": { "type": "string", "description": "OAuth2 client secret (encrypted at rest)" },
                "authorize_url": { "type": "string", "description": "OAuth2 authorization endpoint URL (HTTPS required)" },
                "token_url": { "type": "string", "description": "OAuth2 token endpoint URL (HTTPS required)" },
                "scopes": { "type": "string", "description": "Space-separated OAuth2 scopes (optional)" },
                "enabled": { "type": "boolean", "description": "Whether the app is active (default: true)" }
            }
        })),
        response_body: Some(oauth_provider_client_response()),
        query_params: None,
        path_params: None,
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "bad_request".to_string(),
            "conflict".to_string(),
        ],
    });

    // GET /api/v1/oauth-provider-clients
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/oauth-provider-clients".to_string(),
        description: "List all MCP OAuth Apps. Requires manage_mcp_servers policy. \
            Returns summaries without client secrets."
            .to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": oauth_provider_client_response()
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });

    // GET /api/v1/oauth-provider-clients/{id}
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/oauth-provider-clients/{id}".to_string(),
        description: "Get a single MCP OAuth App by ID. Requires manage_mcp_servers policy."
            .to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(oauth_provider_client_response()),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP OAuth App ID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });

    // PUT /api/v1/oauth-provider-clients/{id}
    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/oauth-provider-clients/{id}".to_string(),
        description: "Update an MCP OAuth App. All fields are optional. If client_secret \
            is provided, it is re-encrypted. Requires manage_mcp_servers policy."
            .to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "client_id": { "type": "string" },
                "client_secret": { "type": "string", "description": "If provided, re-encrypts the secret" },
                "authorize_url": { "type": "string" },
                "token_url": { "type": "string" },
                "scopes": { "type": "string" },
                "enabled": { "type": "boolean" }
            }
        })),
        response_body: Some(oauth_provider_client_response()),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP OAuth App ID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
        ],
    });

    // DELETE /api/v1/oauth-provider-clients/{id}
    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/oauth-provider-clients/{id}".to_string(),
        description: "Delete an MCP OAuth App. Requires manage_mcp_servers policy.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({ "deleted": true })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP OAuth App ID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });
}

fn oauth_provider_client_response() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string", "format": "uuid" },
            "template_key": { "type": "string" },
            "name": { "type": "string" },
            "client_id": { "type": "string" },
            "authorize_url": { "type": "string" },
            "token_url": { "type": "string" },
            "scopes": { "type": "string" },
            "enabled": { "type": "boolean" },
            "created_at": { "type": "string", "format": "date-time" },
            "updated_at": { "type": "string", "format": "date-time" }
        }
    })
}
