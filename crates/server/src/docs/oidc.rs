//! OIDC authentication and provider management endpoint documentation.

use serde_json::json;

use super::{string_param, uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // -----------------------------------------------------------------------
    // OIDC Authentication
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/auth/oidc/providers".to_string(),
        description: "List enabled OIDC providers available for login. No authentication required. Returns minimal info (id and name) for login UI display.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "name": { "type": "string" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/auth/oidc/authorize".to_string(),
        description: "Initiate OIDC login. Redirects the browser to the external identity provider's authorization endpoint. The provider query parameter specifies which OIDC provider to use.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "redirect",
            "description": "302 redirect to the OIDC provider's authorization endpoint"
        })),
        query_params: Some(vec![
            uuid_param("provider", "OIDC provider UUID to authenticate with"),
        ]),
        path_params: None,
        error_codes: vec!["bad_request".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/auth/oidc/callback".to_string(),
        description: "OIDC callback endpoint. Called by the identity provider after authentication. Validates the authorization code, exchanges it for tokens, validates the ID token, provisions or finds the user, creates a session, and redirects to the web UI.".to_string(),
        auth_required: false,
        request_body: None,
        response_body: Some(json!({
            "type": "redirect",
            "description": "302 redirect to / with session cookies set on success, or to /login?error=... on failure"
        })),
        query_params: Some(vec![
            string_param("code", "Authorization code from the OIDC provider", true),
            string_param("state", "CSRF state parameter (must match the stored state)", true),
        ]),
        path_params: None,
        error_codes: vec!["bad_request".to_string(), "unauthorized".to_string()],
    });

    // -----------------------------------------------------------------------
    // OIDC Provider Management (admin only)
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/oidc-providers".to_string(),
        description: "Create a new OIDC provider configuration. Requires admin role (manage_oidc_providers policy). The client secret is encrypted at rest.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name", "issuer_url", "client_id", "client_secret"],
            "properties": {
                "name": { "type": "string", "description": "Display name for the provider" },
                "issuer_url": { "type": "string", "description": "OIDC issuer URL (must be HTTPS, except localhost for dev)" },
                "client_id": { "type": "string", "description": "OAuth2 client ID" },
                "client_secret": { "type": "string", "description": "OAuth2 client secret (encrypted at rest)" },
                "scopes": { "type": "array", "items": { "type": "string" }, "description": "Scopes to request (default: openid, profile, email)" },
                "role_mapping": { "type": "object", "description": "Map OIDC claims/groups to AgentCordon user roles" },
                "auto_provision": { "type": "boolean", "description": "Auto-create users on first OIDC login (default: true)" },
                "enabled": { "type": "boolean", "description": "Whether the provider is active (default: true)" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "issuer_url": { "type": "string" },
                "client_id": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "role_mapping": { "type": "object" },
                "auto_provision": { "type": "boolean" },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/oidc-providers".to_string(),
        description: "List all OIDC providers. Requires admin role. Returns summaries without client secrets.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "name": { "type": "string" },
                    "issuer_url": { "type": "string" },
                    "client_id": { "type": "string" },
                    "scopes": { "type": "array", "items": { "type": "string" } },
                    "role_mapping": { "type": "object" },
                    "auto_provision": { "type": "boolean" },
                    "enabled": { "type": "boolean" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "updated_at": { "type": "string", "format": "date-time" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/oidc-providers/{id}".to_string(),
        description: "Get a single OIDC provider by ID. Requires admin role. Returns summary without client secret.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "issuer_url": { "type": "string" },
                "client_id": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "role_mapping": { "type": "object" },
                "auto_provision": { "type": "boolean" },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "OIDC provider UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/oidc-providers/{id}".to_string(),
        description: "Update an OIDC provider. Requires admin role. All fields are optional; only provided fields are updated. If client_secret is provided, it is re-encrypted.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "issuer_url": { "type": "string" },
                "client_id": { "type": "string" },
                "client_secret": { "type": "string", "description": "New client secret (re-encrypted at rest)" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "role_mapping": { "type": "object" },
                "auto_provision": { "type": "boolean" },
                "enabled": { "type": "boolean" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "issuer_url": { "type": "string" },
                "client_id": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "role_mapping": { "type": "object" },
                "auto_provision": { "type": "boolean" },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "OIDC provider UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/oidc-providers/{id}".to_string(),
        description: "Delete an OIDC provider. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "OIDC provider UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });
}
