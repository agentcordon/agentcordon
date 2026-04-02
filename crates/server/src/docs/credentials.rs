//! Credential, permission, and credential template endpoint documentation.

use serde_json::json;

use super::{string_param, uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // -----------------------------------------------------------------------
    // Credentials
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/credentials".to_string(),
        description: "Store a new credential. The secret value is encrypted at rest. The creator automatically receives full permissions (read, write, delete, delegated_use).".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name", "service"],
            "properties": {
                "name": { "type": "string", "description": "Unique credential name (used in {{name}} placeholders)" },
                "service": { "type": "string", "description": "Service identifier (e.g., 'slack', 'github')" },
                "secret_value": { "type": "string", "description": "The raw secret (API key, token, password). Encrypted at rest. Required for 'generic' type. For 'aws' type, can be JSON or omitted in favor of structured aws_* fields." },
                "scopes": { "type": "array", "items": { "type": "string" }, "description": "Optional list of scopes/permissions this credential has" },
                "metadata": { "type": "object", "description": "Optional arbitrary metadata" },
                "allowed_url_pattern": { "type": "string", "description": "Optional URL pattern for proxy whitelisting (e.g., 'https://api.slack.com/*'). Auto-defaults to 'https://*.amazonaws.com/*' for AWS type." },
                "expires_at": { "type": "string", "format": "date-time", "description": "Optional expiry date (ISO 8601). Null or absent means never expires." },
                "transform_script": { "type": "string", "description": "Optional Rhai script for transforming the decrypted secret before proxy injection. The script receives variables: secret, method, url, headers (map), body. Must return a string." },
                "transform_name": { "type": "string", "description": "Optional named built-in transform. Available: 'identity' (passthrough), 'basic-auth' (base64-encodes 'user:pass' as 'Basic ...'), 'bearer' (prefixes with 'Bearer '), 'aws-sigv4' (AWS SigV4 signing). If both transform_script and transform_name are provided, script takes precedence." },
                "vault": { "type": "string", "description": "Optional vault name for organizational grouping. Defaults to 'default' if not specified." },
                "credential_type": { "type": "string", "enum": ["generic", "aws", "oauth2_client_credentials"], "description": "Credential type. Defaults to 'generic'. When 'aws', provide aws_access_key_id + aws_secret_access_key fields (preferred) or secret_value as JSON with access_key_id and secret_access_key. When 'oauth2_client_credentials', provide oauth2_client_id + oauth2_token_endpoint + secret_value (client secret). Auto-defaults transform_name to 'aws-sigv4' for AWS." },
                "aws_access_key_id": { "type": "string", "description": "AWS Access Key ID. Used with credential_type='aws' instead of raw JSON in secret_value." },
                "aws_secret_access_key": { "type": "string", "description": "AWS Secret Access Key. Used with credential_type='aws' instead of raw JSON in secret_value." },
                "oauth2_client_id": { "type": "string", "description": "OAuth2 client ID. Required when credential_type='oauth2_client_credentials'." },
                "oauth2_token_endpoint": { "type": "string", "description": "OAuth2 token endpoint URL. Required when credential_type='oauth2_client_credentials'." },
                "oauth2_scopes": { "type": "string", "description": "OAuth2 scopes (space-delimited). Optional for credential_type='oauth2_client_credentials'." }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "service": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "metadata": { "type": "object" },
                "created_by": { "type": "string", "format": "uuid" },
                "created_at": { "type": "string", "format": "date-time" },
                "allowed_url_pattern": { "type": "string", "nullable": true },
                "expires_at": { "type": "string", "format": "date-time", "nullable": true },
                "expired": { "type": "boolean", "description": "True if the credential has expired" },
                "transform_script": { "type": "string", "nullable": true, "description": "Rhai transform script (if set)" },
                "transform_name": { "type": "string", "nullable": true, "description": "Named built-in transform (if set)" },
                "vault": { "type": "string", "description": "Vault name this credential belongs to (default: 'default')" },
                "credential_type": { "type": "string", "description": "Credential type: 'generic', 'aws', or 'oauth2_client_credentials'" },
                "owner_username": { "type": "string", "nullable": true, "description": "Display name of the credential owner (resolved from agent or user)" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "bad_request".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/credentials".to_string(),
        description: "List credentials visible to the authenticated principal (summary only, no secret values). Results are filtered by Cedar policy: admins see their own credentials, workspaces see credentials with explicit grants.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "name": { "type": "string" },
                    "service": { "type": "string" },
                    "scopes": { "type": "array", "items": { "type": "string" } },
                    "metadata": { "type": "object" },
                    "created_by": { "type": "string", "format": "uuid" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "allowed_url_pattern": { "type": "string", "nullable": true },
                    "expires_at": { "type": "string", "format": "date-time", "nullable": true },
                    "expired": { "type": "boolean", "description": "True if the credential has expired" },
                    "transform_script": { "type": "string", "nullable": true },
                    "transform_name": { "type": "string", "nullable": true },
                    "vault": { "type": "string", "description": "Vault name this credential belongs to" },
                    "credential_type": { "type": "string", "description": "Credential type: 'generic', 'aws', or 'oauth2_client_credentials'" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/credentials/{id}".to_string(),
        description: "Get a single credential by ID (summary only, no secret value).".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "service": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "metadata": { "type": "object" },
                "created_by": { "type": "string", "format": "uuid" },
                "created_at": { "type": "string", "format": "date-time" },
                "allowed_url_pattern": { "type": "string", "nullable": true },
                "expires_at": { "type": "string", "format": "date-time", "nullable": true },
                "expired": { "type": "boolean", "description": "True if the credential has expired" },
                "transform_script": { "type": "string", "nullable": true },
                "transform_name": { "type": "string", "nullable": true },
                "vault": { "type": "string", "description": "Vault name this credential belongs to" },
                "credential_type": { "type": "string", "description": "Credential type: 'generic', 'aws', or 'oauth2_client_credentials'" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/credentials/{id}".to_string(),
        description: "Update a credential's metadata (name, service, scopes, URL pattern, etc.). Does NOT update the secret value. Requires update permission on the credential.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "New credential name (must be unique)" },
                "service": { "type": "string", "description": "Service identifier" },
                "scopes": { "type": "array", "items": { "type": "string" }, "description": "Updated list of scopes" },
                "metadata": { "type": "object", "description": "Updated arbitrary metadata" },
                "allowed_url_pattern": { "type": "string", "description": "Updated URL pattern for proxy whitelisting" },
                "expires_at": { "type": "string", "format": "date-time", "description": "Updated expiry date (ISO 8601)" },
                "transform_script": { "type": "string", "description": "Updated Rhai transform script" },
                "transform_name": { "type": "string", "description": "Updated named built-in transform" },
                "vault": { "type": "string", "description": "Updated vault grouping" }
            },
            "description": "All fields are optional. Only provided fields are updated."
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "service": { "type": "string" },
                "scopes": { "type": "array", "items": { "type": "string" } },
                "metadata": { "type": "object" },
                "created_by": { "type": "string", "format": "uuid" },
                "created_at": { "type": "string", "format": "date-time" },
                "allowed_url_pattern": { "type": "string", "nullable": true },
                "expires_at": { "type": "string", "format": "date-time", "nullable": true },
                "expired": { "type": "boolean", "description": "True if the credential has expired" },
                "transform_script": { "type": "string", "nullable": true },
                "transform_name": { "type": "string", "nullable": true },
                "vault": { "type": "string" },
                "credential_type": { "type": "string" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "conflict".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/credentials/{id}".to_string(),
        description: "Delete a credential. Requires delete permission on the credential."
            .to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });

    // Reveal credential secret (human users only)
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/credentials/{id}/reveal".to_string(),
        description: "Reveal (decrypt) a credential's secret value. Requires session cookie authentication (human users only -- agents are forbidden). Cedar policy with action 'unprotect' is evaluated before decryption. Emits a CredentialSecretViewed audit event.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "secret_value": { "type": "string", "description": "The decrypted raw secret value" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "not_found".to_string()],
    });

    // Get credential by name
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/credentials/by-name/{name}".to_string(),
        description: "Look up a credential by name instead of UUID. Returns the same CredentialSummary as GET /credentials/{id}. Useful when the caller knows the credential name but not its UUID.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "description": "Same CredentialSummary as GET /credentials/{id}"
        })),
        query_params: None,
        path_params: Some(vec![string_param("name", "Credential name", true)]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    // -----------------------------------------------------------------------
    // Permissions
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/credentials/{id}/permissions".to_string(),
        description: "Get all permissions for a credential.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "credential_id": { "type": "string", "format": "uuid" },
                "owner": { "type": "string", "format": "uuid" },
                "permissions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "agent_id": { "type": "string", "format": "uuid", "description": "Workspace UUID (named agent_id for backward compatibility)" },
                            "permission": { "type": "string", "enum": ["read", "write", "delete", "delegated_use"] },
                            "granted_by": { "type": "string", "format": "uuid", "description": "Workspace that granted this permission (null if granted by a user)" },
                            "granted_by_user": { "type": "string", "format": "uuid", "description": "User that granted this permission (null if granted by a workspace)" },
                            "granted_at": { "type": "string", "format": "date-time" }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/credentials/{id}/permissions".to_string(),
        description: "Grant permission(s) on a credential to a workspace. Supports both single and batch formats. Single: {\"workspace_id\": \"...\", \"permission\": \"read\"}. Batch: {\"workspace_id\": \"...\", \"permissions\": [\"read\", \"write\"]}. The field 'agent_id' is accepted as an alias for backward compatibility. Both fields can be provided and are merged. One audit event is emitted per permission granted.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["workspace_id"],
            "properties": {
                "workspace_id": { "type": "string", "format": "uuid", "description": "Target workspace UUID to grant permission to (alias: agent_id)" },
                "permission": { "type": "string", "enum": ["read", "write", "delete", "delegated_use"], "description": "Single permission (backward compatible)" },
                "permissions": { "type": "array", "items": { "type": "string", "enum": ["read", "write", "delete", "delegated_use"] }, "description": "Batch permissions" }
            },
            "note": "At least one of 'permission' or 'permissions' must be provided."
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "granted": { "type": "array", "items": { "type": "string" }, "description": "List of permissions that were granted" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/credentials/{id}/permissions".to_string(),
        description: "Replace all permissions on a credential with the provided set.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["permissions"],
            "properties": {
                "permissions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["workspace_id", "permission"],
                        "properties": {
                            "workspace_id": { "type": "string", "format": "uuid", "description": "Target workspace UUID (alias: agent_id)" },
                            "permission": { "type": "string", "enum": ["read", "write", "delete", "delegated_use"] }
                        }
                    }
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": { "updated": { "type": "boolean" } }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Credential UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/credentials/{id}/permissions/{agent_id}/{permission}".to_string(),
        description: "Revoke a specific permission from an agent on a credential.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": { "revoked": { "type": "boolean" } }
        })),
        query_params: None,
        path_params: Some(vec![
            uuid_param("id", "Credential UUID"),
            uuid_param("agent_id", "Target workspace UUID"),
            string_param(
                "permission",
                "Permission to revoke (read, write, delete, delegated_use)",
                true,
            ),
        ]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
        ],
    });

    // -----------------------------------------------------------------------
    // Credential Templates
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/credential-templates".to_string(),
        description: "List pre-defined credential templates for common services (Anthropic, OpenAI, GitHub). Templates provide default field values for credential creation.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "example": "Anthropic API Key" },
                    "service": { "type": "string", "example": "api.anthropic.com" },
                    "auth_type": { "type": "string", "example": "api_key" },
                    "header": { "type": "string", "example": "x-api-key" },
                    "allowed_url_pattern": { "type": "string", "example": "https://api.anthropic.com/*" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });
}
