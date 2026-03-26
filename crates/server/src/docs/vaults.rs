//! Vault and vault sharing endpoint documentation.

use serde_json::json;

use super::{EndpointDoc, ParamDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults".to_string(),
        description: "List all distinct vault names. Each credential belongs to a vault (default: 'default'). Returns an array of vault name strings.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Distinct vault names"
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults/{name}/credentials".to_string(),
        description: "List credentials belonging to a specific vault. Returns credential summaries (no secret material).".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": { "type": "object", "description": "CredentialSummary" }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![ParamDoc {
            name: "name".to_string(),
            type_name: "string".to_string(),
            required: true,
            description: "The vault name to filter by.".to_string(),
        }]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/vaults/{name}/shares".to_string(),
        description: "Share a vault with another user. Only admin or root users can share vaults. Agents cannot share.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["user_id"],
            "properties": {
                "user_id": { "type": "string", "format": "uuid", "description": "ID of the user to share with" },
                "permission": {
                    "type": "string",
                    "enum": ["read", "write", "admin"],
                    "default": "read",
                    "description": "Permission level to grant"
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": { "type": "object", "description": "The created VaultShare record" }
            }
        })),
        query_params: None,
        path_params: Some(vec![ParamDoc {
            name: "name".to_string(),
            type_name: "string".to_string(),
            required: true,
            description: "The vault name to share.".to_string(),
        }]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults/{name}/shares".to_string(),
        description: "List all shares for a specific vault. Returns VaultShare records showing which users have access.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": { "type": "object", "description": "VaultShare record" }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![ParamDoc {
            name: "name".to_string(),
            type_name: "string".to_string(),
            required: true,
            description: "The vault name to list shares for.".to_string(),
        }]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/vaults/{name}/shares/{user_id}".to_string(),
        description:
            "Revoke vault sharing for a specific user. Only admin or root users can unshare."
                .to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": { "type": "object", "properties": { "removed": { "type": "boolean" } } }
            }
        })),
        query_params: None,
        path_params: Some(vec![
            ParamDoc {
                name: "name".to_string(),
                type_name: "string".to_string(),
                required: true,
                description: "The vault name.".to_string(),
            },
            ParamDoc {
                name: "user_id".to_string(),
                type_name: "string".to_string(),
                required: true,
                description: "UUID of the user whose share to revoke.".to_string(),
            },
        ]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });
}
