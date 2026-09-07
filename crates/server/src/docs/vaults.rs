//! Vault and vault sharing endpoint documentation.

use serde_json::json;

use super::{EndpointDoc, ParamDoc};

/// The `{id}` path parameter every vault route takes.
fn vault_id_param() -> ParamDoc {
    ParamDoc {
        name: "id".to_string(),
        type_name: "string".to_string(),
        required: true,
        description: "The vault's id. Vault names are display labels and are not unique, so \
                      every route names a vault by id."
            .to_string(),
    }
}

/// The shape a vault comes back as.
fn vault_object() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string", "format": "uuid" },
            "name": { "type": "string", "description": "Display label. Not unique." },
            "owner_user_id": {
                "type": ["string", "null"],
                "description": "The owning user, or null for the system default vault."
            },
            "is_default": {
                "type": "boolean",
                "description": "True for the one system vault every principal may write to, and nobody may rename, share or delete."
            },
            "shared_by": {
                "type": "string",
                "description": "Username of whoever shared this vault with you. Present only when you see the vault through a share."
            },
            "permission": {
                "type": "string",
                "description": "The share's permission level. Present only when you see the vault through a share."
            },
            "created_at": { "type": "string", "format": "date-time" },
            "updated_at": { "type": "string", "format": "date-time" }
        }
    })
}

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults".to_string(),
        description: "List the vaults you can see: the system default, the vaults you own, and the vaults shared with you (each naming who shared it). A holder of `manage_vaults` sees every vault.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": { "type": "array", "items": vault_object() }
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
        method: "POST".to_string(),
        path: "/api/v1/vaults".to_string(),
        description: "Create a vault owned by you. Anyone who may create credentials may create somewhere to put them. Names are not unique — two vaults may share one.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": { "type": "string", "maxLength": 100, "description": "Display label." }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": { "data": vault_object() }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "bad_request".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "PATCH".to_string(),
        path: "/api/v1/vaults/{id}".to_string(),
        description:
            "Rename a vault. The owner or root; the system default vault cannot be renamed."
                .to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name"],
            "properties": { "name": { "type": "string", "maxLength": 100 } }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": { "data": vault_object() }
        })),
        query_params: None,
        path_params: Some(vec![vault_id_param()]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/vaults/{id}".to_string(),
        description: "Delete a vault. The owner or root, and only while the vault is empty: a vault that still holds credentials answers 409, because deleting it would take them with it. The system default vault cannot be deleted.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": { "type": "object", "properties": { "deleted": { "type": "boolean" } } }
            }
        })),
        query_params: None,
        path_params: Some(vec![vault_id_param()]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "conflict".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults/{id}/credentials".to_string(),
        description: "List credentials in a vault. Filtered to what the caller may see — the credentials they created, the vaults they own, and the vaults shared with them — so a stranger gets an empty list rather than a refusal.".to_string(),
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
        path_params: Some(vec![vault_id_param()]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/vaults/{id}/shares".to_string(),
        description: "Share a vault with another user, granting them read visibility of its credentials. The vault's owner (or root) only, at any role: holding `manage_vaults` does not let an admin hand out someone else's credentials. The system default vault cannot be shared.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["user_id"],
            "properties": {
                "user_id": { "type": "string", "format": "uuid", "description": "ID of the user to share with" },
                "permission": {
                    "type": "string",
                    "enum": ["read"],
                    "default": "read",
                    "description": "Only 'read' is supported; 'write' and 'admin' are refused with 400 until the authorization rework."
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "vault_id": { "type": "string", "format": "uuid" },
                        "shared_with_user_id": { "type": "string", "format": "uuid" },
                        "permission_level": { "type": "string" },
                        "shared_by_user_id": { "type": "string", "format": "uuid" },
                        "created_at": { "type": "string", "format": "date-time" }
                    }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![vault_id_param()]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
            "conflict".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/vaults/{id}/shares".to_string(),
        description: "List a vault's shares. The owner, root, or a holder of `manage_vaults`; a signed-in stranger is refused rather than handed the roster.".to_string(),
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
        path_params: Some(vec![vault_id_param()]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/vaults/{id}/shares/{user_id}".to_string(),
        description:
            "Revoke a user's share. The owner, root, or a holder of `manage_vaults` — that grant exists so someone can cut off a share they did not make."
                .to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": { "type": "object", "properties": { "deleted": { "type": "boolean" } } }
            }
        })),
        query_params: None,
        path_params: Some(vec![
            vault_id_param(),
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
