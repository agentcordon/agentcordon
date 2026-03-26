//! Policy, RSoP, and schema reference endpoint documentation.

use serde_json::json;

use super::{uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // -----------------------------------------------------------------------
    // Policies
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/policies".to_string(),
        description: "Create a new Cedar policy. Requires manage_policies permission. The policy is validated and the engine is reloaded.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["name", "cedar_policy"],
            "properties": {
                "name": { "type": "string", "description": "Policy name" },
                "description": { "type": "string", "description": "Optional description" },
                "cedar_policy": { "type": "string", "description": "Cedar policy text" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "description": { "type": "string", "nullable": true },
                "cedar_policy": { "type": "string" },
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
        path: "/api/v1/policies".to_string(),
        description: "List all policies. Requires manage_policies permission.".to_string(),
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
                    "cedar_policy": { "type": "string" },
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
        path: "/api/v1/policies/{id}".to_string(),
        description: "Get a single policy by ID. Requires manage_policies permission.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "description": { "type": "string", "nullable": true },
                "cedar_policy": { "type": "string" },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Policy UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/policies/{id}".to_string(),
        description: "Update a policy. Requires manage_policies permission. The policy is validated and the engine is reloaded.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "description": { "type": "string" },
                "cedar_policy": { "type": "string" },
                "enabled": { "type": "boolean" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "description": { "type": "string", "nullable": true },
                "cedar_policy": { "type": "string" },
                "enabled": { "type": "boolean" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Policy UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/policies/{id}".to_string(),
        description: "Delete a policy. Requires manage_policies permission. The engine is reloaded after deletion.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": { "deleted": { "type": "boolean" } }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "Policy UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/policies/schema".to_string(),
        description: "Get the Cedar schema. Returns the Cedar schema JSON text. Requires manage_policies permission (admin-only).".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "string",
            "description": "Cedar schema in JSON format"
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/policies/validate".to_string(),
        description: "Validate Cedar policy text without creating or updating a policy. Returns structured errors with severity for inline editor feedback. Requires manage_policies permission.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["cedar_policy"],
            "properties": {
                "cedar_policy": {
                    "type": "string",
                    "description": "Cedar policy text to validate"
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "valid": { "type": "boolean", "description": "Whether the policy text is valid" },
                "errors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "message": { "type": "string" },
                            "severity": { "type": "string", "enum": ["error", "warning"] },
                            "policy_index": { "type": "integer", "nullable": true }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "bad_request".to_string()],
    });

    // -----------------------------------------------------------------------
    // Policy Analysis (RSoP + Schema Reference)
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/policies/rsop".to_string(),
        description: "Resultant Set of Policy (RSoP). Evaluates all active policies against every principal for a given resource, producing a permission matrix. Requires manage_policies permission.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["resource_type", "resource_id"],
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["Credential", "McpServer"],
                    "description": "Type of resource to evaluate policies against"
                },
                "resource_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "ID of the specific resource to evaluate"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of principals to evaluate (default 100)",
                    "default": 100
                }
            },
            "example": {
                "resource_type": "Credential",
                "resource_id": "550e8400-e29b-41d4-a716-446655440000",
                "limit": 100
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["ok"] },
                "data": {
                    "type": "object",
                    "properties": {
                        "resource": {
                            "type": "object",
                            "properties": {
                                "type": { "type": "string" },
                                "id": { "type": "string", "format": "uuid" },
                                "name": { "type": "string" },
                                "service": { "type": "string" }
                            }
                        },
                        "evaluated_at": { "type": "string", "format": "date-time" },
                        "principal_count": { "type": "integer" },
                        "matrix": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "principal_type": { "type": "string", "enum": ["Agent", "Device"] },
                                    "principal_id": { "type": "string", "format": "uuid" },
                                    "principal_name": { "type": "string" },
                                    "principal_tags": { "type": "array", "items": { "type": "string" } },
                                    "results": {
                                        "type": "object",
                                        "description": "Map of action name to decision object",
                                        "additionalProperties": {
                                            "type": "object",
                                            "properties": {
                                                "decision": { "type": "string", "enum": ["permit", "deny", "forbid"] },
                                                "reasons": { "type": "array", "items": { "type": "string" } }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "conditional_policies": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "policy_name": { "type": "string" },
                                    "policy_id": { "type": "string", "format": "uuid" },
                                    "condition_type": { "type": "string" },
                                    "description": { "type": "string" }
                                }
                            }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "bad_request".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/policies/schema/reference".to_string(),
        description: "Human-readable action catalog derived from the Cedar schema. Lists all actions with their applicable principal types, resource types, and context attributes. Requires manage_policies permission.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["ok"] },
                "data": {
                    "type": "object",
                    "properties": {
                        "actions": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string", "description": "Action name (e.g., 'vend_credential')" },
                                    "description": { "type": "string", "description": "Human-readable description of the action" },
                                    "principal_types": { "type": "array", "items": { "type": "string" } },
                                    "resource_types": { "type": "array", "items": { "type": "string" } },
                                    "context_attributes": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "name": { "type": "string" },
                                                "type": { "type": "string" },
                                                "description": { "type": "string" }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "entity_types": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": { "type": "string" },
                                    "attributes": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "name": { "type": "string" },
                                                "type": { "type": "string" },
                                                "required": { "type": "boolean" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });
}
