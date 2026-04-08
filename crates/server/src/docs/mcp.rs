//! MCP server and proxy endpoint documentation.

use serde_json::json;

use super::{string_param, uuid_param, EndpointDoc};

pub(super) fn push_endpoints(endpoints: &mut Vec<EndpointDoc>) {
    // -----------------------------------------------------------------------
    // MCP Servers
    // -----------------------------------------------------------------------

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp-servers/import".to_string(),
        description: "Bulk import MCP server configs from a device. Authenticates via device JWT. Upserts servers scoped to the calling device and auto-generates Cedar allow-all policies. Used by the CLI `upload-mcps` command and device `upload-configs` endpoint.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["servers"],
            "properties": {
                "device_id": { "type": "string", "format": "uuid", "description": "Device ID (injected by device proxy, optional from direct calls)" },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string", "description": "MCP server name" },
                            "transport": { "type": "string", "enum": ["http", "sse"], "description": "Transport: http or sse (default: http)" },
                            "url": { "type": "string", "description": "Upstream URL for HTTP/SSE transport servers" }
                        }
                    }
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "imported": { "type": "integer", "description": "Number of servers imported/updated" },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "format": "uuid" },
                            "name": { "type": "string" },
                            "status": { "type": "string", "enum": ["created", "updated"] }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/mcp-servers".to_string(),
        description: "List all registered MCP servers. Optionally filter by device_id. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "device_id": { "type": "string", "format": "uuid", "description": "Device this MCP server is scoped to" },
                    "name": { "type": "string" },
                    "upstream_url": { "type": "string" },
                    "transport": { "type": "string" },
                    "allowed_tools": { "type": "array" },
                    "enabled": { "type": "boolean" },
                    "created_by": { "type": "string" },
                    "created_at": { "type": "string", "format": "date-time" },
                    "updated_at": { "type": "string", "format": "date-time" },
                    "tags": { "type": "array", "items": { "type": "string" } }
                }
            }
        })),
        query_params: Some(vec![
            string_param("device_id", "Filter MCP servers by device UUID", false),
        ]),
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/mcp-servers/{id}".to_string(),
        description: "Get details of a registered MCP server. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "device_id": { "type": "string", "format": "uuid", "description": "Device this MCP server is scoped to" },
                "name": { "type": "string" },
                "upstream_url": { "type": "string" },
                "transport": { "type": "string" },
                "allowed_tools": { "type": "array" },
                "enabled": { "type": "boolean" },
                "created_by": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" },
                "tags": { "type": "array", "items": { "type": "string" } }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "PUT".to_string(),
        path: "/api/v1/mcp-servers/{id}".to_string(),
        description: "Update a registered MCP server's name. Requires admin role.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "New server name (must not contain dots)" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "upstream_url": { "type": "string" },
                "transport": { "type": "string" },
                "allowed_tools": { "type": "array" },
                "enabled": { "type": "boolean" },
                "created_by": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" },
                "tags": { "type": "array", "items": { "type": "string" } }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/mcp-servers/{id}".to_string(),
        description: "Delete a registered MCP server. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "deleted": { "type": "boolean" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp-servers/{id}/generate-policies".to_string(),
        description: "Generates Cedar policies for selected tools on an MCP server. Creates one policy per tool/tag combination. Requires admin role.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["tools", "agent_tags"],
            "properties": {
                "tools": { "type": "array", "items": { "type": "string" }, "description": "List of tool names to generate policies for (max 50)" },
                "agent_tags": { "type": "array", "items": { "type": "string" }, "description": "List of agent tags to grant access (max 50)" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "policies_created": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "format": "uuid", "description": "ID of the created policy" },
                            "name": { "type": "string", "description": "Generated policy name" },
                            "cedar_policy": { "type": "string", "description": "The Cedar policy text" }
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_request".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/mcp-templates".to_string(),
        description: "List available MCP server templates from the built-in catalog and any runtime overrides. Templates describe popular remote MCP servers that can be provisioned per-workspace.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "key": { "type": "string" },
                    "name": { "type": "string" },
                    "description": { "type": "string" },
                    "upstream_url": { "type": "string" },
                    "transport": { "type": "string", "enum": ["http", "sse"] },
                    "auth_method": { "type": "string", "enum": ["api_key", "oauth2", "none"] },
                    "credential_template_key": { "type": "string" },
                    "category": { "type": "string" },
                    "tags": { "type": "array", "items": { "type": "string" } },
                    "icon": { "type": "string" },
                    "sort_order": { "type": "integer" }
                }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec!["unauthorized".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp-servers/provision".to_string(),
        description: "Provision an MCP server from a catalog template for a workspace. Creates the server record, optionally creates or links a credential, generates Cedar policies, and emits an audit event. Requires the `manage_mcp_servers` Cedar permission (admin and operator roles by default).".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["template_key", "workspace_id"],
            "properties": {
                "template_key": { "type": "string", "description": "Key of the MCP template to provision (e.g. 'github')" },
                "workspace_id": { "type": "string", "format": "uuid", "description": "Workspace to provision the server for" },
                "credential_id": { "type": "string", "format": "uuid", "description": "Existing credential UUID to link (optional)" },
                "secret_value": { "type": "string", "description": "Secret value to create a new credential (optional, mutually exclusive with credential_id)" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "workspace_id": { "type": "string", "format": "uuid" },
                "name": { "type": "string" },
                "upstream_url": { "type": "string" },
                "transport": { "type": "string" },
                "auth_method": { "type": "string", "enum": ["none", "api_key", "oauth2"] },
                "template_key": { "type": "string" },
                "enabled": { "type": "boolean" },
                "tags": { "type": "array", "items": { "type": "string" } },
                "required_credentials": { "type": "array", "items": { "type": "string", "format": "uuid" } }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden".to_string(),
            "not_found".to_string(),
            "bad_request".to_string(),
            "conflict".to_string(),
        ],
    });

    // -----------------------------------------------------------------------
    // MCP Proxy
    // -----------------------------------------------------------------------
    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp/proxy".to_string(),
        description: "Proxy an MCP JSON-RPC call to a registered MCP server. Authenticates the agent (JWT), evaluates Cedar policy (mcp_tool_call or mcp_list_tools), injects credentials, forwards to upstream, leak-scans the response, and emits audit events. Returns a JSON-RPC response.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["mcp_server", "jsonrpc", "method"],
            "properties": {
                "mcp_server": { "type": "string", "description": "Name of the registered MCP server to call" },
                "jsonrpc": { "type": "string", "enum": ["2.0"] },
                "method": { "type": "string", "description": "MCP method name (e.g., \"tools/call\", \"tools/list\")" },
                "params": { "type": "object", "description": "MCP method parameters (optional)" },
                "id": { "description": "JSON-RPC request ID (string or number)" }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "description": "JSON-RPC 2.0 response (not wrapped in ApiResponse envelope)",
            "properties": {
                "jsonrpc": { "type": "string", "enum": ["2.0"] },
                "result": { "description": "Result from the upstream MCP server (on success)" },
                "error": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "integer", "description": "JSON-RPC error code" },
                        "message": { "type": "string" }
                    },
                    "description": "JSON-RPC error (on failure)"
                },
                "id": { "description": "Echoed request ID" }
            }
        })),
        query_params: None,
        path_params: None,
        error_codes: vec![
            "unauthorized".to_string(),
            "-32600 (invalid request)".to_string(),
            "-32601 (method not found)".to_string(),
            "-32002 (policy denied)".to_string(),
            "-32003 (server not found)".to_string(),
            "-32004 (server disabled)".to_string(),
            "-32005 (tool not allowed)".to_string(),
            "-32006 (credential failed)".to_string(),
            "-32007 (upstream error)".to_string(),
        ],
    });
}
