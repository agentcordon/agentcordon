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
                "workspace_id": { "type": "string", "format": "uuid", "description": "Workspace ID the imported servers are bound to (originating workspace for each entry)" },
                "servers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string", "description": "MCP server name" },
                            "transport": { "type": "string", "enum": ["http", "sse"], "description": "Transport: http or sse (default: http)" },
                            "url": { "type": "string", "description": "Upstream URL for HTTP/SSE transport servers" },
                            "tools": {
                                "type": "array",
                                "description": "Tools the workspace knows this server has. Stored the way discovery stores them: names, descriptions and input schemas are all kept.",
                                "items": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {
                                        "name": { "type": "string", "description": "Tool name" },
                                        "description": { "type": "string", "description": "What the tool does" },
                                        "input_schema": { "type": "object", "description": "JSON Schema for the tool's arguments; the MCP spelling `inputSchema` is accepted too" }
                                    }
                                }
                            }
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
        description: "List registered MCP servers, each with its live bindings as `installed_workspaces`. When filtered by `workspace_id`, results join through the `mcp_server_workspaces` junction so an MCP bound to multiple workspaces appears in each of their lists. Unfiltered, admins see all servers; non-admin users see servers whose owner is the caller. Requires admin role or a workspace actor. `device_id` is accepted as a legacy alias for `workspace_id`.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "workspace_id": { "type": "string", "format": "uuid", "description": "Legacy field, `null` for every MCP provisioned since the junction consolidation. NOT the binding set — read the bindings from `installed_workspaces` or GET /api/v1/mcp-servers/{id}/workspaces." },
                    "installed_workspaces": { "type": "array", "description": "Every workspace bound to this MCP through the `mcp_server_workspaces` junction, disabled workspaces filtered out. The admin UI's Workspaces column is rendered from this.", "items": { "type": "object", "properties": { "id": { "type": "string", "format": "uuid" }, "name": { "type": "string" } } } },
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
            string_param("workspace_id", "Filter MCP servers bound to this workspace (via the junction). `device_id` accepted as a legacy alias.", false),
        ]),
        path_params: None,
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/mcp-servers/{id}".to_string(),
        description: "Get details of a registered MCP server. Includes all workspaces the MCP is currently bound to via the `mcp_server_workspaces` junction. `installed_workspaces` can contain zero or more entries; it is the junction's own answer, not a 0-or-1 vec derived from the legacy `workspace_id`. Requires admin role.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "format": "uuid" },
                "workspace_id": { "type": "string", "format": "uuid", "description": "Legacy field, `null` for every MCP provisioned since the junction consolidation. NOT the binding set — read the bindings from `installed_workspaces` or GET /api/v1/mcp-servers/{id}/workspaces." },
                "name": { "type": "string" },
                "upstream_url": { "type": "string" },
                "transport": { "type": "string" },
                "allowed_tools": { "type": "array" },
                "enabled": { "type": "boolean" },
                "created_by": { "type": "string" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" },
                "tags": { "type": "array", "items": { "type": "string" } },
                "installed_workspaces": {
                    "type": "array",
                    "description": "All workspaces bound to this MCP via the junction. Reflects live bindings, not just the original workspace.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string", "format": "uuid" },
                            "name": { "type": "string" }
                        }
                    }
                },
                "tools": { "type": "array" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    // -----------------------------------------------------------------------
    // MCP Server Workspace Bindings (M:N sharing)
    // -----------------------------------------------------------------------

    endpoints.push(EndpointDoc {
        method: "GET".to_string(),
        path: "/api/v1/mcp-servers/{id}/workspaces".to_string(),
        description: "The workspaces currently bound to this MCP server through the `mcp_server_workspaces` junction — the bindings the share and unshare endpoints write, read back. Requires `manage_mcp_servers` on this server, so a user who does not own it is refused with 403. Disabled workspaces are filtered out, so this is the same list as `installed_workspaces` on the server responses.".to_string(),
        auth_required: true,
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
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp-servers/{id}/workspaces".to_string(),
        description: "Bind one or more workspaces to an existing MCP server. Owner-only (the authenticated user must own the MCP — `created_by_user` match — or be admin/root). Idempotent: workspaces already bound are returned under `already_bound` and do not cause an error. Returns 201 when at least one new binding was created, 200 when every requested workspace was already bound. Each newly-added binding emits an `McpServerSharedWithWorkspace` audit event. Cross-user binding is rejected at the handler with 403 — the request validator checks `workspace.owner_id == mcp.created_by_user` for every requested workspace before inserting any junction row, so no partial writes occur on rejection. Admin/root bypass the cross-owner check.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "required": ["workspace_ids"],
            "properties": {
                "workspace_ids": {
                    "type": "array",
                    "minItems": 1,
                    "items": { "type": "string", "format": "uuid" },
                    "description": "Workspaces to bind to this MCP. Every entry must be owned by the same user as the MCP (created_by_user), unless the caller is admin/root."
                }
            }
        })),
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "added": {
                            "type": "array",
                            "items": { "type": "string", "format": "uuid" },
                            "description": "Workspace IDs that were newly bound by this call."
                        },
                        "already_bound": {
                            "type": "array",
                            "items": { "type": "string", "format": "uuid" },
                            "description": "Workspace IDs that were already bound before this call (idempotent no-op)."
                        }
                    }
                }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden (403: caller is not the owner of the MCP and not admin/root, OR any requested workspace is owned by a different user than the MCP and the caller is not admin/root)".to_string(),
            "not_found (404: unknown MCP id, or a requested workspace does not exist at all — owned-by-another-user is 403, not 404)".to_string(),
            "unprocessable_entity (422: workspace_ids is empty or contains invalid UUIDs)".to_string(),
        ],
    });

    endpoints.push(EndpointDoc {
        method: "DELETE".to_string(),
        path: "/api/v1/mcp-servers/{id}/workspaces/{workspace_id}".to_string(),
        description: "Remove a single workspace binding from an MCP server. Owner-only. Returns 204 on success with an empty body. Emits an `McpServerUnsharedFromWorkspace` audit event. **Last-binding rule:** removing the only remaining binding for the MCP returns 409 — delete the MCP record itself (`DELETE /api/v1/mcp-servers/{id}`) to remove the final workspace. Admins are subject to the same last-binding rule (it is a state invariant, not an authz check). **Eventual consistency:** the unshared workspace's broker keeps the MCP in its cache until its next `mcp_sync` tick (~30 s); in-flight calls in that window may complete. This is not a security boundary — Cedar policy 3a remains the gate. `mcp_servers.workspace_id` (the original-provisioning workspace) is an immutable audit anchor and is never mutated by unshare, even when unsharing the original workspace while others remain bound.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: None,
        query_params: None,
        path_params: Some(vec![
            uuid_param("id", "MCP server UUID"),
            uuid_param("workspace_id", "Workspace UUID to unbind"),
        ]),
        error_codes: vec![
            "unauthorized".to_string(),
            "forbidden (403: caller is not the owner of the MCP and not admin/root)".to_string(),
            "not_found (404: unknown MCP id, or no binding exists between this MCP and this workspace)".to_string(),
            "conflict (409: request would remove the last remaining binding — delete the MCP server instead)".to_string(),
        ],
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
        path: "/api/v1/mcp-servers/{id}/discover-tools".to_string(),
        description: "Re-run tool discovery against the server's upstream, presenting the credential the broker would present (an upstream OAuth credential is exchanged for a fresh access token first). Install-time discovery is best-effort, so a server installed while its upstream was unreachable — down, or refused by the SSRF guard — has no tools; this is the retry behind the detail page's **Rediscover tools** button. Requires `manage_mcp_servers` on this server. A probe that fails answers 502 with the reason and emits an `mcp_tool_discovery_failed` audit event.".to_string(),
        auth_required: true,
        request_body: None,
        response_body: Some(json!({
            "type": "object",
            "properties": {
                "tool_count": { "type": "integer", "description": "How many tools the probe found and stored" }
            }
        })),
        query_params: None,
        path_params: Some(vec![uuid_param("id", "MCP server UUID")]),
        error_codes: vec!["unauthorized".to_string(), "forbidden".to_string(), "not_found".to_string(), "bad_gateway".to_string()],
    });

    endpoints.push(EndpointDoc {
        method: "POST".to_string(),
        path: "/api/v1/mcp-servers/{id}/generate-policies".to_string(),
        description: "Generates Cedar policies for selected tools on an MCP server. Creates one policy per tool/tag combination. Both fields are optional, so an empty body ({}) grants what the server already has. Requires admin role.".to_string(),
        auth_required: true,
        request_body: Some(json!({
            "type": "object",
            "properties": {
                "tools": { "type": "array", "items": { "type": "string" }, "description": "Tool names to generate policies for (max 50). Omit for every tool the server currently has: its allowed_tools, else what discovery found. An explicit empty list is rejected." },
                "agent_tags": { "type": "array", "items": { "type": "string" }, "description": "Agent tags to grant access (max 50). Omit for every tag the workspaces bound to this server carry. An explicit empty list is rejected." }
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
}
