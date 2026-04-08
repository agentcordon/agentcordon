//! Machine-readable API documentation for agent self-discovery.
//!
//! This module provides structured JSON documentation of the entire AgentCordon
//! API surface. The primary consumers are autonomous AI agents that need to
//! discover how to interact with the system from a single URL (`GET /api/v1/docs`).
//!
//! The documentation is generated from explicit, inline metadata — not from
//! router introspection. Each endpoint is manually documented here, which
//! keeps the documentation in sync with the actual implementation as long as
//! new endpoints are added to the builder functions.
//!
//! Endpoint documentation is organized by API area in submodules:
//! - `agents` — Agent CRUD
//! - `credentials` — Credentials, permissions, and templates
//! - `policies` — Cedar policies, RSoP, schema reference
//! - `mcp` — MCP servers and proxy
//! - `vaults` — Vault management and sharing
//! - `oidc` — OIDC authentication and provider management
//! - `general` — Health, auth, audit, demo, proxy, SSE, docs, admin

mod agents;
mod credentials;
mod general;
mod mcp;
mod oauth_provider_clients;
mod oidc;
mod policies;
mod vaults;

use serde::Serialize;
use serde_json::{json, Value};

use crate::config::AppConfig;

// ---------------------------------------------------------------------------
// Data model types
// ---------------------------------------------------------------------------

/// Top-level API documentation returned by `GET /api/v1/docs`.
#[derive(Serialize, Clone)]
pub struct ApiDocumentation {
    pub server: ServerInfo,
    pub authentication: AuthInfo,
    pub endpoints: Vec<EndpointDoc>,
    pub error_format: ErrorFormatDoc,
    pub proxy_guide: ProxyGuideDoc,
}

#[derive(Serialize, Clone)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub base_url: String,
}

#[derive(Serialize, Clone)]
pub struct AuthInfo {
    pub methods: Vec<AuthMethodDoc>,
}

#[derive(Serialize, Clone)]
pub struct AuthMethodDoc {
    pub method: String,
    pub description: String,
    pub header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct EndpointDoc {
    pub method: String,
    pub path: String,
    pub description: String,
    pub auth_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_params: Option<Vec<ParamDoc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_params: Option<Vec<ParamDoc>>,
    pub error_codes: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct ParamDoc {
    pub name: String,
    pub type_name: String,
    pub required: bool,
    pub description: String,
}

#[derive(Serialize, Clone)]
pub struct ErrorFormatDoc {
    pub envelope: Value,
    pub codes: Vec<ErrorCodeDoc>,
}

#[derive(Serialize, Clone)]
pub struct ErrorCodeDoc {
    pub code: String,
    pub http_status: u16,
    pub description: String,
}

#[derive(Serialize, Clone)]
pub struct ProxyGuideDoc {
    pub endpoint: String,
    pub description: String,
    pub placeholder_syntax: String,
    pub request_schema: Value,
    pub response_schema: Value,
    pub workflow_steps: Vec<String>,
    pub example_request: Value,
    pub example_response: Value,
    pub security_notes: Vec<String>,
}

/// Concise getting-started guide returned by `GET /api/v1/docs/quickstart`.
#[derive(Serialize, Clone)]
pub struct QuickstartDoc {
    pub authentication: Value,
    pub proxy: Value,
    pub errors: Value,
}

// ---------------------------------------------------------------------------
// Content builders
// ---------------------------------------------------------------------------

/// Build the full API documentation. Accepts `AppConfig` so that dynamic
/// values such as `jwt_ttl_seconds` are reflected.
pub fn build_api_docs(config: &AppConfig) -> ApiDocumentation {
    ApiDocumentation {
        server: build_server_info(),
        authentication: build_auth_info(config),
        endpoints: build_all_endpoints(config),
        error_format: build_error_format(),
        proxy_guide: build_proxy_guide(),
    }
}

/// Build the concise quickstart guide.
pub fn build_quickstart_doc(config: &AppConfig) -> QuickstartDoc {
    QuickstartDoc {
        authentication: json!({
            "overview": "AgentCordon uses OAuth-based workspace registration and JWT authentication. Agents register via the CLI (`agentcordon register`), receive a JWT, and use it for all authenticated requests.",
            "jwt": {
                "description": "Agents authenticate using server-issued JWTs via OAuth workspace registration.",
                "header": "Authorization: Bearer <access_token>",
                "ttl_seconds": config.jwt_ttl_seconds
            },
            "response_envelope": {
                "description": "All authenticated endpoints (except /api/v1/docs and /api/v1/docs/quickstart) wrap responses in {\"data\": ...} for success and {\"error\": {\"code\": ..., \"message\": ...}} for errors."
            }
        }),
        proxy: json!({
            "overview": "The credential proxy lets agents use external services through AgentCordon without seeing raw credentials. Agents use the CLI (`agentcordon proxy`) which communicates through the OAuth broker.",
            "endpoint": "agentcordon proxy <name> <METHOD> <target>",
            "cli_command": "agentcordon proxy <name> GET <target>",
            "auth_required": true,
            "placeholder_syntax": "{{credential-name}}",
            "workflow": [
                "1. An admin stores a credential via the web UI or API",
                "2. Grant your agent permission to the credential (the creator gets full permissions automatically)",
                "3. Agent discovers credentials: GET /api/v1/credentials (or `agentcordon credentials list`)",
                "4. Agent proxies via CLI: `agentcordon proxy <name> GET <target>` — the CLI handles credential injection through the broker.",
                "5. The server resolves the credential, applies transforms, and makes the upstream request. The agent never sees the raw credential."
            ],
            "example_request": {
                "method": "POST",
                "url": "https://api.example.com/v1/data",
                "headers": { "Authorization": "Bearer {{my-credential}}", "Content-Type": "application/json" },
                "body": "{\"query\": \"latest\"}"
            },
            "example_response": {
                "data": {
                    "status_code": 200,
                    "headers": { "content-type": "application/json" },
                    "body": "{\"results\": [...]}"
                }
            },
            "security_notes": [
                "Agents never see raw credential values -- they are injected server-side.",
                "Credentials can have URL whitelist patterns (allowed_url_pattern) restricting which domains they can be sent to.",
                "Response bodies are scanned for leaked credential values. If a credential value is found in the upstream response, the response is withheld and an audit event is logged.",
                "All proxy requests are policy-evaluated (Cedar) before execution.",
                "SSRF protection blocks requests to internal/private IP ranges in production."
            ],
            "transforms": {
                "overview": "Credentials can have transforms that modify the decrypted secret before injection. Transforms run server-side in a sandboxed Rhai runtime.",
                "built_in_transforms": [
                    { "name": "identity", "description": "Returns the secret as-is (default behavior)" },
                    { "name": "basic-auth", "description": "Expects 'user:pass' format, returns 'Basic <base64>'" },
                    { "name": "bearer", "description": "Returns 'Bearer <secret>'" },
                    { "name": "aws-sigv4", "description": "AWS Signature Version 4 signing. Secret must be JSON: {access_key_id, secret_access_key, region, service}. Returns Authorization header and injects x-amz-date, x-amz-content-sha256, host headers automatically." }
                ],
                "transform_output": {
                    "description": "Transforms return a TransformOutput with a primary value (for placeholder substitution) and optional extra_headers (injected into the outgoing proxy request). Simple transforms return only the value; aws-sigv4 also returns extra headers.",
                    "extra_headers_behavior": "Extra headers are merged into the proxy request. If a header already exists in the request, the existing value takes precedence."
                },
                "custom_scripts": {
                    "description": "Set transform_script on a credential to run a custom Rhai script. The script receives variables: secret, method, url, headers (map), body. It must return a string.",
                    "helpers": ["hmac_sha256(key, data)", "sha256(data)", "base64_encode(data)", "base64_decode(data)", "hex_encode(data)", "url_encode(data)", "url_decode(data)"],
                    "example": "base64_encode(secret)"
                }
            }
        }),
        errors: json!({
            "envelope": { "error": { "code": "<error_code>", "message": "<human-readable message>" } },
            "codes": [
                { "code": "not_found", "http_status": 404, "description": "The requested resource does not exist." },
                { "code": "unauthorized", "http_status": 401, "description": "Authentication failed or missing." },
                { "code": "forbidden", "http_status": 403, "description": "Authenticated but not authorized (policy denied)." },
                { "code": "bad_request", "http_status": 400, "description": "Invalid input or malformed request." },
                { "code": "conflict", "http_status": 409, "description": "Resource conflict (e.g., duplicate name, already redeemed)." },
                { "code": "gone", "http_status": 410, "description": "Resource no longer available (e.g., expired authorization code)." },
                { "code": "internal_error", "http_status": 500, "description": "Unexpected server error." },
                { "code": "bad_gateway", "http_status": 502, "description": "Upstream service error during proxy execution." },
                { "code": "credential_leak_detected", "http_status": 502, "description": "A credential value was detected in an upstream response. The response has been withheld for security." }
            ]
        }),
    }
}

// ---------------------------------------------------------------------------
// Internal builder helpers
// ---------------------------------------------------------------------------

fn build_server_info() -> ServerInfo {
    ServerInfo {
        name: "AgentCordon".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "Agentic Identity Provider -- secure, auditable, policy-controlled credential brokerage for autonomous agents.".to_string(),
        base_url: "/api/v1".to_string(),
    }
}

fn build_auth_info(config: &AppConfig) -> AuthInfo {
    AuthInfo {
        methods: vec![AuthMethodDoc {
            method: "jwt".to_string(),
            description:
                "Agents authenticate using server-issued JWTs via OAuth workspace registration."
                    .to_string(),
            header: "Authorization: Bearer <jwt>".to_string(),
            token_endpoint: None,
            ttl_seconds: Some(config.jwt_ttl_seconds),
        }],
    }
}

fn build_error_format() -> ErrorFormatDoc {
    ErrorFormatDoc {
        envelope: json!({
            "error": {
                "code": "<error_code>",
                "message": "<human-readable description>"
            }
        }),
        codes: vec![
            ErrorCodeDoc {
                code: "not_found".to_string(),
                http_status: 404,
                description: "The requested resource does not exist.".to_string(),
            },
            ErrorCodeDoc {
                code: "unauthorized".to_string(),
                http_status: 401,
                description: "Authentication failed -- missing, invalid, or expired credentials.".to_string(),
            },
            ErrorCodeDoc {
                code: "forbidden".to_string(),
                http_status: 403,
                description: "Authenticated but not authorized. The Cedar policy engine denied the request.".to_string(),
            },
            ErrorCodeDoc {
                code: "bad_request".to_string(),
                http_status: 400,
                description: "The request is malformed, missing required fields, or contains invalid values.".to_string(),
            },
            ErrorCodeDoc {
                code: "conflict".to_string(),
                http_status: 409,
                description: "Resource conflict (e.g., duplicate name, grant already redeemed, self-disable attempt).".to_string(),
            },
            ErrorCodeDoc {
                code: "gone".to_string(),
                http_status: 410,
                description: "The resource is no longer available (e.g., an authorization code has expired).".to_string(),
            },
            ErrorCodeDoc {
                code: "internal_error".to_string(),
                http_status: 500,
                description: "An unexpected server error occurred. The error message is generic for security.".to_string(),
            },
            ErrorCodeDoc {
                code: "bad_gateway".to_string(),
                http_status: 502,
                description: "The upstream service returned an error or was unreachable during proxy execution.".to_string(),
            },
            ErrorCodeDoc {
                code: "credential_leak_detected".to_string(),
                http_status: 502,
                description: "A credential value was detected in the upstream response body. The response has been withheld to prevent credential leakage.".to_string(),
            },
        ],
    }
}

fn build_proxy_guide() -> ProxyGuideDoc {
    ProxyGuideDoc {
        endpoint: "agentcordon proxy <name> <METHOD> <target>".to_string(),
        description: "Execute an HTTP request through the credential proxy. Agents use `agentcordon proxy` via the CLI, which communicates through the OAuth broker.".to_string(),
        placeholder_syntax: "{{credential-name}}".to_string(),
        request_schema: json!({
            "type": "object",
            "required": ["method", "url"],
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                    "description": "HTTP method for the upstream request"
                },
                "url": {
                    "type": "string",
                    "description": "Target URL. May contain {{credential-name}} placeholders."
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "HTTP headers to send. Values may contain {{credential-name}} placeholders."
                },
                "body": {
                    "type": "string",
                    "description": "Request body. May contain {{credential-name}} placeholders."
                }
            }
        }),
        response_schema: json!({
            "type": "object",
            "properties": {
                "status_code": { "type": "integer", "description": "HTTP status code from the upstream response" },
                "headers": {
                    "type": "object",
                    "additionalProperties": { "type": "string" },
                    "description": "Response headers from the upstream service"
                },
                "body": {
                    "type": "string",
                    "nullable": true,
                    "description": "Response body from the upstream service (null if empty)"
                }
            }
        }),
        workflow_steps: vec![
            "1. Store a credential via POST /api/v1/credentials (admin or authorized agent).".to_string(),
            "2. Ensure your agent has permission to the credential (creator gets full permissions automatically, or use the permissions endpoints).".to_string(),
            "3. Agent discovers credentials: GET /api/v1/credentials or `agentcordon credentials list`.".to_string(),
            "4. Agent proxies via CLI: `agentcordon proxy <name> GET <target>` — the CLI handles credential injection through the broker.".to_string(),
            "5. The server resolves the credential, applies transforms, and calls the upstream API.".to_string(),
            "6. The upstream response is returned to the agent. The agent never sees raw credentials.".to_string(),
            "7. Receive the upstream response (status code, headers, body) wrapped in the standard API envelope.".to_string(),
        ],
        example_request: json!({
            "method": "POST",
            "url": "https://slack.com/api/chat.postMessage",
            "headers": {
                "Authorization": "Bearer {{slack-bot-token}}",
                "Content-Type": "application/json"
            },
            "body": "{\"channel\": \"#general\", \"text\": \"Hello from my agent!\"}"
        }),
        example_response: json!({
            "data": {
                "status_code": 200,
                "headers": {
                    "content-type": "application/json; charset=utf-8"
                },
                "body": "{\"ok\": true, \"channel\": \"C1234\", \"ts\": \"1234567890.123456\"}"
            }
        }),
        security_notes: vec![
            "Agents never receive raw credential values. Credentials are resolved and injected server-side.".to_string(),
            "Each credential can have an allowed_url_pattern that restricts which URLs it can be sent to (e.g., 'https://slack.com/api/*').".to_string(),
            "All proxy requests are evaluated by the Cedar policy engine before execution. The policy checks the requesting agent, the credential, and the target URL.".to_string(),
            "Upstream response bodies are scanned for leaked credential values. If a credential value appears in the response, the response is withheld and an audit event is logged with error code 'credential_leak_detected'.".to_string(),
            "SSRF protection prevents proxy requests to internal/private IP ranges (loopback, link-local, RFC 1918) in production deployments.".to_string(),
            "Same-domain redirects are followed automatically (up to 10 hops). Cross-domain redirects are returned without following.".to_string(),
            "Credentials can have transforms (built-in: identity, basic-auth, bearer; or custom Rhai scripts) that modify the secret before injection. Scripts run in a sandboxed runtime with resource limits.".to_string(),
        ],
    }
}

fn uuid_param(name: &str, description: &str) -> ParamDoc {
    ParamDoc {
        name: name.to_string(),
        type_name: "uuid".to_string(),
        required: true,
        description: description.to_string(),
    }
}

fn string_param(name: &str, description: &str, required: bool) -> ParamDoc {
    ParamDoc {
        name: name.to_string(),
        type_name: "string".to_string(),
        required,
        description: description.to_string(),
    }
}

fn integer_param(name: &str, description: &str) -> ParamDoc {
    ParamDoc {
        name: name.to_string(),
        type_name: "integer".to_string(),
        required: false,
        description: description.to_string(),
    }
}

fn build_all_endpoints(_config: &AppConfig) -> Vec<EndpointDoc> {
    let mut endpoints = Vec::new();

    general::push_endpoints(&mut endpoints);
    agents::push_endpoints(&mut endpoints);
    credentials::push_endpoints(&mut endpoints);
    policies::push_endpoints(&mut endpoints);
    mcp::push_endpoints(&mut endpoints);
    oauth_provider_clients::push_endpoints(&mut endpoints);
    vaults::push_endpoints(&mut endpoints);
    oidc::push_endpoints(&mut endpoints);

    endpoints
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;

    /// Helper: build docs with default test config.
    fn docs_default() -> ApiDocumentation {
        build_api_docs(&AppConfig::test_default())
    }

    /// Helper: build quickstart with default test config.
    fn quickstart_default() -> QuickstartDoc {
        build_quickstart_doc(&AppConfig::test_default())
    }

    // -----------------------------------------------------------------------
    // 1. Route completeness — every known endpoint appears in docs
    // -----------------------------------------------------------------------

    #[test]
    fn all_known_endpoints_present_in_docs() {
        let docs = docs_default();
        let documented: Vec<(String, String)> = docs
            .endpoints
            .iter()
            .map(|e| (e.method.clone(), e.path.clone()))
            .collect();

        // Exhaustive list of all endpoints in the application.
        let expected: &[(&str, &str)] = &[
            // Health
            ("GET", "/health"),
            // Auth
            ("GET", "/api/v1/auth/whoami"),
            // Agents
            ("POST", "/api/v1/agents"),
            ("GET", "/api/v1/agents"),
            ("GET", "/api/v1/agents/{id}"),
            ("PUT", "/api/v1/agents/{id}"),
            ("DELETE", "/api/v1/agents/{id}"),
            // Credentials
            ("POST", "/api/v1/credentials"),
            ("GET", "/api/v1/credentials"),
            ("GET", "/api/v1/credentials/{id}"),
            ("PUT", "/api/v1/credentials/{id}"),
            ("DELETE", "/api/v1/credentials/{id}"),
            ("POST", "/api/v1/credentials/{id}/reveal"),
            ("GET", "/api/v1/credentials/by-name/{name}"),
            // Permissions
            ("GET", "/api/v1/credentials/{id}/permissions"),
            ("POST", "/api/v1/credentials/{id}/permissions"),
            ("PUT", "/api/v1/credentials/{id}/permissions"),
            (
                "DELETE",
                "/api/v1/credentials/{id}/permissions/{agent_id}/{permission}",
            ),
            // Policies
            ("POST", "/api/v1/policies"),
            ("GET", "/api/v1/policies"),
            ("GET", "/api/v1/policies/{id}"),
            ("PUT", "/api/v1/policies/{id}"),
            ("DELETE", "/api/v1/policies/{id}"),
            ("GET", "/api/v1/policies/schema"),
            ("POST", "/api/v1/policies/validate"),
            // Policy Analysis
            ("POST", "/api/v1/policies/rsop"),
            ("GET", "/api/v1/policies/schema/reference"),
            // Audit
            ("GET", "/api/v1/audit"),
            ("GET", "/api/v1/audit/{id}"),
            // Docs (self-referential)
            ("GET", "/api/v1/docs"),
            ("GET", "/api/v1/docs/quickstart"),
            // Vaults
            ("GET", "/api/v1/vaults"),
            ("GET", "/api/v1/vaults/{name}/credentials"),
            ("POST", "/api/v1/vaults/{name}/shares"),
            ("GET", "/api/v1/vaults/{name}/shares"),
            ("DELETE", "/api/v1/vaults/{name}/shares/{user_id}"),
            // OIDC Authentication
            ("GET", "/api/v1/auth/oidc/providers"),
            ("GET", "/api/v1/auth/oidc/authorize"),
            ("GET", "/api/v1/auth/oidc/callback"),
            // OIDC Provider Management
            ("POST", "/api/v1/oidc-providers"),
            ("GET", "/api/v1/oidc-providers"),
            ("GET", "/api/v1/oidc-providers/{id}"),
            ("PUT", "/api/v1/oidc-providers/{id}"),
            ("DELETE", "/api/v1/oidc-providers/{id}"),
            // MCP Servers
            ("POST", "/api/v1/mcp-servers/import"),
            ("GET", "/api/v1/mcp-servers"),
            ("GET", "/api/v1/mcp-servers/{id}"),
            ("PUT", "/api/v1/mcp-servers/{id}"),
            ("DELETE", "/api/v1/mcp-servers/{id}"),
            ("POST", "/api/v1/mcp-servers/{id}/generate-policies"),
            // MCP Proxy
            ("POST", "/api/v1/mcp/proxy"),
            // Device SSE Events
            ("GET", "/api/v1/devices/events"),
            // Admin
            ("POST", "/api/v1/admin/rotate-key"),
            // Credential Templates
            ("GET", "/api/v1/credential-templates"),
            // MCP Templates
            ("GET", "/api/v1/mcp-templates"),
            // MCP Provisioning
            ("POST", "/api/v1/mcp-servers/provision"),
            // OAuth Provider Clients
            ("POST", "/api/v1/oauth-provider-clients"),
            ("GET", "/api/v1/oauth-provider-clients"),
            ("GET", "/api/v1/oauth-provider-clients/{id}"),
            ("PUT", "/api/v1/oauth-provider-clients/{id}"),
            ("DELETE", "/api/v1/oauth-provider-clients/{id}"),
        ];

        for (method, path) in expected {
            assert!(
                documented.contains(&(method.to_string(), path.to_string())),
                "Missing endpoint in docs: {} {}",
                method,
                path,
            );
        }

        // Also ensure docs does not contain extra undocumented endpoints
        // (would indicate a stale or spurious entry).
        assert_eq!(
            documented.len(),
            expected.len(),
            "Endpoint count mismatch: docs has {} but expected {}. \
             Extra entries may indicate stale documentation.",
            documented.len(),
            expected.len(),
        );
    }

    // -----------------------------------------------------------------------
    // 2. Error code coverage — all ApiError variants appear in error_format.codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_error_codes_present_in_error_format() {
        let docs = docs_default();
        let codes: Vec<&str> = docs
            .error_format
            .codes
            .iter()
            .map(|c| c.code.as_str())
            .collect();

        // These correspond 1:1 with ApiError variants via response.rs
        let expected_codes = [
            "not_found",
            "unauthorized",
            "forbidden",
            "bad_request",
            "conflict",
            "gone",
            "internal_error",
            "bad_gateway",
            "credential_leak_detected",
        ];

        for code in &expected_codes {
            assert!(
                codes.contains(code),
                "Error code '{}' missing from error_format.codes",
                code,
            );
        }

        assert_eq!(
            codes.len(),
            expected_codes.len(),
            "Error code count mismatch: docs has {} but expected {}",
            codes.len(),
            expected_codes.len(),
        );
    }

    // -----------------------------------------------------------------------
    // 3. Auth info — JWT method listed
    // -----------------------------------------------------------------------

    #[test]
    fn auth_info_lists_jwt() {
        let docs = docs_default();
        let methods: Vec<&str> = docs
            .authentication
            .methods
            .iter()
            .map(|m| m.method.as_str())
            .collect();

        assert!(methods.contains(&"jwt"), "Auth methods should include jwt");
        assert_eq!(methods.len(), 1, "Expected exactly 1 auth method");

        let jwt_method = docs
            .authentication
            .methods
            .iter()
            .find(|m| m.method == "jwt")
            .expect("jwt method should exist");
        assert!(
            jwt_method.ttl_seconds.is_some(),
            "JWT method should have a ttl_seconds"
        );
    }

    // -----------------------------------------------------------------------
    // 4. Proxy guide — non-empty, contains placeholder syntax
    // -----------------------------------------------------------------------

    #[test]
    fn proxy_guide_non_empty_and_contains_placeholder_syntax() {
        let docs = docs_default();
        let guide = &docs.proxy_guide;

        assert!(
            !guide.endpoint.is_empty(),
            "Proxy guide endpoint should not be empty"
        );
        assert!(
            !guide.description.is_empty(),
            "Proxy guide description should not be empty"
        );
        assert!(
            guide.placeholder_syntax.contains("{{"),
            "Proxy guide placeholder_syntax should contain placeholder braces"
        );
        assert!(
            !guide.workflow_steps.is_empty(),
            "Proxy guide workflow_steps should not be empty"
        );
        assert!(
            !guide.security_notes.is_empty(),
            "Proxy guide security_notes should not be empty"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Quickstart validation — all three sections present and non-null
    // -----------------------------------------------------------------------

    #[test]
    fn quickstart_has_all_sections() {
        let qs = quickstart_default();

        assert!(
            !qs.authentication.is_null(),
            "Quickstart authentication should not be null"
        );
        assert!(!qs.proxy.is_null(), "Quickstart proxy should not be null");
        assert!(!qs.errors.is_null(), "Quickstart errors should not be null");

        // Each section should be a JSON object (not a scalar or array)
        assert!(
            qs.authentication.is_object(),
            "Quickstart authentication should be an object"
        );
        assert!(qs.proxy.is_object(), "Quickstart proxy should be an object");
        assert!(
            qs.errors.is_object(),
            "Quickstart errors should be an object"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Serialization round-trip — JSON serialization does not panic
    // -----------------------------------------------------------------------

    #[test]
    fn build_api_docs_serializes_to_valid_json() {
        let docs = docs_default();
        let json_str = serde_json::to_string(&docs).expect("ApiDocumentation should serialize");
        let parsed: Value =
            serde_json::from_str(&json_str).expect("Serialized docs should parse back");
        assert!(parsed.is_object(), "Parsed docs should be a JSON object");
        assert!(
            parsed.get("endpoints").is_some(),
            "Parsed docs should have endpoints key"
        );
    }

    #[test]
    fn build_quickstart_doc_serializes_to_valid_json() {
        let qs = quickstart_default();
        let json_str = serde_json::to_string(&qs).expect("QuickstartDoc should serialize");
        let parsed: Value =
            serde_json::from_str(&json_str).expect("Serialized quickstart should parse back");
        assert!(
            parsed.is_object(),
            "Parsed quickstart should be a JSON object"
        );
        assert!(
            parsed.get("authentication").is_some(),
            "Parsed quickstart should have authentication key"
        );
        assert!(
            parsed.get("proxy").is_some(),
            "Parsed quickstart should have proxy key"
        );
        assert!(
            parsed.get("errors").is_some(),
            "Parsed quickstart should have errors key"
        );
    }

    #[test]
    fn jwt_ttl_reflects_config_value() {
        let mut config = AppConfig::test_default();
        config.jwt_ttl_seconds = 42;
        let docs = build_api_docs(&config);

        let jwt_method = docs
            .authentication
            .methods
            .iter()
            .find(|m| m.method == "jwt")
            .expect("jwt method should exist");
        assert_eq!(
            jwt_method.ttl_seconds,
            Some(42),
            "JWT TTL should reflect the config value"
        );
    }
}
