//! Shared credential transform logic for injecting credentials into outgoing HTTP requests.
//!
//! This module consolidates the credential application logic that was previously
//! split between `proxy.rs` and `transforms.rs`. It is designed to be usable from
//! both the CLI proxy command and CLI mcp-serve — no dependency on axum or HTTP
//! server types.

use std::collections::HashMap;

use agent_cordon_core::transform::rhai_engine::resolve_transform;
use agent_cordon_core::transform::TransformOutput;

use crate::cp_client::CredentialMaterial;

/// Error from applying a credential transform to an outgoing request.
#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("transform failed: {0}")]
    TransformFailed(String),
}

/// Result of applying a credential transform: headers and query params to add.
#[derive(Debug, Default)]
pub struct TransformedRequest {
    /// Headers to set on the outgoing request (key → value).
    pub headers: HashMap<String, String>,
    /// Query parameters to append to the URL (key → value).
    pub query_params: HashMap<String, String>,
}

/// Apply credential material to an outgoing request.
///
/// Supports all credential types:
/// - `bearer`, `generic`, `oauth2_client_credentials` → `Authorization: Bearer <value>`
/// - `basic` → `Authorization: Basic <base64>`
/// - `aws` → AWS SigV4 headers (Authorization, x-amz-date, x-amz-content-sha256)
/// - `api_key_header` → custom header injection (header name from metadata)
/// - `api_key_query` → query parameter injection (param name from metadata)
/// - Custom Rhai scripts via `transform_name` / `transform_script`
///
/// This function is server-independent — it only operates on plain data types.
pub fn apply(
    material: &CredentialMaterial,
    transform_name: Option<&str>,
    method: &str,
    url: &str,
    existing_headers: &HashMap<String, String>,
    body: Option<&str>,
) -> Result<TransformedRequest, TransformError> {
    let credential_type = material.credential_type.as_deref().unwrap_or("bearer");

    let mut result = TransformedRequest::default();

    match credential_type {
        "api_key_header" => {
            let header_name = material
                .metadata
                .get("header_name")
                .ok_or_else(|| TransformError::MissingField("header_name".to_string()))?;
            result
                .headers
                .insert(header_name.clone(), material.value.clone());
        }
        "api_key_query" => {
            let param_name = material
                .metadata
                .get("param_name")
                .ok_or_else(|| TransformError::MissingField("param_name".to_string()))?;
            result
                .query_params
                .insert(param_name.clone(), material.value.clone());
        }
        _ => {
            // Resolve the transform_name, defaulting based on credential_type
            let effective_transform_name = transform_name.or(match credential_type {
                "bearer" | "generic" | "oauth2_client_credentials" => Some("bearer"),
                "basic" => Some("basic-auth"),
                "aws" => Some("aws-sigv4"),
                _ => None,
            });

            let body_str = body.unwrap_or("");

            let transform_output: TransformOutput = resolve_transform(
                effective_transform_name,
                None, // no custom script on this path (for now)
                &material.value,
                method,
                url,
                existing_headers,
                body_str,
            )
            .map_err(|e| TransformError::TransformFailed(e.to_string()))?;

            // Apply transform output
            if !transform_output.value.is_empty() {
                result
                    .headers
                    .insert("Authorization".to_string(), transform_output.value);
            }
            // Merge extra_headers (e.g., x-amz-date, x-amz-content-sha256 for SigV4)
            for (k, v) in &transform_output.extra_headers {
                result.headers.insert(k.clone(), v.clone());
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_material(cred_type: &str, value: &str) -> CredentialMaterial {
        CredentialMaterial {
            credential_type: Some(cred_type.to_string()),
            value: value.to_string(),
            username: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_bearer_transform() {
        let mat = make_material("bearer", "tok123");
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer tok123"
        );
        assert!(result.query_params.is_empty());
    }

    #[test]
    fn test_basic_auth_transform() {
        let mat = make_material("basic", "user:pass");
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn test_generic_defaults_to_bearer() {
        let mat = make_material("generic", "my-token");
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer my-token"
        );
    }

    #[test]
    fn test_oauth2_defaults_to_bearer() {
        let mat = make_material("oauth2_client_credentials", "oauth-tok");
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer oauth-tok"
        );
    }

    #[test]
    fn test_api_key_header() {
        let mut mat = make_material("api_key_header", "key-abc");
        mat.metadata
            .insert("header_name".to_string(), "X-Api-Key".to_string());
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.headers.get("X-Api-Key").unwrap(), "key-abc");
        assert!(!result.headers.contains_key("Authorization"));
    }

    #[test]
    fn test_api_key_header_missing_metadata() {
        let mat = make_material("api_key_header", "key-abc");
        let err = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, TransformError::MissingField(_)));
    }

    #[test]
    fn test_api_key_query() {
        let mut mat = make_material("api_key_query", "key-xyz");
        mat.metadata
            .insert("param_name".to_string(), "api_key".to_string());
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(result.query_params.get("api_key").unwrap(), "key-xyz");
        assert!(result.headers.is_empty());
    }

    #[test]
    fn test_api_key_query_missing_metadata() {
        let mat = make_material("api_key_query", "key-xyz");
        let err = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, TransformError::MissingField(_)));
    }

    #[test]
    fn test_explicit_transform_name_overrides_default() {
        // Even though credential_type is "bearer", explicit transform_name wins
        let mat = make_material("bearer", "user:pass");
        let result = apply(
            &mat,
            Some("basic-auth"),
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn test_no_credential_type_defaults_to_bearer() {
        let mat = CredentialMaterial {
            credential_type: None,
            value: "fallback-tok".to_string(),
            username: None,
            metadata: HashMap::new(),
        };
        let result = apply(
            &mat,
            None,
            "GET",
            "https://api.example.com",
            &HashMap::new(),
            None,
        )
        .unwrap();
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer fallback-tok"
        );
    }
}
