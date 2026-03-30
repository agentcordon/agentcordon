//! Credential transform logic — applies credential material to outgoing requests.
//!
//! Carried forward from `gateway/src/credential_transform.rs`.

use std::collections::HashMap;

use agent_cordon_core::transform::rhai_engine::resolve_transform;
use agent_cordon_core::transform::TransformOutput;

/// Error from applying a credential transform.
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
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

/// Credential material for transforms (local type, decoupled from server client).
#[derive(Debug)]
pub struct CredentialMaterial {
    pub credential_type: Option<String>,
    pub value: String,
    #[allow(dead_code)]
    pub username: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Apply credential material to an outgoing request.
///
/// Supports: bearer, basic, aws-sigv4, api_key_header, api_key_query, and
/// custom Rhai scripts via `transform_name`.
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
            let effective_transform_name = transform_name.or(match credential_type {
                "bearer" | "generic" | "oauth2_client_credentials" => Some("bearer"),
                "basic" => Some("basic-auth"),
                "aws" => Some("aws-sigv4"),
                _ => None,
            });

            let body_str = body.unwrap_or("");

            let transform_output: TransformOutput = resolve_transform(
                effective_transform_name,
                None,
                &material.value,
                method,
                url,
                existing_headers,
                body_str,
            )
            .map_err(|e| TransformError::TransformFailed(e.to_string()))?;

            if !transform_output.value.is_empty() {
                result
                    .headers
                    .insert("Authorization".to_string(), transform_output.value);
            }
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
    }

    #[test]
    fn test_no_type_defaults_to_bearer() {
        let mat = CredentialMaterial {
            credential_type: None,
            value: "fallback".to_string(),
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
            "Bearer fallback"
        );
    }
}
