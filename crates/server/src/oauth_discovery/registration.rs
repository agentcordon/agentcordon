use serde::{Deserialize, Serialize};

use super::error::DiscoveryError;
use super::metadata::{discovery_http_client, AuthorizationServerMetadata};

#[derive(Debug, Clone, Serialize)]
pub struct DcrRequest<'a> {
    pub client_name: &'a str,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<&'static str>,
    pub response_types: Vec<&'static str>,
    pub token_endpoint_auth_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DcrResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_id_issued_at: Option<i64>,
    #[serde(default)]
    pub client_secret_expires_at: Option<i64>,
    #[serde(default)]
    pub registration_access_token: Option<String>,
    #[serde(default)]
    pub registration_client_uri: Option<String>,
}

/// Register a new client at the authorization server via RFC 7591.
///
/// Chooses `token_endpoint_auth_method` from what the AS supports:
/// - `none` if supported (PKCE-only public client — preferred for AgentCordon)
/// - `client_secret_basic` otherwise
pub async fn register_client(
    as_metadata: &AuthorizationServerMetadata,
    redirect_uri: &str,
    client_name: &str,
    scopes: Option<&str>,
) -> Result<DcrResponse, DiscoveryError> {
    let registration_endpoint = as_metadata
        .registration_endpoint
        .as_ref()
        .ok_or(DiscoveryError::NoDcrSupport)?;

    let auth_method = if as_metadata
        .token_endpoint_auth_methods_supported
        .iter()
        .any(|m| m == "none")
    {
        "none"
    } else {
        "client_secret_basic"
    };

    let req = DcrRequest {
        client_name,
        redirect_uris: vec![redirect_uri.to_string()],
        grant_types: vec!["authorization_code", "refresh_token"],
        response_types: vec!["code"],
        token_endpoint_auth_method: auth_method,
        scope: scopes.map(|s| s.to_string()),
    };

    let client = discovery_http_client();
    let resp = client
        .post(registration_endpoint)
        .json(&req)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                DiscoveryError::Timeout
            } else {
                DiscoveryError::RequestFailed(e.to_string())
            }
        })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(DiscoveryError::RegistrationFailed {
            status: status.as_u16(),
        });
    }

    let dcr_resp: DcrResponse = resp
        .json()
        .await
        .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
    Ok(dcr_resp)
}

/// RFC 7592: re-read / rotate a registered client using registration_access_token.
pub async fn rotate_registration(
    registration_client_uri: &str,
    registration_access_token: &str,
) -> Result<DcrResponse, DiscoveryError> {
    let client = discovery_http_client();
    let resp = client
        .get(registration_client_uri)
        .bearer_auth(registration_access_token)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                DiscoveryError::Timeout
            } else {
                DiscoveryError::RequestFailed(e.to_string())
            }
        })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(DiscoveryError::RegistrationFailed {
            status: status.as_u16(),
        });
    }

    let dcr_resp: DcrResponse = resp
        .json()
        .await
        .map_err(|e| DiscoveryError::InvalidMetadata(e.to_string()))?;
    Ok(dcr_resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcr_request_serialization() {
        let req = DcrRequest {
            client_name: "AgentCordon",
            redirect_uris: vec!["http://localhost:3140/cb".to_string()],
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            token_endpoint_auth_method: "none",
            scope: Some("read write".to_string()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["client_name"], "AgentCordon");
        assert_eq!(json["token_endpoint_auth_method"], "none");
        assert_eq!(json["scope"], "read write");
        assert_eq!(json["grant_types"][0], "authorization_code");
    }

    #[test]
    fn test_dcr_request_serialization_omits_scope() {
        let req = DcrRequest {
            client_name: "x",
            redirect_uris: vec!["http://localhost/cb".to_string()],
            grant_types: vec!["authorization_code"],
            response_types: vec!["code"],
            token_endpoint_auth_method: "none",
            scope: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("scope").is_none());
    }

    #[test]
    fn test_dcr_response_deserialization() {
        let body = serde_json::json!({
            "client_id": "abc",
            "client_secret": "shh",
            "client_id_issued_at": 1700000000,
            "client_secret_expires_at": 0,
            "registration_access_token": "rat",
            "registration_client_uri": "https://as.example.com/reg/abc"
        });
        let resp: DcrResponse = serde_json::from_value(body).unwrap();
        assert_eq!(resp.client_id, "abc");
        assert_eq!(resp.client_secret.as_deref(), Some("shh"));
        assert_eq!(resp.registration_access_token.as_deref(), Some("rat"));
    }

    #[test]
    fn test_dcr_response_public_client() {
        let body = serde_json::json!({ "client_id": "pub" });
        let resp: DcrResponse = serde_json::from_value(body).unwrap();
        assert_eq!(resp.client_id, "pub");
        assert!(resp.client_secret.is_none());
        assert!(resp.registration_access_token.is_none());
    }
}
