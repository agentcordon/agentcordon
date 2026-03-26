//! OIDC client for OpenID Connect discovery, token exchange, and ID token validation.
//!
//! This module implements the core OIDC authorization code flow logic:
//! - Discovery: fetches `.well-known/openid-configuration`
//! - Token exchange: exchanges authorization code for tokens
//! - ID token validation: verifies JWT signature, issuer, audience, expiry, nonce

use std::collections::HashMap;

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// OIDC discovery document (subset of OpenID Provider Metadata).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

/// JWKS (JSON Web Key Set) document.
#[derive(Debug, Clone, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkKey>,
}

/// A single JWK key.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    // RSA fields
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

/// Token response from the OIDC provider.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Parsed ID token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Subject identifier
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience (can be a single string or array)
    pub aud: serde_json::Value,
    /// Expiration time (unix timestamp)
    pub exp: u64,
    /// Issued at time (unix timestamp)
    #[serde(default)]
    pub iat: Option<u64>,
    /// Nonce
    #[serde(default)]
    pub nonce: Option<String>,
    /// Email claim
    #[serde(default)]
    pub email: Option<String>,
    /// Name claim
    #[serde(default)]
    pub name: Option<String>,
    /// Preferred username
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// All other claims as raw JSON
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Errors from OIDC operations.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("OIDC token exchange failed: {0}")]
    TokenExchange(String),
    #[error("OIDC ID token validation failed: {0}")]
    Validation(String),
    #[error("OIDC JWKS fetch failed: {0}")]
    JwksFetch(String),
    #[error("OIDC key not found: {0}")]
    KeyNotFound(String),
}

/// OIDC client that performs discovery, token exchange, and ID token validation.
pub struct OidcClient {
    http_client: reqwest::Client,
    /// Clock skew tolerance in seconds for token validation.
    clock_skew_seconds: u64,
}

impl OidcClient {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http_client,
            clock_skew_seconds: 60,
        }
    }

    /// Fetch the OIDC discovery document from the issuer.
    pub async fn discover(&self, issuer_url: &str) -> Result<OidcDiscoveryDocument, OidcError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(format!("HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(OidcError::Discovery(format!(
                "HTTP {} from discovery endpoint",
                resp.status()
            )));
        }

        let doc: OidcDiscoveryDocument = resp.json().await.map_err(|e| {
            OidcError::Discovery(format!("failed to parse discovery document: {}", e))
        })?;

        // Validate issuer matches
        let expected_issuer = issuer_url.trim_end_matches('/');
        let actual_issuer = doc.issuer.trim_end_matches('/');
        if expected_issuer != actual_issuer {
            return Err(OidcError::Discovery(format!(
                "issuer mismatch: expected '{}', got '{}'",
                expected_issuer, actual_issuer
            )));
        }

        Ok(doc)
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        redirect_uri: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<TokenResponse, OidcError> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ];

        let resp = self
            .http_client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| OidcError::TokenExchange(format!("HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            // SECURITY: do not include response body (may contain sensitive info)
            return Err(OidcError::TokenExchange(format!(
                "HTTP {} from token endpoint",
                resp.status()
            )));
        }

        let token_resp: TokenResponse = resp.json().await.map_err(|e| {
            OidcError::TokenExchange(format!("failed to parse token response: {}", e))
        })?;

        Ok(token_resp)
    }

    /// Fetch the JWKS from the provider.
    async fn fetch_jwks(&self, jwks_uri: &str) -> Result<JwksDocument, OidcError> {
        let resp = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(OidcError::JwksFetch(format!(
                "HTTP {} from JWKS endpoint",
                resp.status()
            )));
        }

        let jwks: JwksDocument = resp
            .json()
            .await
            .map_err(|e| OidcError::JwksFetch(format!("failed to parse JWKS: {}", e)))?;

        Ok(jwks)
    }

    /// Validate an ID token JWT.
    ///
    /// Performs:
    /// - JWKS fetch and key selection by `kid`
    /// - JWT signature verification
    /// - Issuer validation
    /// - Audience validation
    /// - Expiry validation (with clock skew tolerance)
    /// - Nonce validation
    pub async fn validate_id_token(
        &self,
        id_token: &str,
        jwks_uri: &str,
        issuer: &str,
        client_id: &str,
        expected_nonce: &str,
    ) -> Result<IdTokenClaims, OidcError> {
        // Decode the header to find the key ID
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| OidcError::Validation(format!("failed to decode JWT header: {}", e)))?;

        let kid = header.kid.as_deref();

        // Fetch JWKS
        let jwks = self.fetch_jwks(jwks_uri).await?;

        // Find the matching key
        let key = self.find_key(&jwks, kid, &header.alg)?;

        // Build validation
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[client_id]);
        // Apply clock skew tolerance
        validation.leeway = self.clock_skew_seconds;

        // Decode and validate the token
        let token_data = decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| OidcError::Validation(format!("JWT validation failed: {}", e)))?;

        let claims = token_data.claims;

        // Validate nonce
        match &claims.nonce {
            Some(nonce) if nonce == expected_nonce => {}
            Some(_) => {
                return Err(OidcError::Validation("nonce mismatch".to_string()));
            }
            None => {
                return Err(OidcError::Validation(
                    "missing nonce in ID token".to_string(),
                ));
            }
        }

        Ok(claims)
    }

    /// Find a decoding key from the JWKS matching the given `kid` and algorithm.
    fn find_key(
        &self,
        jwks: &JwksDocument,
        kid: Option<&str>,
        alg: &Algorithm,
    ) -> Result<DecodingKey, OidcError> {
        // Filter keys by use=sig (if specified)
        let signing_keys: Vec<&JwkKey> = jwks
            .keys
            .iter()
            .filter(|k| k.key_use.as_deref() != Some("enc")) // exclude encryption-only keys
            .collect();

        // Find key by kid if provided
        let key = if let Some(kid) = kid {
            signing_keys
                .iter()
                .find(|k| k.kid.as_deref() == Some(kid))
                .ok_or_else(|| OidcError::KeyNotFound(format!("no key found with kid '{}'", kid)))?
        } else if signing_keys.len() == 1 {
            // If no kid and only one signing key, use it
            signing_keys[0]
        } else {
            return Err(OidcError::KeyNotFound(
                "no kid in JWT header and multiple keys in JWKS".to_string(),
            ));
        };

        // Build the DecodingKey based on algorithm
        match alg {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                let n = key.n.as_deref().ok_or_else(|| {
                    OidcError::KeyNotFound("RSA key missing 'n' component".to_string())
                })?;
                let e = key.e.as_deref().ok_or_else(|| {
                    OidcError::KeyNotFound("RSA key missing 'e' component".to_string())
                })?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| OidcError::KeyNotFound(format!("invalid RSA key: {}", e)))
            }
            _ => Err(OidcError::Validation(format!(
                "unsupported JWT algorithm: {:?}",
                alg
            ))),
        }
    }
}

impl Default for OidcClient {
    fn default() -> Self {
        Self::new()
    }
}
