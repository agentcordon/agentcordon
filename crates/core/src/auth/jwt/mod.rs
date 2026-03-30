use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AuthError;

/// Standard JWT issuer string for all AgentCordon server-issued tokens.
pub const ISSUER: &str = "agentcordon-server";

/// Well-known audience values for different token types.
pub const AUDIENCE_MCP_PERMISSIONS: &str = "agentcordon:mcp-permissions";
pub const AUDIENCE_DEVICE_AUTH: &str = "agentcordon:device-auth";

/// JWT claims structure for auth tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Not-before claim.
    pub nbf: i64,
    pub jti: String,
    pub roles: Vec<String>,
}

/// Claims for MCP permissions JWTs (server-signed, short-lived).
///
/// These tokens are issued by the server and verified by devices to authorize
/// agent access to MCP servers. Scopes use the 3-part format:
/// `{device_name}.{mcp_server_name}.{action}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPermissionsClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    /// Not-before claim.
    pub nbf: i64,
    pub jti: String,
    pub scopes: Vec<String>,
    pub device_id: String,
}

/// Trait abstracting JWT signing and validation.
///
/// This allows swapping the underlying algorithm (e.g., HS256 -> EdDSA/ES256)
/// without changing call sites.
pub trait JwtSigner: Send + Sync {
    fn sign(&self, claims: &JwtClaims) -> Result<String, AuthError>;
    fn validate(&self, token: &str, expected_audience: &str) -> Result<JwtClaims, AuthError>;
}

/// Shared JWT validation logic.
///
/// Validates signature, expiry, issuer, required claims, and audience.
fn validate_jwt_token(
    token: &str,
    decoding_key: &DecodingKey,
    algorithm: Algorithm,
    issuer: &str,
    expected_audience: &str,
) -> Result<JwtClaims, AuthError> {
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[expected_audience]);
    validation.set_required_spec_claims(&["exp", "sub", "iss", "iat", "aud"]);
    validation.validate_nbf = true;

    let token_data: TokenData<JwtClaims> =
        decode(token, decoding_key, &validation).map_err(|e| AuthError::Jwt(e.to_string()))?;

    Ok(token_data.claims)
}

/// Compute the RFC 7638 JWK thumbprint for a P-256 public key.
///
/// The thumbprint is the base64url-encoded SHA-256 hash of the canonical JWK
/// representation: `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` (alphabetical
/// order, only required members).
fn compute_kid(verifying_key: &VerifyingKey) -> String {
    let point = verifying_key.to_encoded_point(false);
    let x_bytes = point.x().expect("P-256 point must have x coordinate");
    let y_bytes = point.y().expect("P-256 point must have y coordinate");

    let x_b64 = base64_url_encode(x_bytes);
    let y_b64 = base64_url_encode(y_bytes);

    compute_p256_thumbprint(&x_b64, &y_b64)
}

/// Compute the RFC 7638 JWK thumbprint from base64url-encoded P-256 coordinates.
///
/// Takes the `x` and `y` coordinates as base64url strings (no padding) and returns
/// the base64url-encoded SHA-256 hash of the canonical JWK representation.
///
/// This is the public API for computing device key thumbprints (`dkt` claim).
pub fn compute_p256_thumbprint(x_b64: &str, y_b64: &str) -> String {
    // RFC 7638: canonical JSON with required members in alphabetical order
    let thumbprint_input = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        x_b64, y_b64
    );

    let hash = Sha256::digest(thumbprint_input.as_bytes());
    base64_url_encode(&hash)
}

/// Base64url encode without padding (per RFC 7515 / RFC 4648 §5).
pub fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Convert a P-256 signing key to PKCS#8 PEM for jsonwebtoken.
fn signing_key_to_pem(signing_key: &SigningKey) -> String {
    use p256::pkcs8::EncodePrivateKey;
    signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("P-256 key to PKCS#8 PEM should not fail")
        .to_string()
}

/// Convert a P-256 verifying key to SPKI PEM for jsonwebtoken.
fn verifying_key_to_pem(verifying_key: &VerifyingKey) -> String {
    use p256::pkcs8::EncodePublicKey;
    verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("P-256 public key to SPKI PEM should not fail")
}

/// The P-256 public key data needed for JWKS (x, y coordinates and kid).
#[derive(Clone, Debug)]
pub struct Es256PublicKey {
    /// Base64url-encoded x coordinate
    pub x: String,
    /// Base64url-encoded y coordinate
    pub y: String,
    /// Key ID (RFC 7638 thumbprint)
    pub kid: String,
}

/// Configuration for JWT operations.
#[derive(Clone)]
struct JwtConfig {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    #[allow(dead_code)]
    default_ttl_seconds: u64,
    kid: String,
}

/// Issues and validates JWTs using ES256 (P-256 ECDSA).
#[derive(Clone)]
pub struct JwtIssuer {
    config: JwtConfig,
    /// Public key data for JWKS exposure.
    pub public_key: Es256PublicKey,
}

impl JwtIssuer {
    /// Create a new JwtIssuer from an ES256 key pair.
    pub fn new(
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
        issuer: String,
        default_ttl_seconds: u64,
    ) -> Self {
        let kid = compute_kid(verifying_key);

        let private_pem = signing_key_to_pem(signing_key);
        let public_pem = verifying_key_to_pem(verifying_key);

        let encoding_key =
            EncodingKey::from_ec_pem(private_pem.as_bytes()).expect("valid EC private key PEM");
        let decoding_key =
            DecodingKey::from_ec_pem(public_pem.as_bytes()).expect("valid EC public key PEM");

        // Extract public key coordinates for JWKS
        let point = verifying_key.to_encoded_point(false);
        let x_bytes = point.x().expect("P-256 point must have x coordinate");
        let y_bytes = point.y().expect("P-256 point must have y coordinate");

        let public_key = Es256PublicKey {
            x: base64_url_encode(x_bytes),
            y: base64_url_encode(y_bytes),
            kid: kid.clone(),
        };

        Self {
            config: JwtConfig {
                encoding_key,
                decoding_key,
                issuer,
                default_ttl_seconds,
                kid,
            },
            public_key,
        }
    }

    /// Build a JWT header with ES256 algorithm and kid.
    fn jwt_header(&self) -> Header {
        Header {
            alg: Algorithm::ES256,
            kid: Some(self.config.kid.clone()),
            ..Default::default()
        }
    }

    /// Validate a JWT with a specific expected audience.
    pub fn validate_with_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<JwtClaims, AuthError> {
        validate_jwt_token(
            token,
            &self.config.decoding_key,
            Algorithm::ES256,
            &self.config.issuer,
            expected_audience,
        )
    }

    /// Sign arbitrary claims as an ES256 JWT using the control plane's signing key.
    ///
    /// This is used for bootstrap tokens and other custom claim structures
    /// that don't fit the standard auth/grant token pattern.
    pub fn sign_custom_claims<T: Serialize>(&self, claims: &T) -> Result<String, AuthError> {
        encode(&self.jwt_header(), claims, &self.config.encoding_key)
            .map_err(|e| AuthError::Jwt(e.to_string()))
    }

    /// Issue an MCP permissions JWT for an agent on a specific device.
    ///
    /// The token contains 3-part scopes (`{device}.{server}.{action}`) and is
    /// short-lived (typically 300s). Devices verify the signature and filter
    /// scopes to their own name.
    pub fn issue_mcp_permissions_token(
        &self,
        agent_id: &str,
        device_id: &str,
        scopes: Vec<String>,
        ttl_seconds: u64,
    ) -> Result<(String, McpPermissionsClaims), AuthError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(ttl_seconds as i64);

        let claims = McpPermissionsClaims {
            iss: self.config.issuer.clone(),
            sub: agent_id.to_string(),
            aud: AUDIENCE_MCP_PERMISSIONS.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            scopes,
            device_id: device_id.to_string(),
        };

        let token = encode(&self.jwt_header(), &claims, &self.config.encoding_key)
            .map_err(|e| AuthError::Jwt(e.to_string()))?;

        Ok((token, claims))
    }

    /// Validate an MCP permissions JWT. Checks signature, expiry, and audience.
    pub fn validate_mcp_permissions(&self, token: &str) -> Result<McpPermissionsClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[AUDIENCE_MCP_PERMISSIONS]);
        validation.set_required_spec_claims(&["exp", "sub", "iss", "iat", "aud"]);
        validation.validate_nbf = true;

        let token_data: TokenData<McpPermissionsClaims> =
            decode(token, &self.config.decoding_key, &validation)
                .map_err(|e| AuthError::Jwt(e.to_string()))?;

        Ok(token_data.claims)
    }

    /// Validate a JWT signed by the control plane, enforcing a specific audience.
    ///
    /// Returns the raw claims as a `serde_json::Value` on success.
    /// This is used for validating bootstrap tokens and other custom JWTs.
    pub fn validate_custom_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<serde_json::Value, AuthError> {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[expected_audience]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "iss", "nbf"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let token_data: TokenData<serde_json::Value> =
            decode(token, &self.config.decoding_key, &validation)
                .map_err(|e| AuthError::Jwt(e.to_string()))?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests;
