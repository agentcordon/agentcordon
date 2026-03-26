use axum::{extract::State, http::header, response::IntoResponse, Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    kid: String,
    #[serde(rename = "use")]
    key_use: String,
    alg: String,
}

/// GET `/.well-known/jwks.json`
///
/// Returns the ES256 public signing key in standard JWK Set format.
/// This endpoint is unauthenticated per standard JWKS practice.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let pub_key = &state.jwt_issuer.public_key;

    let jwk_set = JwkSet {
        keys: vec![Jwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: pub_key.x.clone(),
            y: pub_key.y.clone(),
            kid: pub_key.kid.clone(),
            key_use: "sig".to_string(),
            alg: "ES256".to_string(),
        }],
    };

    (
        [(header::CACHE_CONTROL, "public, max-age=3600")],
        Json(jwk_set),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    use crate::test_helpers::TestAppBuilder;

    async fn setup_test_app() -> Router {
        let ctx = TestAppBuilder::new().build().await;
        ctx.app
    }

    #[tokio::test]
    async fn jwks_returns_valid_jwk_set() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check Cache-Control header
        let cache_control = response
            .headers()
            .get("cache-control")
            .expect("cache-control header must be present")
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "public, max-age=3600");

        // Parse body
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Verify structure
        let keys = json["keys"].as_array().expect("keys must be an array");
        assert_eq!(keys.len(), 1);

        let key = &keys[0];
        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "ES256");
        assert!(key["x"].is_string(), "x coordinate must be present");
        assert!(key["y"].is_string(), "y coordinate must be present");
        assert!(key["kid"].is_string(), "kid must be present");
    }

    #[tokio::test]
    async fn jwks_kid_matches_jwt_kid() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

        let ctx = TestAppBuilder::new().with_admin().build().await;
        let app = ctx.app;

        // Issue a workspace identity JWT using the shared jwt_issuer
        let agent = ctx.admin_agent.expect("admin agent must exist");
        let now = chrono::Utc::now();
        let claims = serde_json::json!({
            "iss": agent_cordon_core::auth::jwt::ISSUER,
            "sub": agent.id.0.to_string(),
            "aud": agent_cordon_core::auth::jwt::AUDIENCE_WORKSPACE_IDENTITY,
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
            "wkt": "test-workspace-key",
        });
        let token = ctx
            .jwt_issuer
            .sign_custom_claims(&claims)
            .expect("issue JWT");

        // Extract kid from the JWT header (first segment, base64url-decoded JSON)
        let header_b64 = token
            .split('.')
            .next()
            .expect("JWT must have header segment");
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("valid base64url");
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("valid JSON header");
        let jwt_kid = header_json["kid"]
            .as_str()
            .expect("JWT header must contain kid");

        // Fetch JWKS endpoint
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = jwks["keys"].as_array().expect("keys must be an array");
        assert_eq!(keys.len(), 1);

        let jwks_kid = keys[0]["kid"].as_str().expect("JWKS key must contain kid");

        assert_eq!(
            jwt_kid, jwks_kid,
            "kid in JWT header must match kid in JWKS response"
        );
    }

    #[tokio::test]
    async fn jwks_requires_no_authentication() {
        let app = setup_test_app().await;

        // No auth header — should still succeed
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
