use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use uuid::Uuid;

use agent_cordon_core::auth::jwt::AUDIENCE_WORKSPACE_IDENTITY;
use agent_cordon_core::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};

use crate::response::ApiError;
use crate::state::AppState;

/// An authenticated workspace, validated via a server-signed workspace identity JWT
/// in the `Authorization: Bearer` header.
///
/// This is the single auth extractor for all workspace requests.
pub struct AuthenticatedWorkspace {
    pub workspace: Workspace,
}

impl AuthenticatedWorkspace {
    /// Backward-compat accessor: returns the workspace as `agent`.
    pub fn agent(&self) -> &Workspace {
        &self.workspace
    }
}

impl<S> FromRequestParts<S> for AuthenticatedWorkspace
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::Unauthorized("workspace authentication required".to_string())
            })?;

        let workspace = authenticate_workspace(&app_state, auth_header).await?;
        Ok(AuthenticatedWorkspace { workspace })
    }
}

/// Authenticate a workspace via server-signed JWT in the Authorization header.
///
/// Validates the JWT against the server's own signing key (JWKS), checks audience
/// `agentcordon:workspace-identity`, looks up the workspace, and verifies status/enabled.
/// Anti-replay is provided by the short JWT TTL (5 min).
pub(crate) async fn authenticate_workspace(
    state: &AppState,
    auth_header: &str,
) -> Result<Workspace, ApiError> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("expected Bearer token".to_string()))?;

    // Validate JWT against server's own signing key with workspace-identity audience
    let ws_claims = state
        .jwt_issuer
        .validate_custom_audience(token, AUDIENCE_WORKSPACE_IDENTITY)
        .map_err(|e| ApiError::Unauthorized(format!("invalid workspace JWT: {}", e)))?;

    let workspace_id_str = ws_claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::Unauthorized("missing sub in workspace JWT".to_string()))?;

    let workspace_id = Uuid::parse_str(workspace_id_str)
        .map_err(|_| ApiError::Unauthorized("invalid workspace_id in sub".to_string()))?;

    // Look up the workspace
    let workspace = state
        .store
        .get_workspace(&WorkspaceId(workspace_id))
        .await?
        .ok_or_else(|| ApiError::Unauthorized("workspace not found".to_string()))?;

    if workspace.status != WorkspaceStatus::Active {
        return Err(ApiError::Unauthorized(
            "workspace is not active".to_string(),
        ));
    }

    if !workspace.enabled {
        return Err(ApiError::Forbidden("workspace is disabled".to_string()));
    }

    // NOTE: JTI replay protection is intentionally NOT enforced here.
    // Workspace identity JWTs are bearer tokens reused for multiple server calls
    // within their short TTL (5 min). The device proxy makes several server calls
    // per agent request (credential resolve, permissions fetch, credential vend)
    // with the same JWT. Single-use JTI enforcement breaks this flow.
    // Anti-replay is provided by the short TTL + server-signed JWT.

    // Update last_authenticated_at
    let now = chrono::Utc::now();
    state
        .store
        .touch_workspace_authenticated(&workspace.id, &now)
        .await?;

    tracing::debug!(
        workspace_id = %workspace.id.0,
        auth_method = "workspace_identity",
        "request authenticated via workspace identity JWT"
    );

    Ok(workspace)
}
