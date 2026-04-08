mod agent_store;
mod create;
mod history;
mod list;
mod manage;
mod vend;

use axum::{
    routing::{get, post},
    Router,
};

use crate::state::AppState;

use agent_store::agent_store_credential;
use create::store_credential;
use history::{list_secret_history, restore_secret_history};
use list::list_credentials;
use manage::{delete_credential, get_credential, get_credential_by_name, update_credential};
use vend::{reveal_credential, vend_credential, vend_credential_to_device};

/// Known credential types. Unknown types are rejected at creation time.
pub(crate) const KNOWN_CREDENTIAL_TYPES: &[&str] =
    &["generic", "aws", "oauth2_client_credentials", "oauth2_user_authorization"];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/credentials", post(store_credential).get(list_credentials))
        .route(
            "/credentials/{id}",
            get(get_credential)
                .put(update_credential)
                .delete(delete_credential),
        )
        .route("/credentials/{id}/reveal", post(reveal_credential))
        .route("/credentials/{id}/secret-history", get(list_secret_history))
        .route(
            "/credentials/{id}/secret-history/{history_id}/restore",
            post(restore_secret_history),
        )
        .route("/credentials/{id}/vend", post(vend_credential))
        .route("/credentials/by-name/{name}", get(get_credential_by_name))
        .route(
            "/credentials/vend-device/{name}",
            post(vend_credential_to_device),
        )
        .route("/credentials/agent-store", post(agent_store_credential))
}

/// Helper: get the actor identity strings for history tracking.
pub(crate) fn actor_identity_strings(
    actor: &crate::extractors::AuthenticatedActor,
) -> (Option<String>, Option<String>) {
    match actor {
        crate::extractors::AuthenticatedActor::User(user) => (Some(user.id.0.to_string()), None),
        crate::extractors::AuthenticatedActor::Workspace { workspace, .. } => {
            (None, Some(workspace.id.0.to_string()))
        }
    }
}

/// Enrich a list of credential summaries with `owner_username`, resolved from
/// the `created_by` (agent) or `created_by_user` (user) IDs.
pub(crate) async fn enrich_owner_usernames(
    store: &dyn agent_cordon_core::storage::Store,
    creds: &mut [agent_cordon_core::domain::credential::CredentialSummary],
) {
    for cred in creds.iter_mut() {
        // Try user first, then agent
        if let Some(ref user_id) = cred.created_by_user {
            if let Ok(Some(user)) = store.get_user(user_id).await {
                cred.owner_username = user.display_name.or(Some(user.username));
            }
        } else if let Some(ref workspace_id) = cred.created_by {
            if let Ok(Some(workspace)) = store.get_workspace(workspace_id).await {
                // Resolve through workspace's owner to the user's display name
                if let Some(ref owner_id) = workspace.owner_id {
                    if let Ok(Some(user)) = store.get_user(owner_id).await {
                        cred.owner_username = user.display_name.or(Some(user.username));
                    } else {
                        cred.owner_username = Some(workspace.name);
                    }
                } else {
                    cred.owner_username = Some(workspace.name);
                }
            }
        }
    }
}
