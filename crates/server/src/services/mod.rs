//! Application services, one per aggregate.
//!
//! A service owns the store writes, the audit event, the UI event, and any
//! policy-engine reload for its aggregate, and it answers the authorization
//! question for every state change it makes. Handlers parse input, call the
//! service, and shape the response; reads that need no state change stay in
//! the handler. `device_codes` is the reference shape.

use std::sync::Arc;

use agent_cordon_core::domain::audit::AuditEvent;
use agent_cordon_core::oauth2::OAuth2TokenManager;
use agent_cordon_core::storage::Store;

use crate::authz::Authz;
use crate::config::AppConfig;
use crate::events::UiEventBus;
use crate::rate_limit::LoginRateLimiter;
use crate::state::{CryptoState, SharedStore};

pub mod credentials;
pub mod device_codes;
pub mod identity_providers;
pub mod mcp_servers;
pub mod oauth;
pub mod policies;
pub mod upstream_tokens;
pub mod users;
pub mod vaults;
pub mod workspaces;

pub use credentials::CredentialService;
pub use device_codes::DeviceCodeService;
pub use identity_providers::IdentityProviderService;
pub use mcp_servers::McpServerService;
pub use oauth::OAuthService;
pub use policies::PolicyService;
pub use users::UserService;
pub use vaults::VaultService;
pub use workspaces::WorkspaceService;

/// Every application service, constructed once in `AppState::new`.
#[derive(Clone)]
pub struct Services {
    pub credentials: CredentialService,
    pub device_codes: DeviceCodeService,
    pub identity_providers: IdentityProviderService,
    pub mcp_servers: McpServerService,
    pub oauth: OAuthService,
    pub policies: PolicyService,
    pub users: UserService,
    pub vaults: VaultService,
    pub workspaces: WorkspaceService,
}

impl Services {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: SharedStore,
        authz: Arc<Authz>,
        crypto: CryptoState,
        ui_event_bus: UiEventBus,
        oauth2_token_manager: OAuth2TokenManager,
        login_limiter: Arc<LoginRateLimiter>,
        config: AppConfig,
    ) -> Self {
        let policies = PolicyService::new(store.clone(), authz.clone(), ui_event_bus.clone());
        let vaults = VaultService::new(store.clone(), authz.clone(), ui_event_bus.clone());
        let credentials = CredentialService::new(
            store.clone(),
            crypto.key_ring.clone(),
            authz.clone(),
            ui_event_bus.clone(),
            oauth2_token_manager,
            policies.clone(),
            vaults.clone(),
        );
        let workspaces = WorkspaceService::new(
            store.clone(),
            authz.clone(),
            ui_event_bus.clone(),
            policies.clone(),
        );
        let mcp_servers = McpServerService::new(
            store.clone(),
            authz.clone(),
            ui_event_bus.clone(),
            policies.clone(),
            credentials.clone(),
            config.clone(),
        );
        let device_codes = DeviceCodeService::new(store.clone());
        let identity_providers = IdentityProviderService::new(
            store.clone(),
            authz.clone(),
            crypto.key_ring.clone(),
            config.clone(),
        );
        let oauth = OAuthService::new(
            store.clone(),
            authz.clone(),
            device_codes.clone(),
            workspaces.clone(),
        );
        let users = UserService::new(
            store,
            authz,
            ui_event_bus,
            login_limiter,
            crypto.session_hash_key,
            config,
        );
        Self {
            credentials,
            device_codes,
            identity_providers,
            mcp_servers,
            oauth,
            policies,
            users,
            vaults,
            workspaces,
        }
    }
}

/// Append a domain audit event. Best-effort: a failed write is logged and
/// never fails the state change it describes.
pub(crate) async fn write_audit(store: &(dyn Store + Send + Sync), event: &AuditEvent) {
    if let Err(e) = store.append_audit_event(event).await {
        tracing::warn!(error = %e, "failed to write audit event");
    }
}
