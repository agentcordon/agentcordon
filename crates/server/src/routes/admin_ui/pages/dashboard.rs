//! Dashboard page handler.

use askama::Template;
use axum::{
    extract::{Request, State},
    response::Response,
};

use crate::state::AppState;
use agent_cordon_core::domain::credential::{CredentialId, StoredCredential};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::domain::workspace::WorkspaceStatus;
use agent_cordon_core::policy::{
    actions, PolicyContext, PolicyEngine, PolicyPrincipal, PolicyResource,
};
use agent_cordon_core::storage::AuditFilter;

use super::{is_admin_user, render_template, CsrfToken, UserContext};

// ---------------------------------------------------------------------------
// Dashboard template
// ---------------------------------------------------------------------------

/// A recent audit event formatted for display in the dashboard template.
#[derive(Debug, Clone)]
pub struct DashboardEvent {
    pub id: String,
    pub timestamp: String,
    pub principal: String,
    pub event_type: String,
    pub resource_type: String,
    pub resource_id: String,
    pub resource_name: String,
    pub decision: String,
}

#[derive(Template)]
#[template(path = "pages/dashboard.html")]
pub struct DashboardPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub workspaces_total: usize,
    pub workspaces_active: usize,
    pub credentials_total: usize,
    pub credential_vending_events: Vec<DashboardEvent>,
    pub mcp_activity_events: Vec<DashboardEvent>,
}

/// GET /dashboard — render the dashboard page.
pub async fn dashboard_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Tenant scoping: admins see all data, non-admins see only their own.
    let is_admin = is_admin_user(&user);

    let workspaces = if is_admin {
        state.store.list_workspaces().await.unwrap_or_default()
    } else {
        state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default()
    };

    // Filter credentials through Cedar so non-root users only see their own count.
    let all_summaries = state.store.list_credentials().await.unwrap_or_default();
    let all_stored = state
        .store
        .list_all_stored_credentials()
        .await
        .unwrap_or_default();
    let cred_map: std::collections::HashMap<CredentialId, StoredCredential> =
        all_stored.into_iter().map(|c| (c.id.clone(), c)).collect();
    let principal = PolicyPrincipal::User(&user);
    let ctx = PolicyContext {
        target_url: None,
        requested_scopes: vec![],
        ..Default::default()
    };
    let credentials: Vec<_> = all_summaries
        .into_iter()
        .filter(|summary| {
            let cred = match cred_map.get(&summary.id) {
                Some(c) => c.clone(),
                None => return false,
            };
            // 1. Check Cedar with User principal
            if state
                .policy_engine
                .evaluate(
                    &principal,
                    actions::LIST,
                    &PolicyResource::Credential {
                        credential: cred.clone(),
                    },
                    &ctx,
                )
                .ok()
                .is_some_and(|d| d.decision != PolicyDecisionResult::Forbid)
            {
                return true;
            }
            // 2. Check Cedar with each owned Workspace principal
            for ws in &workspaces {
                if state
                    .policy_engine
                    .evaluate(
                        &PolicyPrincipal::Workspace(ws),
                        actions::LIST,
                        &PolicyResource::Credential {
                            credential: cred.clone(),
                        },
                        &ctx,
                    )
                    .ok()
                    .is_some_and(|d| d.decision != PolicyDecisionResult::Forbid)
                {
                    return true;
                }
            }
            false
        })
        .collect();
    // Fetch credential vending and MCP activity events.
    //
    // For non-admin users we need to query by BOTH user_id (user-initiated
    // actions) AND workspace_id (workspace-initiated vends/MCP calls via the
    // CLI proxy or mcp-call). The AuditFilter ANDs its conditions, so we run
    // separate queries per owned workspace and merge.
    let owned_workspace_ids: Vec<String> = if is_admin {
        vec![]
    } else {
        workspaces.iter().map(|w| w.id.0.to_string()).collect()
    };

    // Helper: fetch audit events for a given event_type, scoped to the current user.
    // Returns events matching by user_id OR by any owned workspace_id.
    let fetch_scoped_events = |store: crate::state::SharedStore,
                               event_type: String,
                               is_admin: bool,
                               user_id: String,
                               ws_ids: Vec<String>| async move {
        if is_admin {
            let filter = AuditFilter {
                limit: 5,
                event_type: Some(event_type),
                ..Default::default()
            };
            return store
                .list_audit_events_filtered(&filter)
                .await
                .unwrap_or_default();
        }

        // Query by user_id
        let user_filter = AuditFilter {
            limit: 5,
            event_type: Some(event_type.clone()),
            user_id: Some(user_id),
            ..Default::default()
        };
        let mut events = store
            .list_audit_events_filtered(&user_filter)
            .await
            .unwrap_or_default();

        // Also query by each owned workspace_id
        for ws_id in &ws_ids {
            let ws_filter = AuditFilter {
                limit: 5,
                event_type: Some(event_type.clone()),
                workspace_id: Some(ws_id.clone()),
                ..Default::default()
            };
            let ws_events = store
                .list_audit_events_filtered(&ws_filter)
                .await
                .unwrap_or_default();
            events.extend(ws_events);
        }

        // Deduplicate by event ID, sort, and truncate
        let mut seen = std::collections::HashSet::new();
        events.retain(|e| seen.insert(e.id));
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(5);
        events
    };

    let user_id_str = user.id.0.to_string();

    let cred_vend_events = fetch_scoped_events(
        state.store.clone(),
        "credential_vended".to_string(),
        is_admin,
        user_id_str.clone(),
        owned_workspace_ids.clone(),
    )
    .await;
    let cred_deny_events = fetch_scoped_events(
        state.store.clone(),
        "credential_vend_denied".to_string(),
        is_admin,
        user_id_str.clone(),
        owned_workspace_ids.clone(),
    )
    .await;
    let mut all_cred_events: Vec<_> = cred_vend_events
        .into_iter()
        .chain(cred_deny_events)
        .collect();
    all_cred_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    all_cred_events.truncate(5);

    // Fetch MCP activity events (user-initiated + workspace-initiated)
    let mcp_call_events = fetch_scoped_events(
        state.store.clone(),
        "mcp_tool_call".to_string(),
        is_admin,
        user_id_str.clone(),
        owned_workspace_ids.clone(),
    )
    .await;
    let mcp_deny_events = fetch_scoped_events(
        state.store.clone(),
        "mcp_tool_denied".to_string(),
        is_admin,
        user_id_str,
        owned_workspace_ids,
    )
    .await;
    let mut all_mcp_events: Vec<_> = mcp_call_events.into_iter().chain(mcp_deny_events).collect();
    all_mcp_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    all_mcp_events.truncate(5);

    let workspaces_total = workspaces.len();
    let workspaces_active = workspaces
        .iter()
        .filter(|w| w.status == WorkspaceStatus::Active && w.enabled)
        .count();
    let credentials_total = credentials.len();

    let to_dashboard_event = |e: agent_cordon_core::domain::audit::AuditEvent| -> DashboardEvent {
        let principal = e
            .user_name
            .as_deref()
            .or(e.workspace_name.as_deref())
            .unwrap_or("system")
            .to_string();
        let event_type = serde_json::to_value(&e.event_type)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", e.event_type));
        let decision = serde_json::to_value(&e.decision)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{:?}", e.decision));
        // Extract a human-readable resource name from metadata if available.
        let resource_name = e
            .metadata
            .as_object()
            .and_then(|m| {
                m.get("credential_name")
                    .or_else(|| m.get("tool"))
                    .or_else(|| m.get("tool_name"))
                    .or_else(|| m.get("name"))
                    .or_else(|| m.get("resource_name"))
                    .or_else(|| m.get("workspace_name"))
            })
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        DashboardEvent {
            id: e.id.to_string(),
            timestamp: e.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            principal,
            event_type,
            resource_type: e.resource_type,
            resource_id: e
                .resource_id
                .as_deref()
                .map(|s| if s.len() > 8 { &s[..8] } else { s })
                .unwrap_or("")
                .to_string(),
            resource_name,
            decision,
        }
    };

    let credential_vending_events: Vec<DashboardEvent> = all_cred_events
        .into_iter()
        .map(&to_dashboard_event)
        .collect();
    let mcp_activity_events: Vec<DashboardEvent> = all_mcp_events
        .into_iter()
        .map(&to_dashboard_event)
        .collect();

    render_template(&DashboardPage {
        show_nav: true,
        current_page: "dashboard".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        workspaces_total,
        workspaces_active,
        credentials_total,
        credential_vending_events,
        mcp_activity_events,
    })
}
