//! Audit log page handler.

use askama::Template;
use axum::{
    extract::{Path, Request, State},
    response::Response,
};
use uuid::Uuid;

use crate::state::AppState;
use agent_cordon_core::domain::audit::AuditDecision;
use agent_cordon_core::storage::AuditFilter;

use super::{is_admin_user, render_template, CsrfToken, UserContext};

// ---------------------------------------------------------------------------
// View model for audit event rows
// ---------------------------------------------------------------------------

/// Pre-formatted audit event data for Askama templates.
#[derive(serde::Serialize)]
pub struct AuditEventView {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub principal: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub resource_id_short: String,
    pub decision: String,
    pub decision_class: String,
    pub correlation_id: String,
    pub decision_reason: String,
    pub metadata_json: String,
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "pages/audit.html")]
pub struct AuditPage {
    pub show_nav: bool,
    pub current_page: String,
    pub user: UserContext,
    pub csrf_token: String,
    pub events: Vec<AuditEventView>,
    pub events_json: String,
}

/// GET /audit — render the audit log page.
pub async fn audit_page(State(state): State<AppState>, request: Request) -> Response {
    let user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    // Tenant scoping: admins see all events, non-admins see events matching
    // their user_id OR any workspace they own (workspace-initiated events like
    // credential_vended and mcp_tool_call are tagged with workspace_id, not
    // user_id).
    let is_admin = is_admin_user(&user);

    let events = if is_admin {
        let filter = AuditFilter {
            limit: 50,
            exclude_event_types: vec!["policy_evaluated".to_string()],
            ..Default::default()
        };
        state
            .store
            .list_audit_events_filtered(&filter)
            .await
            .unwrap_or_default()
    } else {
        // Query by user_id
        let user_filter = AuditFilter {
            limit: 50,
            exclude_event_types: vec!["policy_evaluated".to_string()],
            user_id: Some(user.id.0.to_string()),
            ..Default::default()
        };
        let mut events = state
            .store
            .list_audit_events_filtered(&user_filter)
            .await
            .unwrap_or_default();

        // Also query by each owned workspace_id
        let owned_workspaces = state
            .store
            .get_workspaces_by_owner(&user.id)
            .await
            .unwrap_or_default();
        for ws in &owned_workspaces {
            let ws_filter = AuditFilter {
                limit: 50,
                exclude_event_types: vec!["policy_evaluated".to_string()],
                workspace_id: Some(ws.id.0.to_string()),
                ..Default::default()
            };
            let ws_events = state
                .store
                .list_audit_events_filtered(&ws_filter)
                .await
                .unwrap_or_default();
            events.extend(ws_events);
        }

        // Deduplicate by event ID, sort newest-first, and truncate
        let mut seen = std::collections::HashSet::new();
        events.retain(|e| seen.insert(e.id));
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        events.truncate(50);
        events
    };

    let event_views: Vec<AuditEventView> = events
        .iter()
        .map(|ev| {
            let decision_str = match &ev.decision {
                AuditDecision::Permit => "permit",
                AuditDecision::Forbid => "forbid",
                AuditDecision::Error => "error",
                AuditDecision::NotApplicable => "n/a",
            };
            let decision_class = match &ev.decision {
                AuditDecision::Permit => "pill-ok",
                AuditDecision::Forbid => "pill-bad",
                _ => "pill-warn",
            };
            let principal = ev
                .workspace_name
                .as_deref()
                .or(ev.user_name.as_deref())
                .unwrap_or("\u{2014}")
                .to_string();
            let resource_id_short = ev
                .resource_id
                .as_ref()
                .map(|rid| {
                    if rid.len() > 8 {
                        format!("{}...", &rid[..8])
                    } else {
                        rid.clone()
                    }
                })
                .unwrap_or_default();

            let summary = extract_audit_summary(&ev.metadata);

            // Use serde snake_case for event_type to match the API format
            let event_type_str = serde_json::to_string(&ev.event_type)
                .unwrap_or_else(|_| format!("{:?}", ev.event_type))
                .trim_matches('"')
                .to_string();

            AuditEventView {
                id: ev.id.to_string(),
                timestamp: ev.timestamp.to_rfc3339(),
                event_type: event_type_str,
                principal,
                action: ev.action.clone(),
                resource_type: ev.resource_type.clone(),
                resource_id: ev.resource_id.clone().unwrap_or_default(),
                resource_id_short,
                decision: decision_str.to_string(),
                decision_class: decision_class.to_string(),
                correlation_id: ev.correlation_id.clone(),
                decision_reason: ev.decision_reason.clone().unwrap_or_default(),
                metadata_json: serde_json::to_string_pretty(&ev.metadata)
                    .unwrap_or_else(|_| "{}".to_string()),
                summary,
            }
        })
        .collect();

    /// Extract the most important detail from audit event metadata for inline display.
    fn extract_audit_summary(metadata: &serde_json::Value) -> String {
        if let Some(v) = metadata.get("credential_name").and_then(|v| v.as_str()) {
            return v.to_string();
        }
        if let Some(v) = metadata.get("tool").and_then(|v| v.as_str()) {
            return v.to_string();
        }
        if let Some(v) = metadata.get("tool_name").and_then(|v| v.as_str()) {
            return v.to_string();
        }
        if let Some(v) = metadata.get("name").and_then(|v| v.as_str()) {
            return v.to_string();
        }
        if let Some(v) = metadata.get("resource_name").and_then(|v| v.as_str()) {
            return v.to_string();
        }
        String::new()
    }

    let events_json = serde_json::to_string(&event_views)
        .unwrap_or_else(|_| "[]".to_string())
        .replace("</", "<\\/");

    render_template(&AuditPage {
        show_nav: true,
        current_page: "audit".to_string(),
        user: UserContext::from(&user),
        csrf_token: csrf.0,
        events: event_views,
        events_json,
    })
}

// ---------------------------------------------------------------------------
// Audit Detail Partial (for split-view AJAX loading)
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "partials/audit_detail_pane.html")]
pub struct AuditDetailPane {
    pub csrf_token: String,
    pub event_id: String,
}

/// GET /audit/{id}/detail-partial — HTML fragment for split-view right pane.
pub async fn audit_detail_partial(Path(id): Path<String>, request: Request) -> Response {
    if Uuid::parse_str(&id).is_err() {
        return Response::builder()
            .status(axum::http::StatusCode::NOT_FOUND)
            .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(axum::body::Body::from("not found"))
            .unwrap();
    }

    let _user = match super::extract_page_user(&request) {
        Ok(u) => u,
        Err(redirect) => return redirect,
    };
    let csrf = request
        .extensions()
        .get::<CsrfToken>()
        .cloned()
        .unwrap_or(CsrfToken(String::new()));

    render_template(&AuditDetailPane {
        csrf_token: csrf.0,
        event_id: id,
    })
}
