use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use agent_cordon_core::domain::audit::{AuditDecision, AuditEvent};
use agent_cordon_core::domain::policy::PolicyDecisionResult;
use agent_cordon_core::policy::{actions, PolicyContext, PolicyEngine, PolicyResource};
use agent_cordon_core::storage::AuditFilter;

use crate::extractors::AuthenticatedActor;
use crate::response::ApiError;
use crate::state::AppState;

use super::{CSV_EXPORT_MAX_ROWS, EXPORT_MAX_ROWS};

#[derive(Deserialize)]
pub(super) struct AuditExportQuery {
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
}

// ---------------------------------------------------------------------------
// CSV Export
// ---------------------------------------------------------------------------

/// Escape a field value for CSV output.
///
/// If the value contains a comma, double-quote, or newline, the entire field
/// is wrapped in double quotes and any internal double-quotes are doubled.
pub(super) fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        value.to_string()
    }
}

/// Serialize an `AuditEvent` to a single CSV row.
fn audit_event_to_csv_row(event: &AuditEvent) -> String {
    let event_type_str = serde_json::to_value(&event.event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let decision_str = serde_json::to_value(&event.decision)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let workspace_id_str = event
        .workspace_id
        .as_ref()
        .map(|id| id.0.to_string())
        .unwrap_or_default();

    let metadata_str = if event.metadata.is_null() {
        String::new()
    } else {
        serde_json::to_string(&event.metadata).unwrap_or_default()
    };

    let fields = [
        csv_escape(&event.timestamp.to_rfc3339()),
        csv_escape(&event.correlation_id),
        csv_escape(&event_type_str),
        csv_escape(event.user_id.as_deref().unwrap_or("")),
        csv_escape(event.user_name.as_deref().unwrap_or("")),
        csv_escape(&workspace_id_str),
        csv_escape(event.workspace_name.as_deref().unwrap_or("")),
        csv_escape(&event.action),
        csv_escape(&event.resource_type),
        csv_escape(event.resource_id.as_deref().unwrap_or("")),
        csv_escape(&decision_str),
        csv_escape(event.decision_reason.as_deref().unwrap_or("")),
        csv_escape(&metadata_str),
    ];
    fields.join(",")
}

pub(super) async fn export_audit_csv(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Query(q): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    // Policy check: require view_audit permission (same as list_audit)
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision != PolicyDecisionResult::Permit {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    // Fetch up to CSV_EXPORT_MAX_ROWS + 1 to detect truncation
    let events = state
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: CSV_EXPORT_MAX_ROWS + 1,
            resource_type: q.resource_type,
            resource_id: q.resource_id,
            ..Default::default()
        })
        .await?;

    let truncated = events.len() > CSV_EXPORT_MAX_ROWS as usize;
    let export_events = if truncated {
        &events[..CSV_EXPORT_MAX_ROWS as usize]
    } else {
        &events
    };

    // Build CSV content
    let mut csv = String::with_capacity(export_events.len() * 256);

    // Header row
    csv.push_str("timestamp,correlation_id,event_type,user_id,user_name,workspace_id,workspace_name,action,resource_type,resource_id,decision,decision_reason,metadata\n");

    for event in export_events {
        csv.push_str(&audit_event_to_csv_row(event));
        csv.push('\n');
    }

    if truncated {
        csv.push_str(&format!(
            "# Export truncated: results exceeded {} row limit\n",
            CSV_EXPORT_MAX_ROWS
        ));
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("audit-export-{}.csv", timestamp);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        csv,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Syslog Export (RFC 5424)
// ---------------------------------------------------------------------------

/// RFC 5424 syslog priority for local0 facility.
/// local0 = facility 16, so facility code = 16 * 8 = 128.
/// info = severity 6 -> priority 134
/// err  = severity 3 -> priority 131
pub(super) fn syslog_priority(decision: &AuditDecision) -> u8 {
    match decision {
        AuditDecision::Permit => 134,        // local0.info
        AuditDecision::Forbid => 131,        // local0.err
        AuditDecision::Error => 131,         // local0.err
        AuditDecision::NotApplicable => 134, // local0.info
    }
}

/// Escape a value for use in RFC 5424 structured data (SD-PARAM).
/// Per RFC 5424 section 6.3.3, within SD-PARAM values the characters
/// `"`, `\`, and `]` must be escaped with a preceding backslash.
pub(super) fn sd_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' | '\\' | ']' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Serialize an `AuditEvent` to an RFC 5424 syslog line.
fn audit_event_to_syslog(event: &AuditEvent, hostname: &str) -> String {
    let priority = syslog_priority(&event.decision);

    let event_type_str = serde_json::to_value(&event.event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let decision_str = serde_json::to_value(&event.decision)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    let workspace_id_str = event
        .workspace_id
        .as_ref()
        .map(|id| id.0.to_string())
        .unwrap_or_else(|| "-".to_string());

    // Build structured data element
    let sd = format!(
        "[meta event_type=\"{}\" user=\"{}\" workspace=\"{}\" action=\"{}\" resource_type=\"{}\" resource_id=\"{}\" decision=\"{}\"]",
        sd_escape(&event_type_str),
        sd_escape(event.user_id.as_deref().unwrap_or("-")),
        sd_escape(&workspace_id_str),
        sd_escape(&event.action),
        sd_escape(&event.resource_type),
        sd_escape(event.resource_id.as_deref().unwrap_or("-")),
        sd_escape(&decision_str),
    );

    // Build human-readable message
    let msg = format!(
        "{} {} on {}/{}",
        decision_str,
        event.action,
        event.resource_type,
        event.resource_id.as_deref().unwrap_or("-"),
    );

    // RFC 5424 format:
    // <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    format!(
        "<{}>1 {} {} AgentCordon - {} {} {}",
        priority,
        event.timestamp.to_rfc3339(),
        hostname,
        event.correlation_id,
        sd,
        msg,
    )
}

pub(super) async fn export_audit_syslog(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Query(q): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    // Policy check: require view_audit permission
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision != PolicyDecisionResult::Permit {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let events = state
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: EXPORT_MAX_ROWS,
            resource_type: q.resource_type,
            resource_id: q.resource_id,
            ..Default::default()
        })
        .await?;

    // Use a stable hostname; the actual machine hostname is not meaningful
    // in containerized deployments, so we use the app name.
    let hostname = "AgentCordon";

    let mut output = String::with_capacity(events.len() * 300);
    for event in &events {
        output.push_str(&audit_event_to_syslog(event, hostname));
        output.push('\n');
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("audit-export-{}.log", timestamp);

    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        output,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// JSON Lines Export (NDJSON)
// ---------------------------------------------------------------------------

pub(super) async fn export_audit_jsonl(
    State(state): State<AppState>,
    actor: AuthenticatedActor,
    Query(q): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    // Policy check: require view_audit permission
    let decision = state.policy_engine.evaluate(
        &actor.policy_principal(),
        actions::VIEW_AUDIT,
        &PolicyResource::System,
        &PolicyContext {
            target_url: None,
            requested_scopes: vec![],
            ..Default::default()
        },
    )?;

    if decision.decision != PolicyDecisionResult::Permit {
        return Err(ApiError::Forbidden("access denied by policy".to_string()));
    }

    let events = state
        .store
        .list_audit_events_filtered(&AuditFilter {
            limit: EXPORT_MAX_ROWS,
            resource_type: q.resource_type,
            resource_id: q.resource_id,
            ..Default::default()
        })
        .await?;

    let mut output = String::with_capacity(events.len() * 400);
    for event in &events {
        // Each line is a complete JSON object — no pretty-printing
        if let Ok(json_line) = serde_json::to_string(event) {
            output.push_str(&json_line);
            output.push('\n');
        }
    }

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let filename = format!("audit-export-{}.jsonl", timestamp);

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-ndjson".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        output,
    )
        .into_response())
}
