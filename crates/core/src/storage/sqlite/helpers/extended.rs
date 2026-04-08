use std::str::FromStr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::domain::audit::AuditEvent;
use crate::domain::credential::CredentialId;
use crate::domain::mcp::{McpAuthMethod, McpServer, McpServerId, McpTransport};
use crate::domain::oidc::{OidcAuthState, OidcProvider, OidcProviderId, OidcProviderSummary};
use crate::domain::user::UserId;
use crate::domain::workspace::{Workspace, WorkspaceId, WorkspaceStatus};
use crate::error::StoreError;

use super::{deserialize_decision, deserialize_event_type};

pub(crate) fn row_to_audit_event(row: &rusqlite::Row<'_>) -> Result<AuditEvent, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let timestamp_str: String = row.get(1)?;
    let correlation_id: String = row.get(2)?;
    let event_type_str: String = row.get(3)?;
    let workspace_id_str: Option<String> = row.get(4)?;
    let workspace_name: Option<String> = row.get(5)?;
    let action: String = row.get(6)?;
    let resource_type: String = row.get(7)?;
    let resource_id: Option<String> = row.get(8)?;
    let decision_str: String = row.get(9)?;
    let decision_reason: Option<String> = row.get(10)?;
    let metadata_json: String = row.get(11)?;
    let user_id: Option<String> = row.get(12)?;
    let user_name: Option<String> = row.get(13)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let event_type = deserialize_event_type(&event_type_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let workspace_id = workspace_id_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let decision = deserialize_decision(&decision_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(AuditEvent {
        id,
        timestamp,
        correlation_id,
        event_type,
        workspace_id,
        workspace_name,
        user_id,
        user_name,
        action,
        resource_type,
        resource_id,
        decision,
        decision_reason,
        metadata,
    })
}

/// Map a row from the `workspaces` table to a `Workspace` domain type.
/// Column order must match `WORKSPACE_COLUMNS`:
/// id, name, enabled, status, pk_hash, encryption_public_key, tags, owner_id,
/// parent_id, tool_name, enrollment_token_hash, last_authenticated_at, created_at, updated_at
pub(crate) fn row_to_workspace(row: &rusqlite::Row<'_>) -> Result<Workspace, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let enabled: bool = row.get(2)?;
    let status_str: String = row.get(3)?;
    let pk_hash: Option<String> = row.get(4)?;
    let encryption_public_key: Option<String> = row.get(5)?;
    let tags_json: String = row.get(6)?;
    let owner_id_str: Option<String> = row.get(7)?;
    let parent_id_str: Option<String> = row.get(8)?;
    let tool_name: Option<String> = row.get(9)?;
    let _enrollment_token_hash: Option<String> = row.get(10)?;
    let _last_authenticated_at_str: Option<String> = row.get(11)?;
    let created_at_str: String = row.get(12)?;
    let updated_at_str: String = row.get(13)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let status = WorkspaceStatus::from_str(&status_str).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid workspace status: {}", status_str),
            )),
        )
    })?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let owner_id = owner_id_str
        .map(|s| Uuid::parse_str(&s).map(UserId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let parent_id = parent_id_str
        .map(|s| Uuid::parse_str(&s).map(WorkspaceId))
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(13, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(Workspace {
        id: WorkspaceId(id),
        name,
        enabled,
        status,
        pk_hash,
        encryption_public_key,
        tags,
        owner_id,
        parent_id,
        tool_name,
        created_at,
        updated_at,
    })
}

/// Column order: id, workspace_id, name, upstream_url, transport, credential_bindings,
/// allowed_tools, enabled, created_by, created_at, updated_at, tags, required_credentials,
/// auth_method, template_key, discovered_tools, created_by_user
pub(crate) fn row_to_mcp_server(row: &rusqlite::Row<'_>) -> Result<McpServer, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let workspace_id_str: Option<String> = row.get(1)?;
    let name: String = row.get(2)?;
    let upstream_url: String = row.get(3)?;
    let transport_str: String = row.get(4)?;
    let transport = McpTransport::from_str_opt(&transport_str).unwrap_or_default();
    // Column 5 is the legacy credential_bindings column -- read but ignore for backwards compat
    let _legacy_bindings: String = row.get(5)?;
    let allowed_tools_json: Option<String> = row.get(6)?;
    let enabled: i32 = row.get(7)?;
    let created_by: Option<String> = row.get(8)?;
    let created_at_str: String = row.get(9)?;
    let updated_at_str: String = row.get(10)?;
    let tags_json: String = row.get(11)?;
    let required_credentials_json: Option<String> = row.get(12)?;
    let auth_method_str: String = row.get(13)?;
    let template_key: Option<String> = row.get(14)?;
    let discovered_tools_json: Option<String> = row.get(15)?;
    let created_by_user_str: Option<String> = row.get(16)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let workspace_id = match workspace_id_str {
        Some(s) => {
            let uuid = Uuid::parse_str(&s).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            WorkspaceId(uuid)
        }
        None => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "workspace_id is required on MCP server",
                )),
            ));
        }
    };
    let allowed_tools: Option<Vec<String>> = match allowed_tools_json {
        Some(json) => Some(serde_json::from_str(&json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?),
        None => None,
    };
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
        })?;

    let created_by_ws = created_by
        .map(|s| {
            Uuid::parse_str(&s).map(WorkspaceId).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })
        .transpose()?;
    let required_credentials: Option<Vec<CredentialId>> = required_credentials_json.and_then(|j| {
        serde_json::from_str::<Vec<String>>(&j).ok().map(|v| {
            v.into_iter()
                .filter_map(|s| Uuid::parse_str(&s).ok().map(CredentialId))
                .collect()
        })
    });

    let auth_method = McpAuthMethod::from_str_opt(&auth_method_str).unwrap_or_default();
    let discovered_tools = discovered_tools_json.and_then(|j| serde_json::from_str(&j).ok());
    let created_by_user = created_by_user_str
        .map(|s| {
            Uuid::parse_str(&s).map(UserId).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    16,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })
        .transpose()?;

    Ok(McpServer {
        id: McpServerId(id),
        workspace_id,
        name,
        upstream_url,
        transport,
        allowed_tools,
        enabled: enabled != 0,
        created_by: created_by_ws,
        created_at,
        updated_at,
        tags,
        required_credentials,
        auth_method,
        template_key,
        discovered_tools,
        created_by_user,
    })
}

pub(crate) fn row_to_oidc_provider(
    row: &rusqlite::Row<'_>,
) -> Result<OidcProvider, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let issuer_url: String = row.get(2)?;
    let client_id: String = row.get(3)?;
    let encrypted_client_secret: Vec<u8> = row.get(4)?;
    let nonce: Vec<u8> = row.get(5)?;
    let scopes_json: String = row.get(6)?;
    let role_mapping_json: String = row.get(7)?;
    let auto_provision: i32 = row.get(8)?;
    let enabled: i32 = row.get(9)?;
    let username_claim: String = row.get(10)?;
    let created_at_str: String = row.get(11)?;
    let updated_at_str: String = row.get(12)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let scopes: Vec<String> = serde_json::from_str(&scopes_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let role_mapping: serde_json::Value =
        serde_json::from_str(&role_mapping_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(OidcProvider {
        id: OidcProviderId(id),
        name,
        issuer_url,
        client_id,
        encrypted_client_secret,
        nonce,
        scopes,
        role_mapping,
        auto_provision: auto_provision != 0,
        enabled: enabled != 0,
        username_claim,
        created_at,
        updated_at,
    })
}

pub(crate) fn row_to_oidc_provider_summary(
    row: &rusqlite::Row<'_>,
) -> Result<OidcProviderSummary, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let issuer_url: String = row.get(2)?;
    let client_id: String = row.get(3)?;
    let scopes_json: String = row.get(4)?;
    let role_mapping_json: String = row.get(5)?;
    let auto_provision: i32 = row.get(6)?;
    let enabled: i32 = row.get(7)?;
    let username_claim: String = row.get(8)?;
    let created_at_str: String = row.get(9)?;
    let updated_at_str: String = row.get(10)?;

    let id = Uuid::parse_str(&id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let scopes: Vec<String> = serde_json::from_str(&scopes_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let role_mapping: serde_json::Value =
        serde_json::from_str(&role_mapping_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(OidcProviderSummary {
        id: OidcProviderId(id),
        name,
        issuer_url,
        client_id,
        scopes,
        role_mapping,
        auto_provision: auto_provision != 0,
        enabled: enabled != 0,
        username_claim,
        created_at,
        updated_at,
    })
}

pub(crate) fn row_to_oidc_auth_state(
    row: &rusqlite::Row<'_>,
) -> Result<OidcAuthState, rusqlite::Error> {
    let state: String = row.get(0)?;
    let nonce: String = row.get(1)?;
    let provider_id_str: String = row.get(2)?;
    let redirect_uri: String = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    let expires_at_str: String = row.get(5)?;

    let provider_id = Uuid::parse_str(&provider_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(OidcAuthState {
        state,
        nonce,
        provider_id: OidcProviderId(provider_id),
        redirect_uri,
        created_at,
        expires_at,
    })
}

/// Map a `StoreError` into a `tokio_rusqlite::Error` for use inside `conn.call()` closures.
pub(crate) fn store_err_to_tokio(e: StoreError) -> tokio_rusqlite::Error {
    tokio_rusqlite::Error::Other(Box::new(e))
}

pub(crate) fn row_to_workspace_registration(
    row: &rusqlite::Row<'_>,
) -> Result<crate::domain::workspace::WorkspaceRegistration, rusqlite::Error> {
    use crate::domain::workspace::WorkspaceRegistration;

    let pk_hash: String = row.get(0)?;
    let code_challenge: String = row.get(1)?;
    let code_hash: String = row.get(2)?;
    let approval_code: Option<String> = row.get(3)?;
    let expires_at_str: String = row.get(4)?;
    let attempts: i32 = row.get(5)?;
    let max_attempts: i32 = row.get(6)?;
    let created_at_str: String = row.get(7)?;
    let approved_by: Option<String> = row.get(8)?;

    let expires_at = DateTime::parse_from_rfc3339(&expires_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(WorkspaceRegistration {
        pk_hash,
        code_challenge,
        code_hash,
        approval_code,
        expires_at,
        attempts: attempts as u8,
        max_attempts: max_attempts as u8,
        approved_by,
        created_at,
    })
}
