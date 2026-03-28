use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{db_err, is_unique_violation, PostgresStore, WorkspaceRow};
use crate::domain::user::UserId;
use crate::domain::workspace::{
    ProvisioningToken, Workspace, WorkspaceId, WorkspaceRegistration, WorkspaceStatus,
};
use crate::error::StoreError;
use crate::storage::shared::WORKSPACE_COLUMNS;
use crate::storage::WorkspaceStore;

#[async_trait]
impl WorkspaceStore for PostgresStore {
    // ---- CRUD ----

    async fn create_workspace(&self, workspace: &Workspace) -> Result<(), StoreError> {
        let tags = serde_json::to_value(&workspace.tags).unwrap_or_default();
        let result = sqlx::query(
            "INSERT INTO workspaces (id, name, enabled, status, pk_hash, encryption_public_key, tags, owner_id, parent_id, tool_name, enrollment_token_hash, last_authenticated_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(workspace.id.0)
        .bind(&workspace.name)
        .bind(workspace.enabled)
        .bind(workspace.status.as_str())
        .bind(&workspace.pk_hash)
        .bind(&workspace.encryption_public_key)
        .bind(&tags)
        .bind(workspace.owner_id.as_ref().map(|u| u.0))
        .bind(workspace.parent_id.as_ref().map(|p| p.0))
        .bind(&workspace.tool_name)
        .bind(None::<String>) // enrollment_token_hash — set separately
        .bind(None::<DateTime<Utc>>) // last_authenticated_at
        .bind(workspace.created_at)
        .bind(workspace.updated_at)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict {
                message: format!("workspace with name '{}' already exists", workspace.name),
                existing_id: None,
            }),
            Err(e) => Err(db_err(e)),
        }
    }

    async fn get_workspace(&self, id: &WorkspaceId) -> Result<Option<Workspace>, StoreError> {
        let sql = format!("SELECT {} FROM workspaces WHERE id = $1", WORKSPACE_COLUMNS);
        let row = sqlx::query_as::<_, WorkspaceRow>(&sql)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| r.into_workspace()).transpose()
    }

    async fn get_workspace_by_name(&self, name: &str) -> Result<Option<Workspace>, StoreError> {
        let sql = format!(
            "SELECT {} FROM workspaces WHERE name = $1",
            WORKSPACE_COLUMNS
        );
        let row = sqlx::query_as::<_, WorkspaceRow>(&sql)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| r.into_workspace()).transpose()
    }

    async fn get_workspace_by_pk_hash(
        &self,
        pk_hash: &str,
    ) -> Result<Option<Workspace>, StoreError> {
        let sql = format!(
            "SELECT {} FROM workspaces WHERE pk_hash = $1",
            WORKSPACE_COLUMNS
        );
        let row = sqlx::query_as::<_, WorkspaceRow>(&sql)
            .bind(pk_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(|r| r.into_workspace()).transpose()
    }

    async fn list_workspaces(&self) -> Result<Vec<Workspace>, StoreError> {
        let sql = format!("SELECT {} FROM workspaces ORDER BY name", WORKSPACE_COLUMNS);
        let rows = sqlx::query_as::<_, WorkspaceRow>(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(|r| r.into_workspace()).collect()
    }

    async fn get_workspaces_by_owner(
        &self,
        owner_id: &UserId,
    ) -> Result<Vec<Workspace>, StoreError> {
        let sql = format!(
            "SELECT {} FROM workspaces WHERE owner_id = $1 ORDER BY name",
            WORKSPACE_COLUMNS
        );
        let rows = sqlx::query_as::<_, WorkspaceRow>(&sql)
            .bind(owner_id.0)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(|r| r.into_workspace()).collect()
    }

    async fn update_workspace(&self, workspace: &Workspace) -> Result<(), StoreError> {
        let tags = serde_json::to_value(&workspace.tags).unwrap_or_default();
        let result = sqlx::query(
            "UPDATE workspaces SET name = $1, enabled = $2, status = $3, pk_hash = $4, \
             encryption_public_key = $5, tags = $6, owner_id = $7, parent_id = $8, \
             tool_name = $9, updated_at = $10 \
             WHERE id = $11",
        )
        .bind(&workspace.name)
        .bind(workspace.enabled)
        .bind(workspace.status.as_str())
        .bind(&workspace.pk_hash)
        .bind(&workspace.encryption_public_key)
        .bind(&tags)
        .bind(workspace.owner_id.as_ref().map(|u| u.0))
        .bind(workspace.parent_id.as_ref().map(|p| p.0))
        .bind(&workspace.tool_name)
        .bind(workspace.updated_at)
        .bind(workspace.id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound(format!(
                "workspace {} not found",
                workspace.id.0
            )));
        }
        Ok(())
    }

    async fn delete_workspace(&self, id: &WorkspaceId) -> Result<bool, StoreError> {
        // Check for credentials referencing this workspace
        let cred_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM credentials WHERE created_by = $1")
                .bind(id.0)
                .fetch_one(&self.pool)
                .await
                .map_err(db_err)?;

        if cred_count.0 > 0 {
            return Err(StoreError::Conflict {
                message: "workspace has credentials referencing it; disable instead or delete credentials first".to_string(),
                existing_id: None,
            });
        }

        let result = sqlx::query("DELETE FROM workspaces WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    // ---- JTI tracking ----

    async fn check_workspace_jti(&self, jti: &str) -> Result<bool, StoreError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM workspace_used_jtis WHERE jti = $1")
            .bind(jti)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.0 > 0)
    }

    async fn store_workspace_jti(
        &self,
        jti: &str,
        workspace_id: &WorkspaceId,
        expires_at: &DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        // The table was renamed from device_used_jtis but columns are unchanged (jti, device_id, expires_at)
        let result = sqlx::query(
            "INSERT INTO workspace_used_jtis (jti, device_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(jti)
        .bind(workspace_id.0)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired_workspace_jtis(&self) -> Result<u32, StoreError> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM workspace_used_jtis WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() as u32)
    }

    // ---- Authentication tracking ----

    async fn touch_workspace_authenticated(
        &self,
        id: &WorkspaceId,
        now: &DateTime<Utc>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE workspaces SET last_authenticated_at = $1, updated_at = $2 WHERE id = $3",
        )
        .bind(now)
        .bind(now)
        .bind(id.0)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    // ---- Registration flow ----

    async fn create_workspace_registration(
        &self,
        reg: &WorkspaceRegistration,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO workspace_registrations (pk_hash, code_challenge, code_hash, approval_code, expires_at, attempts, max_attempts, created_at, approved_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (pk_hash) DO UPDATE SET code_challenge = $2, code_hash = $3, approval_code = $4, expires_at = $5, attempts = $6, max_attempts = $7, created_at = $8, approved_by = $9",
        )
        .bind(&reg.pk_hash)
        .bind(&reg.code_challenge)
        .bind(&reg.code_hash)
        .bind(&reg.approval_code)
        .bind(reg.expires_at)
        .bind(reg.attempts as i32)
        .bind(reg.max_attempts as i32)
        .bind(reg.created_at)
        .bind(&reg.approved_by)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn get_workspace_registration(
        &self,
        pk_hash: &str,
    ) -> Result<Option<WorkspaceRegistration>, StoreError> {
        let row = sqlx::query_as::<_, (String, String, String, Option<String>, DateTime<Utc>, i32, i32, DateTime<Utc>, Option<String>)>(
            "SELECT pk_hash, code_challenge, code_hash, approval_code, expires_at, attempts, max_attempts, created_at, approved_by FROM workspace_registrations WHERE pk_hash = $1",
        )
        .bind(pk_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(
            |(
                pk_hash,
                code_challenge,
                code_hash,
                approval_code,
                expires_at,
                attempts,
                max_attempts,
                created_at,
                approved_by,
            )| {
                WorkspaceRegistration {
                    pk_hash,
                    code_challenge,
                    code_hash,
                    approval_code,
                    expires_at,
                    attempts: attempts as u8,
                    max_attempts: max_attempts as u8,
                    approved_by,
                    created_at,
                }
            },
        ))
    }

    async fn increment_registration_attempts(&self, pk_hash: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE workspace_registrations SET attempts = attempts + 1 WHERE pk_hash = $1",
        )
        .bind(pk_hash)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn delete_workspace_registration(&self, pk_hash: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM workspace_registrations WHERE pk_hash = $1")
            .bind(pk_hash)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn null_registration_approval_code(&self, pk_hash: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE workspace_registrations SET approval_code = NULL WHERE pk_hash = $1")
            .bind(pk_hash)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    // ---- Provisioning tokens ----

    async fn create_provisioning_token(&self, token: &ProvisioningToken) -> Result<(), StoreError> {
        let result = sqlx::query(
            "INSERT INTO provisioning_tokens (token_hash, name, expires_at, used, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&token.token_hash)
        .bind(&token.name)
        .bind(token.expires_at)
        .bind(token.used)
        .bind(token.created_at)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict {
                message: "provisioning token already exists".to_string(),
                existing_id: None,
            }),
            Err(e) => Err(db_err(e)),
        }
    }

    async fn get_provisioning_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<ProvisioningToken>, StoreError> {
        let row = sqlx::query_as::<_, (String, String, DateTime<Utc>, bool, DateTime<Utc>)>(
            "SELECT token_hash, name, expires_at, used, created_at FROM provisioning_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.map(
            |(token_hash, name, expires_at, used, created_at)| ProvisioningToken {
                token_hash,
                name,
                expires_at,
                used,
                created_at,
            },
        ))
    }

    async fn mark_provisioning_token_used(&self, token_hash: &str) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE provisioning_tokens SET used = TRUE WHERE token_hash = $1 AND used = FALSE",
        )
        .bind(token_hash)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}
