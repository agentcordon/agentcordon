use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use super::{db_err, is_unique_violation, CredentialRow, CredentialSummaryRow, PostgresStore};
use crate::domain::agent::AgentId;
use crate::domain::credential::{
    CredentialId, CredentialSummary, CredentialUpdate, SecretHistoryEntry, StoredCredential,
};
use crate::domain::user::UserId;
use crate::domain::workspace::WorkspaceId;
use crate::error::StoreError;
use crate::storage::shared::{
    build_credential_update_sql, CredentialParamValue, PlaceholderStyle, CREDENTIAL_COLUMNS,
    CREDENTIAL_SUMMARY_COLUMNS,
};
use crate::storage::{CredentialStore, SecretHistoryStore};

#[async_trait]
impl CredentialStore for PostgresStore {
    async fn store_credential(&self, cred: &StoredCredential) -> Result<(), StoreError> {
        let scopes = serde_json::to_value(&cred.scopes).unwrap_or_default();
        let tags = serde_json::to_value(&cred.tags).unwrap_or_default();
        let created_by = cred.created_by.as_ref().map(|id| id.0);
        let created_by_user = cred.created_by_user.as_ref().map(|id| id.0);

        let sql = format!(
            "INSERT INTO credentials ({}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)",
            CREDENTIAL_COLUMNS
        );
        let result = sqlx::query(&sql)
            .bind(cred.id.0)
            .bind(&cred.name)
            .bind(&cred.service)
            .bind(&cred.encrypted_value)
            .bind(&cred.nonce)
            .bind(&scopes)
            .bind(&cred.metadata)
            .bind(created_by)
            .bind(cred.created_at)
            .bind(cred.updated_at)
            .bind(&cred.allowed_url_pattern)
            .bind(created_by_user)
            .bind(cred.expires_at)
            .bind(&cred.transform_script)
            .bind(&cred.transform_name)
            .bind(&cred.vault)
            .bind(&cred.credential_type)
            .bind(&tags)
            .bind(cred.key_version as i32)
            .bind(&cred.description)
            .bind(&cred.target_identity)
            .execute(&self.pool)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) if is_unique_violation(&e) => Err(StoreError::Conflict {
                message: format!("credential with name '{}' already exists", cred.name),
                existing_id: None,
            }),
            Err(e) => Err(db_err(e)),
        }
    }

    async fn get_credential(
        &self,
        id: &CredentialId,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let sql = format!(
            "SELECT {} FROM credentials WHERE id = $1",
            CREDENTIAL_COLUMNS
        );
        let row = sqlx::query_as::<_, CredentialRow>(&sql)
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn get_credential_by_name(
        &self,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let sql = format!(
            "SELECT {} FROM credentials WHERE name = $1",
            CREDENTIAL_COLUMNS
        );
        let row = sqlx::query_as::<_, CredentialRow>(&sql)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn get_credential_by_workspace_and_name(
        &self,
        workspace_id: &WorkspaceId,
        name: &str,
    ) -> Result<Option<StoredCredential>, StoreError> {
        let sql = format!(
            "SELECT {} FROM credentials WHERE name = $1 AND created_by = $2",
            CREDENTIAL_COLUMNS
        );
        let row = sqlx::query_as::<_, CredentialRow>(&sql)
            .bind(name)
            .bind(workspace_id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialSummary>, StoreError> {
        let sql = format!(
            "SELECT {} FROM credentials ORDER BY name",
            CREDENTIAL_SUMMARY_COLUMNS
        );
        let rows = sqlx::query_as::<_, CredentialSummaryRow>(&sql)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn delete_credential(&self, id: &CredentialId) -> Result<bool, StoreError> {
        let result = sqlx::query("DELETE FROM credentials WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_vaults(&self) -> Result<Vec<String>, StoreError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT vault FROM credentials ORDER BY vault")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_vaults_for_user(&self, user_id: &UserId) -> Result<Vec<String>, StoreError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT vault FROM credentials WHERE created_by_user = $1 \
             UNION \
             SELECT DISTINCT vault_name FROM vault_shares WHERE shared_with_user_id = $1 \
             ORDER BY 1",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn list_credentials_by_vault(
        &self,
        vault: &str,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let sql = format!(
            "SELECT {} FROM credentials WHERE vault = $1 ORDER BY name",
            CREDENTIAL_SUMMARY_COLUMNS
        );
        let rows = sqlx::query_as::<_, CredentialSummaryRow>(&sql)
            .bind(vault)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn list_credentials_by_vault_for_user(
        &self,
        vault: &str,
        user_id: &UserId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        let sql = format!(
            "SELECT c.{} FROM credentials c \
             WHERE c.vault = $1 \
             AND (c.created_by_user = $2 \
                  OR EXISTS (SELECT 1 FROM vault_shares vs \
                             WHERE vs.vault_name = c.vault \
                             AND vs.shared_with_user_id = $2)) \
             ORDER BY c.name",
            CREDENTIAL_SUMMARY_COLUMNS.replace(", ", ", c.")
        );
        let rows = sqlx::query_as::<_, CredentialSummaryRow>(&sql)
            .bind(vault)
            .bind(user_id.0)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_credential(
        &self,
        id: &CredentialId,
        updates: &CredentialUpdate,
    ) -> Result<bool, StoreError> {
        let cq = build_credential_update_sql(
            "",
            updates,
            PlaceholderStyle::DollarSign,
            "::jsonb", // PostgreSQL JSON cast
        )?;

        if !cq.has_changes {
            let now = Utc::now();
            let result = sqlx::query(&cq.sql)
                .bind(now)
                .bind(id.0)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
            return Ok(result.rows_affected() > 0);
        }

        let mut query = sqlx::query(&cq.sql);
        for p in &cq.params {
            match p {
                CredentialParamValue::String(s) => query = query.bind(s),
                CredentialParamValue::Bytes(b) => query = query.bind(b),
                CredentialParamValue::Int64(i) => query = query.bind(*i),
            }
        }
        query = query.bind(id.0);

        let result = query.execute(&self.pool).await;
        match result {
            Ok(r) => Ok(r.rows_affected() > 0),
            Err(e) if is_unique_violation(&e) => {
                let name = updates.name.clone().unwrap_or_default();
                Err(StoreError::Conflict {
                    message: format!("credential with name '{}' already exists", name),
                    existing_id: None,
                })
            }
            Err(e) => Err(db_err(e)),
        }
    }

    async fn list_credentials_for_agent(
        &self,
        _agent_id: &AgentId,
    ) -> Result<Vec<CredentialSummary>, StoreError> {
        // credential_permissions table has been dropped — all credential access
        // is now authorized through Cedar policies. This method is retained for
        // trait compatibility but always returns an empty list.
        Ok(Vec::new())
    }

    async fn list_all_stored_credentials(&self) -> Result<Vec<StoredCredential>, StoreError> {
        Err(StoreError::Database(
            "list_all_stored_credentials not yet implemented for postgres".into(),
        ))
    }
}

#[async_trait]
impl SecretHistoryStore for PostgresStore {
    async fn store_secret_history(
        &self,
        credential_id: &CredentialId,
        encrypted_value: &[u8],
        nonce: &[u8],
        changed_by_user: Option<&str>,
        changed_by_agent: Option<&str>,
    ) -> Result<(), StoreError> {
        let id = Uuid::new_v4();
        let changed_at = Utc::now();

        sqlx::query(
            "INSERT INTO credential_secret_history (id, credential_id, encrypted_value, nonce, changed_at, changed_by_user, changed_by_agent) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(credential_id.0)
        .bind(encrypted_value)
        .bind(nonce)
        .bind(changed_at)
        .bind(changed_by_user)
        .bind(changed_by_agent)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn list_secret_history(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Vec<SecretHistoryEntry>, StoreError> {
        let rows: Vec<(
            Uuid,
            Uuid,
            chrono::DateTime<Utc>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, credential_id, changed_at, changed_by_user, changed_by_agent \
                 FROM credential_secret_history WHERE credential_id = $1 \
                 ORDER BY changed_at DESC",
        )
        .bind(credential_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(rows
            .into_iter()
            .map(|r| SecretHistoryEntry {
                id: r.0,
                credential_id: r.1,
                changed_at: r.2,
                changed_by_user: r.3,
                changed_by_agent: r.4,
            })
            .collect())
    }

    async fn get_secret_history_value(
        &self,
        history_id: &str,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
        let id = Uuid::parse_str(history_id)
            .map_err(|e| StoreError::Database(format!("invalid history id: {}", e)))?;
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT encrypted_value, nonce FROM credential_secret_history WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row)
    }
}
