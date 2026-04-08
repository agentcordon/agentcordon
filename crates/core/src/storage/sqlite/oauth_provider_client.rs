use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::SqliteStore;
use crate::domain::oauth_provider_client::{
    OAuthProviderClient, OAuthProviderClientId, OAuthProviderClientSummary, RegistrationSource,
};
use crate::error::StoreError;
use crate::storage::OAuthProviderClientStore;

const ALL_COLUMNS: &str = "id, authorization_server_url, issuer, authorize_endpoint, \
     token_endpoint, registration_endpoint, code_challenge_methods_supported, \
     token_endpoint_auth_methods_supported, scopes_supported, client_id, \
     encrypted_client_secret, nonce, requested_scopes, registration_source, \
     client_id_issued_at, client_secret_expires_at, registration_access_token_encrypted, \
     registration_access_token_nonce, registration_client_uri, label, enabled, \
     created_at, updated_at";

const SUMMARY_COLUMNS: &str = "id, authorization_server_url, issuer, authorize_endpoint, \
     token_endpoint, registration_endpoint, code_challenge_methods_supported, \
     token_endpoint_auth_methods_supported, scopes_supported, client_id, \
     requested_scopes, registration_source, client_id_issued_at, \
     client_secret_expires_at, registration_client_uri, label, enabled, \
     created_at, updated_at";

fn json_array(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".to_string())
}

fn parse_json_array(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn opt_dt_to_string(dt: Option<DateTime<Utc>>) -> Option<String> {
    dt.map(|d| d.to_rfc3339())
}

fn parse_opt_dt(s: Option<String>, col: usize) -> Result<Option<DateTime<Utc>>, rusqlite::Error> {
    match s {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(&s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    col,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            }),
    }
}

impl SqliteStore {
    pub(crate) async fn create_oauth_provider_client(
        &self,
        c: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        let c = c.clone();
        let sql = format!(
            "INSERT INTO oauth_provider_clients ({ALL_COLUMNS}) VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)"
        );
        self.conn()
            .call(move |conn| {
                conn.execute(
                    &sql,
                    rusqlite::params![
                        c.id.0.to_string(),
                        c.authorization_server_url,
                        c.issuer,
                        c.authorize_endpoint,
                        c.token_endpoint,
                        c.registration_endpoint,
                        json_array(&c.code_challenge_methods_supported),
                        json_array(&c.token_endpoint_auth_methods_supported),
                        json_array(&c.scopes_supported),
                        c.client_id,
                        c.encrypted_client_secret,
                        c.nonce,
                        c.requested_scopes,
                        c.registration_source.as_str(),
                        opt_dt_to_string(c.client_id_issued_at),
                        opt_dt_to_string(c.client_secret_expires_at),
                        c.registration_access_token_encrypted,
                        c.registration_access_token_nonce,
                        c.registration_client_uri,
                        c.label,
                        c.enabled as i32,
                        c.created_at.to_rfc3339(),
                        c.updated_at.to_rfc3339(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        let id_str = id.0.to_string();
        let sql = format!("SELECT {ALL_COLUMNS} FROM oauth_provider_clients WHERE id = ?1");
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![id_str], row_to_oauth_provider_client)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn get_oauth_provider_client_by_authorization_server_url(
        &self,
        authorization_server_url: &str,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        let key = authorization_server_url.to_string();
        let sql = format!(
            "SELECT {ALL_COLUMNS} FROM oauth_provider_clients WHERE authorization_server_url = ?1"
        );
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut rows = stmt
                    .query_map(rusqlite::params![key], row_to_oauth_provider_client)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                match rows.next() {
                    Some(Ok(c)) => Ok(Some(c)),
                    Some(Err(e)) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn list_oauth_provider_clients(
        &self,
    ) -> Result<Vec<OAuthProviderClientSummary>, StoreError> {
        let sql =
            format!("SELECT {SUMMARY_COLUMNS} FROM oauth_provider_clients ORDER BY label ASC");
        self.conn()
            .call(move |conn| {
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let rows = stmt
                    .query_map([], row_to_oauth_provider_client_summary)
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row.map_err(tokio_rusqlite::Error::Rusqlite)?);
                }
                Ok(out)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn update_oauth_provider_client(
        &self,
        c: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        let c = c.clone();
        self.conn()
            .call(move |conn| {
                conn.execute(
                    "UPDATE oauth_provider_clients SET \
                     authorization_server_url = ?1, issuer = ?2, authorize_endpoint = ?3, \
                     token_endpoint = ?4, registration_endpoint = ?5, \
                     code_challenge_methods_supported = ?6, \
                     token_endpoint_auth_methods_supported = ?7, scopes_supported = ?8, \
                     client_id = ?9, encrypted_client_secret = ?10, nonce = ?11, \
                     requested_scopes = ?12, registration_source = ?13, \
                     client_id_issued_at = ?14, client_secret_expires_at = ?15, \
                     registration_access_token_encrypted = ?16, \
                     registration_access_token_nonce = ?17, registration_client_uri = ?18, \
                     label = ?19, enabled = ?20, updated_at = ?21 \
                     WHERE id = ?22",
                    rusqlite::params![
                        c.authorization_server_url,
                        c.issuer,
                        c.authorize_endpoint,
                        c.token_endpoint,
                        c.registration_endpoint,
                        json_array(&c.code_challenge_methods_supported),
                        json_array(&c.token_endpoint_auth_methods_supported),
                        json_array(&c.scopes_supported),
                        c.client_id,
                        c.encrypted_client_secret,
                        c.nonce,
                        c.requested_scopes,
                        c.registration_source.as_str(),
                        opt_dt_to_string(c.client_id_issued_at),
                        opt_dt_to_string(c.client_secret_expires_at),
                        c.registration_access_token_encrypted,
                        c.registration_access_token_nonce,
                        c.registration_client_uri,
                        c.label,
                        c.enabled as i32,
                        c.updated_at.to_rfc3339(),
                        c.id.0.to_string(),
                    ],
                )
                .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(())
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    pub(crate) async fn delete_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<bool, StoreError> {
        let id_str = id.0.to_string();
        self.conn()
            .call(move |conn| {
                let count = conn
                    .execute(
                        "DELETE FROM oauth_provider_clients WHERE id = ?1",
                        rusqlite::params![id_str],
                    )
                    .map_err(tokio_rusqlite::Error::Rusqlite)?;
                Ok(count > 0)
            })
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}

#[async_trait]
impl OAuthProviderClientStore for SqliteStore {
    async fn create_oauth_provider_client(
        &self,
        c: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        self.create_oauth_provider_client(c).await
    }
    async fn get_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        self.get_oauth_provider_client(id).await
    }
    async fn get_oauth_provider_client_by_authorization_server_url(
        &self,
        authorization_server_url: &str,
    ) -> Result<Option<OAuthProviderClient>, StoreError> {
        self.get_oauth_provider_client_by_authorization_server_url(authorization_server_url)
            .await
    }
    async fn list_oauth_provider_clients(
        &self,
    ) -> Result<Vec<OAuthProviderClientSummary>, StoreError> {
        self.list_oauth_provider_clients().await
    }
    async fn update_oauth_provider_client(
        &self,
        c: &OAuthProviderClient,
    ) -> Result<(), StoreError> {
        self.update_oauth_provider_client(c).await
    }
    async fn delete_oauth_provider_client(
        &self,
        id: &OAuthProviderClientId,
    ) -> Result<bool, StoreError> {
        self.delete_oauth_provider_client(id).await
    }
}

fn parse_uuid(s: &str) -> Result<Uuid, rusqlite::Error> {
    Uuid::parse_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn parse_dt(s: &str, col: usize) -> Result<DateTime<Utc>, rusqlite::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
        })
}

fn row_to_oauth_provider_client(
    row: &rusqlite::Row<'_>,
) -> Result<OAuthProviderClient, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let authorization_server_url: String = row.get(1)?;
    let issuer: Option<String> = row.get(2)?;
    let authorize_endpoint: String = row.get(3)?;
    let token_endpoint: String = row.get(4)?;
    let registration_endpoint: Option<String> = row.get(5)?;
    let ccm: String = row.get(6)?;
    let team: String = row.get(7)?;
    let scopes_sup: String = row.get(8)?;
    let client_id: String = row.get(9)?;
    let encrypted_client_secret: Option<Vec<u8>> = row.get(10)?;
    let nonce: Option<Vec<u8>> = row.get(11)?;
    let requested_scopes: String = row.get(12)?;
    let registration_source_str: String = row.get(13)?;
    let client_id_issued_at: Option<String> = row.get(14)?;
    let client_secret_expires_at: Option<String> = row.get(15)?;
    let rat_enc: Option<Vec<u8>> = row.get(16)?;
    let rat_nonce: Option<Vec<u8>> = row.get(17)?;
    let registration_client_uri: Option<String> = row.get(18)?;
    let label: String = row.get(19)?;
    let enabled: i32 = row.get(20)?;
    let created_at_str: String = row.get(21)?;
    let updated_at_str: String = row.get(22)?;

    Ok(OAuthProviderClient {
        id: OAuthProviderClientId(parse_uuid(&id_str)?),
        authorization_server_url,
        issuer,
        authorize_endpoint,
        token_endpoint,
        registration_endpoint,
        code_challenge_methods_supported: parse_json_array(&ccm),
        token_endpoint_auth_methods_supported: parse_json_array(&team),
        scopes_supported: parse_json_array(&scopes_sup),
        client_id,
        encrypted_client_secret,
        nonce,
        requested_scopes,
        registration_source: RegistrationSource::parse(&registration_source_str)
            .unwrap_or(RegistrationSource::Manual),
        client_id_issued_at: parse_opt_dt(client_id_issued_at, 14)?,
        client_secret_expires_at: parse_opt_dt(client_secret_expires_at, 15)?,
        registration_access_token_encrypted: rat_enc,
        registration_access_token_nonce: rat_nonce,
        registration_client_uri,
        label,
        enabled: enabled != 0,
        created_at: parse_dt(&created_at_str, 21)?,
        updated_at: parse_dt(&updated_at_str, 22)?,
    })
}

fn row_to_oauth_provider_client_summary(
    row: &rusqlite::Row<'_>,
) -> Result<OAuthProviderClientSummary, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let authorization_server_url: String = row.get(1)?;
    let issuer: Option<String> = row.get(2)?;
    let authorize_endpoint: String = row.get(3)?;
    let token_endpoint: String = row.get(4)?;
    let registration_endpoint: Option<String> = row.get(5)?;
    let ccm: String = row.get(6)?;
    let team: String = row.get(7)?;
    let scopes_sup: String = row.get(8)?;
    let client_id: String = row.get(9)?;
    let requested_scopes: String = row.get(10)?;
    let registration_source_str: String = row.get(11)?;
    let client_id_issued_at: Option<String> = row.get(12)?;
    let client_secret_expires_at: Option<String> = row.get(13)?;
    let registration_client_uri: Option<String> = row.get(14)?;
    let label: String = row.get(15)?;
    let enabled: i32 = row.get(16)?;
    let created_at_str: String = row.get(17)?;
    let updated_at_str: String = row.get(18)?;

    Ok(OAuthProviderClientSummary {
        id: OAuthProviderClientId(parse_uuid(&id_str)?),
        authorization_server_url,
        issuer,
        authorize_endpoint,
        token_endpoint,
        registration_endpoint,
        code_challenge_methods_supported: parse_json_array(&ccm),
        token_endpoint_auth_methods_supported: parse_json_array(&team),
        scopes_supported: parse_json_array(&scopes_sup),
        client_id,
        requested_scopes,
        registration_source: RegistrationSource::parse(&registration_source_str)
            .unwrap_or(RegistrationSource::Manual),
        client_id_issued_at: parse_opt_dt(client_id_issued_at, 12)?,
        client_secret_expires_at: parse_opt_dt(client_secret_expires_at, 13)?,
        registration_client_uri,
        label,
        enabled: enabled != 0,
        created_at: parse_dt(&created_at_str, 17)?,
        updated_at: parse_dt(&updated_at_str, 18)?,
    })
}
