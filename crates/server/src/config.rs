use std::env;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct AppConfig {
    pub listen_addr: String,
    pub db_path: String,
    /// Database backend: "sqlite" (default) or "postgres".
    pub db_type: String,
    /// PostgreSQL connection URL (used when db_type = "postgres").
    pub db_url: Option<String>,
    pub master_secret: String,
    pub kdf_salt: String,
    pub log_level: String,
    /// Log output format: "json" (default) or "pretty".
    pub log_format: String,
    pub static_dir: Option<String>,
    pub jwt_ttl_seconds: u64,
    pub proxy_timeout_seconds: u64,
    /// Allow proxying to loopback/private addresses (for testing only).
    pub proxy_allow_loopback: bool,
    /// Session TTL in seconds (default 28800 = 8 hours).
    pub session_ttl_seconds: u64,
    /// Auth code TTL in seconds for enrollment flow (default 600 = 10 minutes).
    pub auth_code_ttl_seconds: u64,
    /// Bootstrap root username from env. If None, defaults to "root".
    pub root_username: Option<String>,
    /// Bootstrap root password from env. If None, auto-generated.
    pub root_password: Option<String>,
    /// Interval in seconds between expired-session cleanup runs (default 300 = 5 minutes).
    pub session_cleanup_interval_seconds: u64,
    /// Maximum failed login attempts per username before rate limiting (default 5).
    pub login_max_attempts: u32,
    /// Duration in seconds to lock out a username after max failed attempts (default 900 = 15 min).
    pub login_lockout_seconds: u64,
    /// OIDC auth state TTL in seconds (default 600 = 10 minutes).
    pub oidc_state_ttl_seconds: u64,
    /// Base URL for constructing OIDC callback URIs. If absent, falls back to request Host header.
    pub base_url: Option<String>,
    /// Maximum upstream response body size in bytes (default 10 MiB = 10_485_760).
    pub proxy_max_response_bytes: usize,
    /// Bootstrap token TTL in seconds for device enrollment (default 900 = 15 minutes).
    /// Floor: 60s, cap: 86400s (24h).
    pub bootstrap_token_ttl_seconds: u64,
    /// Whether to seed demo data on first boot (default: true).
    pub seed_demo: bool,
    /// Directory containing runtime credential template overrides (`.json` files).
    pub credential_templates_dir: Option<String>,
    /// Directory containing runtime MCP server template overrides (`.json` files).
    pub mcp_templates_dir: Option<String>,
    /// Directory containing runtime policy template overrides (`.json` files).
    pub policy_templates_dir: Option<String>,
    /// Label used in OAuth Dynamic Client Registration requests as `client_name`.
    /// If `None`, callers should fall back to a sensible default (e.g. hostname
    /// or "AgentCordon"). Helps distinguish multiple AgentCordon instances in a
    /// provider's admin UI.
    pub instance_label: Option<String>,
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("listen_addr", &self.listen_addr)
            .field("db_path", &self.db_path)
            .field("master_secret", &"[REDACTED]")
            .field("kdf_salt", &"[REDACTED]")
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("root_username", &self.root_username)
            .field("root_password", &"[REDACTED]")
            .field("db_type", &self.db_type)
            .field("db_url", &self.db_url.as_ref().map(|_| "[REDACTED]"))
            .field("proxy_allow_loopback", &self.proxy_allow_loopback)
            .finish_non_exhaustive()
    }
}

impl AppConfig {
    /// Create a default config suitable for testing (no env var reads).
    #[doc(hidden)]
    pub fn test_default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".to_string(),
            db_path: ":memory:".to_string(),
            db_type: "sqlite".to_string(),
            db_url: None,
            master_secret: "test-secret-at-least-16-chars".to_string(),
            kdf_salt: "test-salt-value!".to_string(),
            log_level: "warn".to_string(),
            log_format: "json".to_string(),
            static_dir: None,
            jwt_ttl_seconds: 900,
            proxy_timeout_seconds: 30,
            proxy_allow_loopback: true,
            session_ttl_seconds: 28800,
            auth_code_ttl_seconds: 600,
            root_username: None,
            root_password: None,
            session_cleanup_interval_seconds: 300,
            login_max_attempts: 5,
            login_lockout_seconds: 30,
            oidc_state_ttl_seconds: 600,
            base_url: None,
            proxy_max_response_bytes: 10_485_760,
            bootstrap_token_ttl_seconds: 900,
            seed_demo: false, // Don't seed in tests by default
            credential_templates_dir: None,
            mcp_templates_dir: None,
            policy_templates_dir: None,
            instance_label: None,
        }
    }

    /// The well-known default KDF salt value. If this is in use, the server
    /// should log a prominent warning at startup.
    pub const DEFAULT_KDF_SALT: &'static str = "agent-cordon-default-salt-change-me";

    /// Returns `true` if the configured KDF salt is the well-known default value.
    pub fn is_default_salt(&self) -> bool {
        self.kdf_salt == Self::DEFAULT_KDF_SALT
    }

    /// Resolve the master secret: env var > persisted file > auto-generate.
    ///
    /// The secret file is stored alongside the database (same parent directory).
    fn resolve_master_secret(db_path: &str) -> Result<String, String> {
        // 1. If env var is set, use it directly
        if let Ok(secret) = env::var("AGTCRDN_MASTER_SECRET") {
            if secret.len() < 16 {
                return Err("AGTCRDN_MASTER_SECRET must be at least 16 characters".to_string());
            }
            return Ok(secret);
        }

        // 2. Derive the secret file path from the database path's parent directory
        let secret_path = Self::secret_file_path(db_path);

        // 3. Try to read an existing secret file (atomic check avoids TOCTOU)
        match std::fs::read_to_string(&secret_path) {
            Ok(contents) => {
                let secret = contents.trim().to_string();
                if secret.len() < 16 {
                    return Err(format!(
                        "Master secret in {} is too short (must be at least 16 characters)",
                        secret_path.display()
                    ));
                }
                tracing::debug!(path = %secret_path.display(), "Loaded master secret from file");
                return Ok(secret);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fall through to auto-generate
            }
            Err(e) => {
                return Err(format!(
                    "Failed to read master secret from {}: {}",
                    secret_path.display(),
                    e
                ));
            }
        }

        // 4. Auto-generate a new secret and persist it
        let secret = Self::generate_secret();

        // Ensure the parent directory exists
        if let Some(parent) = secret_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create directory {} for secret file: {}",
                    parent.display(),
                    e
                )
            })?;
        }

        // Write the secret file with restrictive permissions
        Self::write_secret_file(&secret_path, &secret)?;

        tracing::info!(path = %secret_path.display(), "Auto-generated master secret — persisted to file");
        Ok(secret)
    }

    /// Compute the path for the persisted secret file based on the database path.
    fn secret_file_path(db_path: &str) -> PathBuf {
        let db = Path::new(db_path);
        let parent = db.parent().unwrap_or(Path::new("."));
        parent.join(".secret")
    }

    /// Generate a 32-byte random secret, base64url-encoded (43 chars, no padding).
    fn generate_secret() -> String {
        use base64::Engine;
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Write the secret to a file with mode 0600 (owner read/write only).
    fn write_secret_file(path: &Path, secret: &str) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("Failed to create secret file {}: {}", path.display(), e))?;
            file.write_all(secret.as_bytes())
                .map_err(|e| format!("Failed to write secret to {}: {}", path.display(), e))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, secret).map_err(|e| {
                format!("Failed to write master secret to {}: {}", path.display(), e)
            })?;
        }

        Ok(())
    }

    /// Derive a KDF salt from the master secret using HKDF-SHA256.
    ///
    /// This provides a secure default when `AGTCRDN_KDF_SALT` is not explicitly set,
    /// avoiding the insecure hardcoded default.
    fn derive_kdf_salt(master_secret: &str) -> Result<String, String> {
        Ok(agent_cordon_core::crypto::kdf::derive_kdf_salt(
            master_secret,
        ))
    }

    pub fn from_env() -> Result<Self, String> {
        let db_path =
            env::var("AGTCRDN_DB_PATH").unwrap_or_else(|_| "./data/agent-cordon.db".to_string());

        let master_secret = Self::resolve_master_secret(&db_path)?;

        let kdf_salt = match env::var("AGTCRDN_KDF_SALT") {
            Ok(salt) => salt,
            Err(_) => Self::derive_kdf_salt(&master_secret)?,
        };

        Ok(Self {
            listen_addr: env::var("AGTCRDN_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3140".to_string()),
            db_path,
            db_type: env::var("AGTCRDN_DB_TYPE").unwrap_or_else(|_| "sqlite".to_string()),
            db_url: env::var("AGTCRDN_DB_URL").ok(),
            master_secret,
            kdf_salt,
            log_level: env::var("AGTCRDN_LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            log_format: env::var("AGTCRDN_LOG_FORMAT").unwrap_or_else(|_| "json".to_string()),
            static_dir: env::var("AGTCRDN_STATIC_DIR").ok(),
            jwt_ttl_seconds: env::var("AGTCRDN_JWT_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900),
            proxy_timeout_seconds: env::var("AGTCRDN_PROXY_TIMEOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            proxy_allow_loopback: env::var("AGTCRDN_PROXY_ALLOW_LOOPBACK")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            session_ttl_seconds: env::var("AGTCRDN_SESSION_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(28800),
            auth_code_ttl_seconds: env::var("AGTCRDN_AUTH_CODE_TTL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
            root_username: env::var("AGTCRDN_ROOT_USERNAME").ok(),
            root_password: env::var("AGTCRDN_ROOT_PASSWORD").ok(),
            session_cleanup_interval_seconds: env::var("AGTCRDN_SESSION_CLEANUP_INTERVAL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.max(10))
                .unwrap_or(300),
            login_max_attempts: env::var("AGTCRDN_LOGIN_MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse::<u32>().ok())
                .map(|v| v.max(1))
                .unwrap_or(5),
            login_lockout_seconds: env::var("AGTCRDN_LOGIN_LOCKOUT_SECONDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.max(1))
                .unwrap_or(30),
            oidc_state_ttl_seconds: env::var("AGTCRDN_OIDC_STATE_TTL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.max(60))
                .unwrap_or(600),
            base_url: env::var("AGTCRDN_BASE_URL").ok(),
            proxy_max_response_bytes: env::var("AGTCRDN_PROXY_MAX_RESPONSE_BYTES")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .map(|v| v.max(1024)) // floor at 1 KiB to avoid nonsensical values
                .unwrap_or(10_485_760),
            bootstrap_token_ttl_seconds: env::var("AGTCRDN_BOOTSTRAP_TOKEN_TTL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|v| v.clamp(60, 86400)) // floor 60s, cap 24h
                .unwrap_or(900),
            seed_demo: env::var("AGTCRDN_SEED_DEMO")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            credential_templates_dir: env::var("AGTCRDN_CREDENTIAL_TEMPLATES_DIR").ok(),
            mcp_templates_dir: env::var("AGTCRDN_MCP_TEMPLATES_DIR").ok(),
            policy_templates_dir: env::var("AGTCRDN_POLICY_TEMPLATES_DIR").ok(),
            instance_label: env::var("AGTCRDN_INSTANCE_LABEL").ok(),
        })
    }
}
