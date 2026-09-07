use std::env;
use std::path::{Path, PathBuf};

use agent_cordon_core::crypto::master_secret::{self, StoreState};
use agent_cordon_core::crypto::{install_argon2_params, Argon2Params};

/// How this process expects to share its database.
///
/// The server keeps policy, rate-limit and SSE state in memory, so two
/// processes over one SQLite file enforce two different pictures of the
/// world. [`ReplicaMode::UnsafeShared`] is the documented escape hatch for an
/// operator who accepts that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaMode {
    /// One process per database; a second one is refused. The default.
    Single,
    /// Skip the guard. Split-brain enforcement is the operator's problem.
    UnsafeShared,
}

impl ReplicaMode {
    /// Parse `AGTCRDN_REPLICA_MODE`. An unrecognised value is an error rather
    /// than a silent fallback, so a typo cannot look like the escape hatch.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.map(str::trim).filter(|v| !v.is_empty()) {
            None | Some("single") => Ok(Self::Single),
            Some("unsafe-shared") => Ok(Self::UnsafeShared),
            Some(other) => Err(format!(
                "AGTCRDN_REPLICA_MODE must be 'single' or 'unsafe-shared', got {other:?}"
            )),
        }
    }
}

/// An advisory `flock(LOCK_EX | LOCK_NB)` on `<db path>.lock`, held for the
/// life of the process.
///
/// The kernel releases it when the process exits, however it exits, so there
/// is no stale-lock cleanup to do. On non-Unix targets the file is created
/// but not locked.
#[derive(Debug)]
pub struct InstanceLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl InstanceLock {
    /// Take the lock, or report who holds it.
    pub fn acquire(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "failed to create directory {} for the instance lock: {e}",
                    parent.display()
                )
            })?;
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts
            .open(path)
            .map_err(|e| format!("failed to open lock file {}: {e}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: `flock` on a file descriptor we own and keep open for
            // the lifetime of `Self`.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                return Err(if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    format!(
                        "another agent-cordon-server is already running against this database \
                         ({} is locked). The server keeps policy, rate-limit and SSE state in \
                         memory, so a second process would enforce a different picture of the \
                         world. Stop the running server, point this one at a different \
                         AGTCRDN_DB_PATH, or set AGTCRDN_REPLICA_MODE=unsafe-shared to accept \
                         split-brain enforcement.",
                        path.display()
                    )
                } else {
                    format!("failed to lock {}: {err}", path.display())
                });
            }
        }

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
        })
    }

    /// The lock file this instance holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub listen_addr: String,
    /// Path to the SQLite database file, the one storage backend.
    pub db_path: String,
    pub master_secret: String,
    pub kdf_salt: String,
    /// Version number of `master_secret`. New ciphertext is stamped with it;
    /// rows record the version they were sealed under. Default 1.
    pub master_key_version: i64,
    /// The secret for version `master_key_version - 1`, present only during
    /// a rotation window so rows sealed under it still open.
    pub previous_master_secret: Option<String>,
    /// HKDF salt for the previous secret: `AGTCRDN_KDF_SALT` when set,
    /// otherwise derived from the previous secret the same way `kdf_salt` is
    /// derived from the current one.
    pub previous_kdf_salt: Option<String>,
    pub log_level: String,
    /// Log output format: "json" (default) or "pretty".
    pub log_format: String,
    pub static_dir: Option<String>,
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
    /// Trust `X-Forwarded-For` as the client address (default false). Turn on
    /// only behind a reverse proxy that overwrites the header; otherwise a
    /// caller can pick any address and sidestep per-address limits.
    pub trust_forwarded_headers: bool,
    /// OIDC auth state TTL in seconds (default 600 = 10 minutes).
    pub oidc_state_ttl_seconds: u64,
    /// Base URL for constructing OIDC callback URIs. If absent, falls back to request Host header.
    pub base_url: Option<String>,
    /// Maximum upstream response body size in bytes (default 10 MiB = 10_485_760).
    pub proxy_max_response_bytes: usize,
    /// Bootstrap token TTL in seconds for device enrollment (default 900 = 15 minutes).
    /// Floor: 60s, cap: 86400s (24h).
    pub bootstrap_token_ttl_seconds: u64,
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
    /// RFC 8628 device authorization grant: TTL for device_code / user_code (seconds).
    /// Default 600 (10 minutes). Override via `AGTCRDN_DEVICE_CODE_TTL_SECS`.
    pub device_code_ttl_secs: i64,
    /// RFC 8628 device authorization grant: baseline poll interval in seconds.
    /// Default 5. Override via `AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS`.
    pub device_code_poll_interval_secs: i64,
    /// Argon2id cost for password hashing, secret hashing, and master-secret
    /// stretching. `AGTCRDN_ARGON2_M_COST_KIB` / `_T_COST` / `_P_COST`.
    pub argon2: Argon2Params,
    /// Whether a second process may run against this database.
    /// `AGTCRDN_REPLICA_MODE`.
    pub replica_mode: ReplicaMode,
}

impl AppConfig {
    /// Canonical base URL for this server, used to construct absolute URIs
    /// in OAuth responses (device flow verification_uri, etc.). Strips
    /// trailing slashes. Falls back to `http://<listen_addr>` if `base_url`
    /// is not set.
    pub fn server_base_url(&self) -> String {
        let raw = self
            .base_url
            .clone()
            .unwrap_or_else(|| format!("http://{}", self.listen_addr));
        raw.trim_end_matches('/').to_string()
    }
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("listen_addr", &self.listen_addr)
            .field("db_path", &self.db_path)
            .field("master_secret", &"[REDACTED]")
            .field("kdf_salt", &"[REDACTED]")
            .field("master_key_version", &self.master_key_version)
            .field(
                "previous_master_secret",
                &self.previous_master_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "previous_kdf_salt",
                &self.previous_kdf_salt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("log_level", &self.log_level)
            .field("log_format", &self.log_format)
            .field("root_username", &self.root_username)
            .field("root_password", &"[REDACTED]")
            .field("proxy_allow_loopback", &self.proxy_allow_loopback)
            .field("argon2", &self.argon2)
            .field("replica_mode", &self.replica_mode)
            .finish_non_exhaustive()
    }
}

impl AppConfig {
    /// Create a default config suitable for testing (no env var reads).
    ///
    /// Building one installs [`Argon2Params::FAST`] process-wide: the test
    /// suite hashes hundreds of passwords and cannot afford production cost.
    /// This is what the `test-crypto` cargo feature used to do, minus the
    /// risk that feature unification weakened a production build.
    #[doc(hidden)]
    pub fn test_default() -> Self {
        install_argon2_params(Argon2Params::FAST);
        Self {
            listen_addr: "127.0.0.1:0".to_string(),
            db_path: ":memory:".to_string(),
            master_secret: "test-secret-at-least-16-chars".to_string(),
            kdf_salt: "test-salt-value!".to_string(),
            master_key_version: 1,
            previous_master_secret: None,
            previous_kdf_salt: None,
            log_level: "warn".to_string(),
            log_format: "json".to_string(),
            static_dir: None,
            proxy_timeout_seconds: 30,
            proxy_allow_loopback: true,
            session_ttl_seconds: 28800,
            auth_code_ttl_seconds: 600,
            root_username: None,
            root_password: None,
            session_cleanup_interval_seconds: 300,
            login_max_attempts: 5,
            login_lockout_seconds: 30,
            trust_forwarded_headers: false,
            oidc_state_ttl_seconds: 600,
            base_url: None,
            proxy_max_response_bytes: 10_485_760,
            bootstrap_token_ttl_seconds: 900,
            credential_templates_dir: None,
            mcp_templates_dir: None,
            policy_templates_dir: None,
            instance_label: None,
            device_code_ttl_secs: 600,
            device_code_poll_interval_secs: 5,
            argon2: Argon2Params::FAST,
            replica_mode: ReplicaMode::Single,
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
        let secret = Self::generate_master_secret();

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

    /// Generate a master secret: 32 random bytes, hex-encoded (64 chars).
    ///
    /// Hex rather than base64 so the file is unambiguous to a human and to
    /// [`master_secret::classify_secret`], which reads 64 hex characters as
    /// exactly 32 bytes of material. Secrets written by earlier versions
    /// (base64url, 43 chars) classify as strong too and are left alone.
    #[doc(hidden)]
    pub fn generate_master_secret() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
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

    /// Check the master-secret versioning inputs before any key is derived.
    ///
    /// Rules: the version is at least 1; a previous secret is at least 16
    /// characters, differs from the current secret, and requires a version
    /// of at least 2 (it is the secret for version N-1).
    pub fn validate_master_key_versioning(
        master_secret: &str,
        master_key_version: i64,
        previous_master_secret: Option<&str>,
    ) -> Result<(), String> {
        if master_key_version < 1 {
            return Err(format!(
                "AGTCRDN_MASTER_KEY_VERSION must be a positive integer, got {master_key_version}"
            ));
        }
        if let Some(previous) = previous_master_secret {
            if previous.len() < 16 {
                return Err(
                    "AGTCRDN_PREVIOUS_MASTER_SECRET must be at least 16 characters".to_string(),
                );
            }
            if previous == master_secret {
                return Err("AGTCRDN_PREVIOUS_MASTER_SECRET must differ from AGTCRDN_MASTER_SECRET: \
                            set the new secret as the current one and bump AGTCRDN_MASTER_KEY_VERSION"
                    .to_string());
            }
            if master_key_version < 2 {
                return Err(format!(
                    "AGTCRDN_PREVIOUS_MASTER_SECRET is the secret for version {} - 1; \
                     AGTCRDN_MASTER_KEY_VERSION must be at least 2 when it is set",
                    master_key_version
                ));
            }
        }
        Ok(())
    }

    /// Refuse a configuration written for the Postgres backend, which was
    /// deleted in 0.4.0.
    ///
    /// An old `.env` carries `AGTCRDN_DB_TYPE=postgres` and
    /// `AGTCRDN_DB_URL=postgres://…`; a hand-edited one may put the
    /// connection URL straight in `AGTCRDN_DB_PATH`. Left alone, the first
    /// two are silently ignored and the third opens a SQLite file literally
    /// named `postgres://…`, so the server comes up on an empty database
    /// that looks like the wrong one. Say so at startup instead.
    ///
    /// The URL itself is never echoed back: it carries a password.
    fn reject_removed_backend_env(
        db_type: Option<&str>,
        db_url_set: bool,
        db_path: &str,
    ) -> Result<(), String> {
        if let Some(db_type) = db_type {
            let db_type = db_type.trim();
            if !db_type.eq_ignore_ascii_case("sqlite") {
                return Err(format!(
                    "AGTCRDN_DB_TYPE={db_type} is not a storage backend. SQLite is the \
                     only backend; the PostgreSQL backend was removed in 0.4.0. Unset \
                     AGTCRDN_DB_TYPE and point AGTCRDN_DB_PATH at a database file."
                ));
            }
        }
        if db_url_set {
            return Err(
                "AGTCRDN_DB_URL is no longer a setting: it named a PostgreSQL \
                        database, and that backend was removed in 0.4.0. Unset it and \
                        point AGTCRDN_DB_PATH at a SQLite database file."
                    .to_string(),
            );
        }
        let db_path = db_path.trim_start().to_ascii_lowercase();
        let looks_like_a_url = ["postgres://", "postgresql://", "mysql://"]
            .iter()
            .any(|scheme| db_path.starts_with(scheme));
        if looks_like_a_url {
            return Err(
                "AGTCRDN_DB_PATH is a file path to a SQLite database, not a \
                        database connection URL. The PostgreSQL backend was removed \
                        in 0.4.0."
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Whether the database is a SQLite file on disk, the only case in which
    /// a salt file or an instance lock can live next to it. An in-memory
    /// database has neither.
    fn is_file_backed_sqlite(&self) -> bool {
        !self.db_path.is_empty()
            && !self.db_path.contains(":memory:")
            && !self.db_path.contains("mode=memory")
    }

    /// Where the Argon2id stretching salt lives, when there is somewhere to
    /// put it.
    pub fn master_salt_path(&self) -> Option<PathBuf> {
        self.is_file_backed_sqlite()
            .then(|| master_secret::salt_file_path(&self.db_path))
    }

    /// Take the single-instance lock for this database.
    ///
    /// `Ok(None)` means no lock was needed: an in-memory or external
    /// database, or `AGTCRDN_REPLICA_MODE=unsafe-shared`. The returned lock
    /// must be held for the life of the process.
    pub fn acquire_instance_lock(&self) -> Result<Option<InstanceLock>, String> {
        if self.replica_mode == ReplicaMode::UnsafeShared {
            tracing::warn!(
                db_path = %self.db_path,
                "AGTCRDN_REPLICA_MODE=unsafe-shared: the single-instance guard is off. \
                 Policy caches, rate limiters and SSE state are per process and will diverge."
            );
            return Ok(None);
        }
        if !self.is_file_backed_sqlite() {
            return Ok(None);
        }
        let path = PathBuf::from(format!("{}.lock", self.db_path));
        InstanceLock::acquire(&path).map(Some)
    }

    /// Second phase of master-secret setup, run once the store is open.
    ///
    /// Replaces `master_secret` (and `previous_master_secret`) with the
    /// material HKDF should actually consume: unchanged for a strong secret,
    /// Argon2id-stretched for a weak one that may be stretched. Returns the
    /// warning to log when a weak secret had to be kept as-is.
    ///
    /// The KDF salts are deliberately left alone: they are derived from the
    /// configured secret, are not themselves secret, and must stay stable
    /// across restarts.
    pub fn finalize_master_secret(
        &mut self,
        store_state: StoreState,
    ) -> Result<Option<String>, String> {
        let salt_path = self.master_salt_path();
        let resolved = master_secret::resolve_secret(
            &self.master_secret,
            salt_path.as_deref(),
            store_state,
            self.argon2,
            "AGTCRDN_MASTER_SECRET",
        )
        .map_err(|e| e.to_string())?;
        let derivation = resolved.derivation;
        self.master_secret = resolved.secret.to_string();

        if let Some(previous) = self.previous_master_secret.clone() {
            // The previous secret is historical: it never creates a salt, it
            // only follows one that already exists.
            let resolved_previous = master_secret::resolve_secret(
                &previous,
                salt_path.as_deref(),
                StoreState::Populated,
                self.argon2,
                "AGTCRDN_PREVIOUS_MASTER_SECRET",
            )
            .map_err(|e| e.to_string())?;
            self.previous_master_secret = Some(resolved_previous.secret.to_string());
        }

        tracing::info!(
            derivation = ?derivation,
            "master secret resolved"
        );
        Ok(resolved.warning)
    }

    /// Parse the three `AGTCRDN_ARGON2_*` values, falling back to production
    /// cost for any that is unset.
    fn parse_argon2_params(
        m_cost_kib: Option<&str>,
        t_cost: Option<&str>,
        p_cost: Option<&str>,
    ) -> Result<Argon2Params, String> {
        fn field(name: &str, raw: Option<&str>, default: u32) -> Result<u32, String> {
            match raw.map(str::trim).filter(|v| !v.is_empty()) {
                None => Ok(default),
                Some(value) => value
                    .parse::<u32>()
                    .map_err(|_| format!("{name} must be a positive integer, got {value:?}")),
            }
        }
        let production = Argon2Params::PRODUCTION;
        let params = Argon2Params::new(
            field(
                "AGTCRDN_ARGON2_M_COST_KIB",
                m_cost_kib,
                production.m_cost_kib,
            )?,
            field("AGTCRDN_ARGON2_T_COST", t_cost, production.t_cost)?,
            field("AGTCRDN_ARGON2_P_COST", p_cost, production.p_cost)?,
        )
        .map_err(|e| e.to_string())?;
        Ok(params)
    }

    pub fn from_env() -> Result<Self, String> {
        let db_path =
            env::var("AGTCRDN_DB_PATH").unwrap_or_else(|_| "./data/agent-cordon.db".to_string());
        Self::reject_removed_backend_env(
            env::var("AGTCRDN_DB_TYPE").ok().as_deref(),
            env::var("AGTCRDN_DB_URL").is_ok(),
            &db_path,
        )?;

        let master_secret = Self::resolve_master_secret(&db_path)?;

        let explicit_kdf_salt = env::var("AGTCRDN_KDF_SALT").ok();
        let kdf_salt = match &explicit_kdf_salt {
            Some(salt) => salt.clone(),
            None => Self::derive_kdf_salt(&master_secret)?,
        };

        let master_key_version = match env::var("AGTCRDN_MASTER_KEY_VERSION") {
            Ok(raw) => raw.trim().parse::<i64>().map_err(|_| {
                format!("AGTCRDN_MASTER_KEY_VERSION must be an integer, got {raw:?}")
            })?,
            Err(_) => 1,
        };
        let previous_master_secret = env::var("AGTCRDN_PREVIOUS_MASTER_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
        Self::validate_master_key_versioning(
            &master_secret,
            master_key_version,
            previous_master_secret.as_deref(),
        )?;
        let argon2 = Self::parse_argon2_params(
            env::var("AGTCRDN_ARGON2_M_COST_KIB").ok().as_deref(),
            env::var("AGTCRDN_ARGON2_T_COST").ok().as_deref(),
            env::var("AGTCRDN_ARGON2_P_COST").ok().as_deref(),
        )?;
        let replica_mode = ReplicaMode::parse(env::var("AGTCRDN_REPLICA_MODE").ok().as_deref())?;

        let previous_kdf_salt = match (&previous_master_secret, &explicit_kdf_salt) {
            (None, _) => None,
            (Some(_), Some(salt)) => Some(salt.clone()),
            (Some(previous), None) => Some(Self::derive_kdf_salt(previous)?),
        };

        Ok(Self {
            listen_addr: env::var("AGTCRDN_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:3140".to_string()),
            db_path,
            master_secret,
            kdf_salt,
            master_key_version,
            previous_master_secret,
            previous_kdf_salt,
            log_level: env::var("AGTCRDN_LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            log_format: env::var("AGTCRDN_LOG_FORMAT").unwrap_or_else(|_| "json".to_string()),
            static_dir: env::var("AGTCRDN_STATIC_DIR").ok(),
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
            trust_forwarded_headers: env::var("AGTCRDN_TRUST_FORWARDED_HEADERS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
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
            credential_templates_dir: env::var("AGTCRDN_CREDENTIAL_TEMPLATES_DIR").ok(),
            mcp_templates_dir: env::var("AGTCRDN_MCP_TEMPLATES_DIR").ok(),
            policy_templates_dir: env::var("AGTCRDN_POLICY_TEMPLATES_DIR").ok(),
            instance_label: env::var("AGTCRDN_INSTANCE_LABEL").ok(),
            device_code_ttl_secs: env::var("AGTCRDN_DEVICE_CODE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .map(|v| v.clamp(30, 3600))
                .unwrap_or(600),
            device_code_poll_interval_secs: env::var("AGTCRDN_DEVICE_CODE_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .map(|v| v.clamp(1, 60))
                .unwrap_or(5),
            argon2,
            replica_mode,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    const CURRENT: &str = "current-master-secret-16+";
    const PREVIOUS: &str = "previous-master-secret-16+";

    #[test]
    fn previous_secret_equal_to_current_is_refused() {
        let err = AppConfig::validate_master_key_versioning(CURRENT, 2, Some(CURRENT))
            .expect_err("same secret twice must not start");
        assert!(err.contains("must differ"), "{err}");
    }

    #[test]
    fn previous_secret_requires_version_two_or_more() {
        let err = AppConfig::validate_master_key_versioning(CURRENT, 1, Some(PREVIOUS))
            .expect_err("previous secret at version 1 has no version to belong to");
        assert!(err.contains("at least 2"), "{err}");
    }

    #[test]
    fn previous_secret_must_be_long_enough() {
        let err = AppConfig::validate_master_key_versioning(CURRENT, 2, Some("short"))
            .expect_err("short previous secret");
        assert!(err.contains("16 characters"), "{err}");
    }

    #[test]
    fn version_must_be_positive() {
        assert!(AppConfig::validate_master_key_versioning(CURRENT, 0, None).is_err());
        assert!(AppConfig::validate_master_key_versioning(CURRENT, -3, None).is_err());
    }

    #[test]
    fn valid_rollover_window_is_accepted() {
        AppConfig::validate_master_key_versioning(CURRENT, 2, Some(PREVIOUS))
            .expect("current v2 with previous v1");
        AppConfig::validate_master_key_versioning(CURRENT, 1, None).expect("single key");
        AppConfig::validate_master_key_versioning(CURRENT, 7, None).expect("no previous at v7");
    }

    #[test]
    fn argon2_parameters_default_to_production_cost() {
        use agent_cordon_core::crypto::Argon2Params;
        assert_eq!(
            AppConfig::parse_argon2_params(None, None, None).expect("defaults"),
            Argon2Params::PRODUCTION
        );
        assert_eq!(
            AppConfig::parse_argon2_params(Some(""), None, Some("  ")).expect("blank is unset"),
            Argon2Params::PRODUCTION
        );
    }

    #[test]
    fn argon2_parameters_come_from_the_environment() {
        use agent_cordon_core::crypto::Argon2Params;
        let params = AppConfig::parse_argon2_params(Some("256"), Some("1"), Some("1"))
            .expect("cheap parameters");
        assert_eq!(params, Argon2Params::FAST);
    }

    #[test]
    fn nonsense_argon2_parameters_stop_startup() {
        let err = AppConfig::parse_argon2_params(Some("lots"), None, None)
            .expect_err("non-numeric memory cost");
        assert!(err.contains("AGTCRDN_ARGON2_M_COST_KIB"), "{err}");
        assert!(
            AppConfig::parse_argon2_params(Some("0"), None, None).is_err(),
            "zero memory cost is not a valid Argon2 configuration"
        );
        assert!(AppConfig::parse_argon2_params(None, Some("0"), None).is_err());
    }

    #[test]
    fn debug_redacts_every_secret() {
        let mut config = AppConfig::test_default();
        config.previous_master_secret = Some(PREVIOUS.to_string());
        config.previous_kdf_salt = Some("prev-salt".to_string());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(config.master_secret.as_str()));
        assert!(!rendered.contains(PREVIOUS));
        assert!(!rendered.contains("prev-salt"));
        assert!(rendered.contains("master_key_version: 1"));
    }
}
