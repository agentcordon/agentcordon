use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {message}")]
    Conflict {
        message: String,
        existing_id: Option<uuid::Uuid>,
    },
}

/// Reason a user login attempt failed (for internal audit logging only —
/// never expose to the client, to avoid user-enumeration vectors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFailureReason {
    /// The username does not match any known user.
    UserNotFound,
    /// The password did not match.
    InvalidPassword,
    /// The user account exists but is disabled.
    UserDisabled,
}

impl LoginFailureReason {
    /// Machine-readable label used in audit event metadata.
    pub fn as_audit_str(&self) -> &'static str {
        match self {
            Self::UserNotFound => "user_not_found",
            Self::InvalidPassword => "invalid_password",
            Self::UserDisabled => "user_disabled",
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("internal auth error: {0}")]
    Internal(String),
    #[error("JWT error: {0}")]
    Jwt(String),
    /// Login failed with a specific internal reason (for audit logging).
    /// The display message is kept generic to prevent user enumeration.
    #[error("unauthorized: invalid username or password")]
    LoginFailed(LoginFailureReason),
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    Encryption(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("nonce exhaustion: encryption count for key exceeded 2^32 — rotate key")]
    NonceExhaustion,
}

#[derive(Debug, Error)]
pub enum TransformError {
    #[error("transform script error: {0}")]
    ScriptError(String),
    #[error("transform script returned non-string value")]
    InvalidReturnType,
    #[error("unknown built-in transform: {0}")]
    UnknownBuiltin(String),
    #[error("transform script timed out")]
    Timeout,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("policy validation error: {0}")]
    Validation(String),
    #[error("policy evaluation error: {0}")]
    Evaluation(String),
    #[error("schema error: {0}")]
    Schema(String),
}

/// Domain-level error type for the service layer.
///
/// `ServiceError` sits between storage/auth/crypto errors and HTTP responses.
/// Route handlers (and future service-layer functions) can return
/// `Result<T, ServiceError>` and rely on the server crate's
/// `From<ServiceError> for ApiError` to produce consistent HTTP responses.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("not found: {resource} {id}")]
    NotFound { resource: String, id: String },
    #[error("conflict: {message}")]
    Conflict { message: String },
    #[error("validation error on field '{field}': {message}")]
    Validation { field: String, message: String },
    #[error("forbidden: {reason}")]
    Forbidden { reason: String },
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound(msg) => ServiceError::NotFound {
                resource: "resource".to_string(),
                id: msg,
            },
            StoreError::Conflict { message, .. } => ServiceError::Conflict { message },
            StoreError::Database(msg) => ServiceError::Internal { message: msg },
        }
    }
}

impl From<AuthError> for ServiceError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Unauthorized(msg) => ServiceError::Unauthorized { reason: msg },
            AuthError::Forbidden(msg) => ServiceError::Forbidden { reason: msg },
            AuthError::Internal(msg) => ServiceError::Internal { message: msg },
            AuthError::Jwt(msg) => ServiceError::Unauthorized { reason: msg },
            AuthError::LoginFailed(_) => ServiceError::Unauthorized {
                reason: "invalid username or password".to_string(),
            },
        }
    }
}

impl From<CryptoError> for ServiceError {
    fn from(e: CryptoError) -> Self {
        ServiceError::Internal {
            message: e.to_string(),
        }
    }
}

impl From<PolicyError> for ServiceError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::Parse(msg) => ServiceError::Validation {
                field: "cedar_policy".to_string(),
                message: msg,
            },
            PolicyError::Validation(msg) => ServiceError::Validation {
                field: "cedar_policy".to_string(),
                message: msg,
            },
            PolicyError::Evaluation(msg) => ServiceError::Internal { message: msg },
            PolicyError::Schema(msg) => ServiceError::Internal { message: msg },
        }
    }
}
