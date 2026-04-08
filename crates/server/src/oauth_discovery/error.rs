use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("missing resource URL in template")]
    MissingResourceUrl,
    #[error("metadata request failed: {0}")]
    RequestFailed(String),
    #[error("metadata request timed out")]
    Timeout,
    #[error("metadata response too large (> 64 KiB)")]
    ResponseTooLarge,
    #[error("invalid metadata JSON: {0}")]
    InvalidMetadata(String),
    #[error("authorization server metadata missing '{field}'")]
    MissingField { field: String },
    #[error("no authorization servers in protected resource metadata")]
    NoAuthorizationServer,
    #[error("cross-origin endpoint: expected {expected}, got {actual}")]
    CrossOriginEndpoint { expected: String, actual: String },
    #[error("registration endpoint not supported by provider")]
    NoDcrSupport,
    #[error("DCR registration failed: HTTP {status}")]
    RegistrationFailed { status: u16 },
    #[error("URL parse failed: {0}")]
    InvalidUrl(String),
}
