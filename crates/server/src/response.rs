//! The one error envelope.
//!
//! Every error a route returns is an [`ApiError`], rendered as
//! `{"error": {"code", "message"}}`. OAuth endpoints, where RFC 6749 §5.2
//! fixes the body shape, return an [`OAuthError`] rendered as
//! `{"error", "error_description"}`. Browser pages that must show an error
//! as HTML render an `ApiError` through [`ApiError::into_html_response`].

use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// The one success envelope: `{"data": ...}`.
///
/// Defined in `agent-cordon-core` as `ApiEnvelope` so the broker
/// deserialises the exact type the server serialises.
pub use agent_cordon_core::wire::ApiEnvelope as ApiResponse;

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
}

#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    Unauthorized(String),
    Forbidden(String),
    /// A vend refused because the target is outside the credential's
    /// `allowed_url_pattern`. Its own code, because "forbidden" reads as a
    /// Cedar denial and sends the reader to `/policies` — the wrong screen
    /// for a mismatch that lives on the credential.
    UrlPatternDenied(String),
    BadRequest(String),
    Conflict(String),
    Gone(String),
    Internal(String),
    BadGateway(String),
    TooManyRequests(String),
    UnprocessableEntity(String),
    CredentialLeakDetected(String),
    PolicyValidation {
        errors: Vec<agent_cordon_core::domain::policy::PolicyValidationError>,
    },
    /// Multiple credentials match the requested name. Returns candidates for disambiguation.
    MultipleChoices {
        message: String,
        candidates: Vec<serde_json::Value>,
    },
    /// No exact match for the requested credential name, but related candidates
    /// (e.g., name-prefix matches) are surfaced to help the caller pick one.
    NotFoundWithCandidates {
        message: String,
        candidates: Vec<serde_json::Value>,
    },
}

impl ApiError {
    /// The HTTP status this error is reported with.
    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::NotFound(_) | ApiError::NotFoundWithCandidates { .. } => {
                StatusCode::NOT_FOUND
            }
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) | ApiError::UrlPatternDenied(_) => StatusCode::FORBIDDEN,
            ApiError::BadRequest(_) | ApiError::PolicyValidation { .. } => StatusCode::BAD_REQUEST,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Gone(_) => StatusCode::GONE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::BadGateway(_) | ApiError::CredentialLeakDetected(_) => {
                StatusCode::BAD_GATEWAY
            }
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            ApiError::UnprocessableEntity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::MultipleChoices { .. } => StatusCode::MULTIPLE_CHOICES,
        }
    }

    /// The message a caller may see. Internal errors are logged and
    /// replaced with a generic message.
    pub fn public_message(&self) -> String {
        match self {
            ApiError::NotFound(m)
            | ApiError::Unauthorized(m)
            | ApiError::Forbidden(m)
            | ApiError::UrlPatternDenied(m)
            | ApiError::BadRequest(m)
            | ApiError::Conflict(m)
            | ApiError::Gone(m)
            | ApiError::BadGateway(m)
            | ApiError::TooManyRequests(m)
            | ApiError::UnprocessableEntity(m)
            | ApiError::CredentialLeakDetected(m) => m.clone(),
            ApiError::Internal(m) => {
                tracing::error!(error = %m, "internal server error");
                "internal server error".to_string()
            }
            ApiError::PolicyValidation { .. } => "Policy validation failed".to_string(),
            ApiError::MultipleChoices { message, .. }
            | ApiError::NotFoundWithCandidates { message, .. } => message.clone(),
        }
    }

    /// Render as a minimal HTML page, for browser flows (consent, activate)
    /// where a JSON body would be shown raw. Same status as the JSON form.
    pub fn into_html_response(self) -> Response {
        let status = self.status();
        let message = self.public_message();
        let title = status.canonical_reason().unwrap_or("Error");
        let html = format!(
            "<!DOCTYPE html><html><head><title>{title}</title>\
            <style>body{{font-family:system-ui;max-width:600px;margin:60px auto;padding:20px;color:#1a1a1a}}\
            h1{{color:#c00}}code{{background:#f4f4f4;padding:2px 6px;border-radius:3px}}</style></head>\
            <body><h1>{title}</h1>\
            <p>{}</p>\
            <p><a href=\"/dashboard\">Return to dashboard</a></p></body></html>",
            html_escape(&message),
        );
        (status, Html(html)).into_response()
    }
}

/// Minimal HTML escape for embedding messages in an error page.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// An RFC 6749 §5.2 error: `{"error", "error_description"}`. Used only by
/// the OAuth token, device-code, and revocation endpoints, where the RFC
/// fixes the body shape; every other route uses [`ApiError`].
#[derive(Debug, Clone, Serialize)]
pub struct OAuthError {
    #[serde(skip)]
    pub status: StatusCode,
    pub error: String,
    pub error_description: String,
}

impl OAuthError {
    pub fn new(status: StatusCode, error: &str, description: &str) -> Self {
        Self {
            status,
            error: error.to_string(),
            error_description: description.to_string(),
        }
    }

    /// `invalid_request` (400).
    pub fn invalid_request(description: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    /// `invalid_client` (401).
    pub fn invalid_client(description: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", description)
    }

    /// `invalid_grant` (400).
    pub fn invalid_grant(description: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    /// `invalid_scope` (400).
    pub fn invalid_scope(description: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_scope", description)
    }

    /// `server_error` (500). The detail is logged, not returned.
    pub fn server_error(detail: impl std::fmt::Display) -> Self {
        tracing::error!(error = %detail, "oauth server error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "internal error",
        )
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        // RFC 6749 §5.1/§5.2: token responses, errors included, must not be cached.
        (
            self.status,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(self),
        )
            .into_response()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
            ApiError::UrlPatternDenied(msg) => (StatusCode::FORBIDDEN, "url_pattern_denied", msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg),
            ApiError::Gone(msg) => (StatusCode::GONE, "gone", msg),
            ApiError::Internal(msg) => {
                tracing::error!(error = %msg, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".to_string(),
                )
            }
            ApiError::BadGateway(msg) => (StatusCode::BAD_GATEWAY, "bad_gateway", msg),
            ApiError::TooManyRequests(msg) => {
                (StatusCode::TOO_MANY_REQUESTS, "too_many_requests", msg)
            }
            ApiError::UnprocessableEntity(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "unprocessable_entity",
                msg,
            ),
            ApiError::CredentialLeakDetected(msg) => {
                (StatusCode::BAD_GATEWAY, "credential_leak_detected", msg)
            }
            ApiError::PolicyValidation { errors } => {
                let body = serde_json::json!({
                    "error": {
                        "code": "VALIDATION_FAILED",
                        "message": "Policy validation failed",
                        "details": {
                            "errors": errors
                        }
                    }
                });
                return (StatusCode::BAD_REQUEST, Json(body)).into_response();
            }
            ApiError::MultipleChoices {
                message,
                candidates,
            } => {
                let body = serde_json::json!({
                    "error": {
                        "code": "multiple_choices",
                        "message": message,
                        "candidates": candidates
                    }
                });
                return (StatusCode::MULTIPLE_CHOICES, Json(body)).into_response();
            }
            ApiError::NotFoundWithCandidates {
                message,
                candidates,
            } => {
                let body = serde_json::json!({
                    "error": {
                        "code": "not_found",
                        "message": message,
                        "candidates": candidates
                    }
                });
                return (StatusCode::NOT_FOUND, Json(body)).into_response();
            }
        };

        (
            status,
            Json(ErrorBody {
                error: ErrorDetail {
                    code: code.to_string(),
                    message,
                },
            }),
        )
            .into_response()
    }
}

impl From<agent_cordon_core::error::StoreError> for ApiError {
    fn from(e: agent_cordon_core::error::StoreError) -> Self {
        match e {
            agent_cordon_core::error::StoreError::NotFound(msg) => ApiError::NotFound(msg),
            agent_cordon_core::error::StoreError::Conflict { message, .. } => {
                ApiError::Conflict(message)
            }
            agent_cordon_core::error::StoreError::Database(msg) => ApiError::Internal(msg),
        }
    }
}

impl From<agent_cordon_core::error::AuthError> for ApiError {
    fn from(e: agent_cordon_core::error::AuthError) -> Self {
        match e {
            agent_cordon_core::error::AuthError::Unauthorized(msg) => ApiError::Unauthorized(msg),
            agent_cordon_core::error::AuthError::Forbidden(msg) => ApiError::Forbidden(msg),
            agent_cordon_core::error::AuthError::Internal(msg) => ApiError::Internal(msg),
            agent_cordon_core::error::AuthError::Jwt(msg) => ApiError::Unauthorized(msg),
            // Display impl provides a generic message ("invalid username or
            // password") to avoid leaking whether the user exists.
            agent_cordon_core::error::AuthError::LoginFailed(_) => {
                ApiError::Unauthorized("invalid username or password".to_string())
            }
        }
    }
}

impl From<agent_cordon_core::error::CryptoError> for ApiError {
    fn from(e: agent_cordon_core::error::CryptoError) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl From<agent_cordon_core::error::PolicyError> for ApiError {
    fn from(e: agent_cordon_core::error::PolicyError) -> Self {
        match e {
            agent_cordon_core::error::PolicyError::Parse(msg) => ApiError::BadRequest(msg),
            agent_cordon_core::error::PolicyError::Validation(msg) => ApiError::BadRequest(msg),
            _ => ApiError::Internal(e.to_string()),
        }
    }
}

impl From<agent_cordon_core::error::ServiceError> for ApiError {
    fn from(e: agent_cordon_core::error::ServiceError) -> Self {
        match e {
            agent_cordon_core::error::ServiceError::NotFound { resource, id } => {
                ApiError::NotFound(format!("{resource} not found: {id}"))
            }
            agent_cordon_core::error::ServiceError::Conflict { message } => {
                ApiError::Conflict(message)
            }
            agent_cordon_core::error::ServiceError::Validation { field, message } => {
                ApiError::BadRequest(format!("{field}: {message}"))
            }
            agent_cordon_core::error::ServiceError::Forbidden { reason } => {
                ApiError::Forbidden(reason)
            }
            agent_cordon_core::error::ServiceError::Unauthorized { reason } => {
                ApiError::Unauthorized(reason)
            }
            agent_cordon_core::error::ServiceError::Internal { message } => {
                ApiError::Internal(message)
            }
        }
    }
}
