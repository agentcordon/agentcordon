use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self { data }
    }
}

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

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "unauthorized", msg),
            ApiError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg),
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
