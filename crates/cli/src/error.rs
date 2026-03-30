use std::fmt;
use std::process;

/// Exit codes per the v3 thin CLI protocol spec (Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    BrokerNotRunning = 2,
    NotRegistered = 3,
    AuthFailed = 4,
    AuthorizationDenied = 5,
    UpstreamError = 6,
}

impl From<ExitCode> for process::ExitCode {
    fn from(code: ExitCode) -> Self {
        process::ExitCode::from(code as u8)
    }
}

/// CLI error type with structured exit codes.
#[derive(Debug)]
pub struct CliError {
    pub code: ExitCode,
    pub message: String,
}

impl CliError {
    pub fn general(msg: impl Into<String>) -> Self {
        Self {
            code: ExitCode::GeneralError,
            message: msg.into(),
        }
    }

    pub fn broker_not_running() -> Self {
        Self {
            code: ExitCode::BrokerNotRunning,
            message: "broker is not running.\nStart it with: agentcordon-broker start".into(),
        }
    }

    #[allow(dead_code)]
    pub fn not_registered() -> Self {
        Self {
            code: ExitCode::NotRegistered,
            message: "workspace is not registered.\nRun: agentcordon register".into(),
        }
    }

    pub fn auth_failed(msg: impl Into<String>) -> Self {
        Self {
            code: ExitCode::AuthFailed,
            message: msg.into(),
        }
    }

    pub fn authorization_denied(msg: impl Into<String>) -> Self {
        Self {
            code: ExitCode::AuthorizationDenied,
            message: msg.into(),
        }
    }

    pub fn upstream_error(msg: impl Into<String>) -> Self {
        Self {
            code: ExitCode::UpstreamError,
            message: msg.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

/// Map a broker error response code to the appropriate CliError.
pub fn from_broker_error(http_status: u16, code: &str, message: &str) -> CliError {
    match (http_status, code) {
        (401, _) => CliError::auth_failed(message),
        (403, _) => CliError::authorization_denied(message),
        (409, _) => CliError::general(message),
        (502, _) | (_, "bad_gateway") => CliError::upstream_error(message),
        _ => CliError::general(message),
    }
}
