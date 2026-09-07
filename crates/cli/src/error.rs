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
    /// `proxy --auto` found no credential fenced for the target, or more
    /// than one. Its own code because it is neither "not registered" (3)
    /// nor a refusal by the broker: nothing was asked of the broker beyond
    /// the listing, and the fix is to name a credential or create one.
    NoCredentialMatch = 7,
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
            message: "broker is not running.\n\
                      Start it first: agentcordon-broker --server-url <url>\n\
                      Or pass: agentcordon register --server-url <url> (auto-starts the broker)."
                .into(),
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

    /// `proxy --auto` could not settle on exactly one credential.
    pub fn no_credential_match(msg: impl Into<String>) -> Self {
        Self {
            code: ExitCode::NoCredentialMatch,
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

/// How the broker words its SSRF refusal, on both the `/proxy` and the
/// `/mcp/call` route. The two routes label it differently on the wire
/// (`bad_request` and `ssrf_blocked`), so the message is what identifies the
/// guard across them.
const SSRF_REFUSAL: &str = "Blocked by SSRF protection";

/// True when a broker error is the SSRF guard refusing the target.
fn is_ssrf_refusal(code: &str, message: &str) -> bool {
    code == "ssrf_blocked" || message.starts_with(SSRF_REFUSAL)
}

/// The exit code for one broker error envelope.
///
/// Every command classifies a broker refusal here, so the same refusal
/// cannot exit two different ways depending on which command hit it: an
/// SSRF-blocked target used to exit 6 from `proxy` and 1 from `mcp-call`,
/// and a script wrapping both could not treat one guard uniformly.
pub fn exit_code_for(http_status: u16, code: &str, message: &str) -> ExitCode {
    if code == "reregistration_required" {
        return ExitCode::NotRegistered;
    }
    // The guard refuses the target before any request is made, so nothing
    // upstream ever answered — whatever the route called the refusal.
    if is_ssrf_refusal(code, message) {
        return ExitCode::GeneralError;
    }
    match (http_status, code) {
        (401, _) => ExitCode::AuthFailed,
        (403, _) => ExitCode::AuthorizationDenied,
        (409, _) => ExitCode::GeneralError,
        (502, _) | (_, "bad_gateway") => ExitCode::UpstreamError,
        _ => ExitCode::GeneralError,
    }
}

/// Map a broker error response code to the appropriate CliError.
///
/// Includes the HTTP status and reason phrase so CLI users get actionable diagnostics.
pub fn from_broker_error(http_status: u16, code: &str, message: &str) -> CliError {
    // Workspace needs re-registration — give a clear, actionable message
    if code == "reregistration_required" {
        return CliError {
            code: ExitCode::NotRegistered,
            message: "Workspace needs re-registration.\nRun: agentcordon register --force".into(),
        };
    }

    let reason = http_reason(http_status);
    CliError {
        code: exit_code_for(http_status, code, message),
        message: format!("{http_status} {reason}: {message}"),
    }
}

/// Return the standard HTTP reason phrase for common status codes.
fn http_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SSRF guard is one guard, however the route labels it: `/proxy`
    /// sends `bad_request` and `/mcp/call` sends `ssrf_blocked`. Both must
    /// classify the same, or a script wrapping the two commands cannot
    /// treat one refusal uniformly.
    #[test]
    fn an_ssrf_refusal_exits_the_same_way_on_both_routes() {
        let from_proxy = from_broker_error(
            400,
            "bad_request",
            "Blocked by SSRF protection: 127.0.0.1 is a loopback address",
        );
        let from_mcp = from_broker_error(
            400,
            "ssrf_blocked",
            "Blocked by SSRF protection: MCP server 'echo': 127.0.0.1 is a loopback address",
        );

        assert_eq!(from_proxy.code, from_mcp.code);
        assert_eq!(
            from_proxy.code,
            ExitCode::GeneralError,
            "nothing was proxied, so this is not an upstream error"
        );
    }

    /// A refusal that never reached an upstream must not claim the upstream
    /// answered.
    #[test]
    fn an_ssrf_refusal_is_not_an_upstream_error() {
        let e = from_broker_error(400, "bad_request", "Blocked by SSRF protection: reserved");
        assert_ne!(e.code, ExitCode::UpstreamError);
    }

    /// The other mappings are unchanged.
    #[test]
    fn broker_errors_keep_their_documented_codes() {
        assert_eq!(
            from_broker_error(401, "unauthorized", "bad signature").code,
            ExitCode::AuthFailed
        );
        assert_eq!(
            from_broker_error(403, "url_pattern_denied", "fenced").code,
            ExitCode::AuthorizationDenied
        );
        assert_eq!(
            from_broker_error(502, "bad_gateway", "upstream refused").code,
            ExitCode::UpstreamError
        );
        assert_eq!(
            from_broker_error(400, "bad_request", "Invalid HTTP method: FETCH").code,
            ExitCode::GeneralError
        );
        assert_eq!(
            from_broker_error(409, "reregistration_required", "stale").code,
            ExitCode::NotRegistered
        );
    }
}
