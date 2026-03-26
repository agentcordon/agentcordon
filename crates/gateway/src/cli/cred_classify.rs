//! Credential classification helpers for MCP migration.
//!
//! Detects whether environment variables or HTTP headers contain
//! credential values that should be stored securely.

/// Classify an environment variable as a credential or config.
///
/// Logic:
/// 1. Negative name match -> not credential
/// 2. Positive name match -> credential
/// 3. Positive value match -> credential
/// 4. Otherwise -> not credential
pub fn is_credential_env_var(name: &str, value: &str) -> bool {
    let upper = name.to_uppercase();

    // Negative name patterns -- never a credential
    let negative_suffixes = [
        "_URL", "_HOST", "_PORT", "_PATH", "_DIR", "_ENV", "_MODE", "_LEVEL", "_REGION",
        "_VERSION", "_NAME", "_FORMAT", "_TIMEOUT",
    ];
    for suffix in &negative_suffixes {
        if upper.ends_with(suffix) {
            return false;
        }
    }

    // Positive name patterns (case-insensitive contains)
    let positive_contains = ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"];
    for pattern in &positive_contains {
        if upper.contains(pattern) {
            return true;
        }
    }

    // Positive name suffixes
    let positive_suffixes = ["_AUTH", "_PWD", "_PAT", "_BEARER"];
    for suffix in &positive_suffixes {
        if upper.ends_with(suffix) {
            return true;
        }
    }

    // Positive value patterns (fallback)
    let value_prefixes = ["sk-", "pk-", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA"];
    for prefix in &value_prefixes {
        if value.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Classify an HTTP header value as a credential or config.
///
/// Headers like `Authorization` almost always contain credentials.
/// Other headers with token/key-like values are also flagged.
pub fn is_credential_header(name: &str, value: &str) -> bool {
    let upper = name.to_uppercase();

    // Authorization header is always a credential
    if upper == "AUTHORIZATION" {
        return true;
    }

    // Headers with credential-like names
    let positive_contains = ["TOKEN", "KEY", "SECRET", "CREDENTIAL", "AUTH"];
    for pattern in &positive_contains {
        if upper.contains(pattern) {
            return true;
        }
    }

    // Check value patterns (Bearer tokens, API keys, etc.)
    let value_prefixes = [
        "Bearer ", "bearer ", "Basic ", "basic ", "Token ", "token ", "sk-", "ghp_", "gho_",
        "xoxb-", "xoxp-",
    ];
    for prefix in &value_prefixes {
        if value.starts_with(prefix) {
            return true;
        }
    }

    false
}

/// Format a credential name: `{server-name}-{env-var-name}` lowercased, underscores to hyphens.
pub fn format_credential_name(server_name: &str, env_var_name: &str) -> String {
    format!("{}-{}", server_name, env_var_name)
        .to_lowercase()
        .replace('_', "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- is_credential_env_var tests --

    #[test]
    fn test_positive_name_patterns() {
        assert!(is_credential_env_var("API_KEY", "some-value"));
        assert!(is_credential_env_var("GITHUB_TOKEN", "ghp_abc123"));
        assert!(is_credential_env_var("DB_PASSWORD", "hunter2"));
        assert!(is_credential_env_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI"
        ));
        assert!(is_credential_env_var("MY_CREDENTIAL", "abc"));
    }

    #[test]
    fn test_positive_suffix_patterns() {
        assert!(is_credential_env_var("SLACK_AUTH", "xoxb-123"));
        assert!(is_credential_env_var("MY_PWD", "pass"));
        assert!(is_credential_env_var("GITHUB_PAT", "ghp_abc"));
        assert!(is_credential_env_var("SERVICE_BEARER", "token123"));
    }

    #[test]
    fn test_negative_name_patterns() {
        assert!(!is_credential_env_var("API_URL", "https://api.example.com"));
        assert!(!is_credential_env_var("SERVER_HOST", "localhost"));
        assert!(!is_credential_env_var("SERVER_PORT", "8080"));
        assert!(!is_credential_env_var("DATA_PATH", "/var/data"));
        assert!(!is_credential_env_var("LOG_LEVEL", "debug"));
        assert!(!is_credential_env_var("AWS_REGION", "us-east-1"));
        assert!(!is_credential_env_var("APP_VERSION", "1.0.0"));
        assert!(!is_credential_env_var("SERVICE_NAME", "my-service"));
        assert!(!is_credential_env_var("OUTPUT_FORMAT", "json"));
        assert!(!is_credential_env_var("REQUEST_TIMEOUT", "30"));
    }

    #[test]
    fn test_negative_overrides_positive() {
        assert!(!is_credential_env_var("API_KEY_URL", "https://example.com"));
    }

    #[test]
    fn test_positive_value_patterns() {
        assert!(is_credential_env_var("SOME_VAR", "sk-abc123def456"));
        assert!(is_credential_env_var("ANOTHER", "ghp_abcdef123456"));
        assert!(is_credential_env_var("SLACK", "xoxb-123-456-abc"));
        assert!(is_credential_env_var("AWS", "AKIA1234567890ABCDEF"));
    }

    #[test]
    fn test_non_credential_value() {
        assert!(!is_credential_env_var("MY_SETTING", "plain-value"));
        assert!(!is_credential_env_var("SOME_FLAG", "true"));
        assert!(!is_credential_env_var("COUNT", "42"));
    }

    // -- is_credential_header tests --

    #[test]
    fn test_credential_header_authorization() {
        assert!(is_credential_header("Authorization", "Bearer ghp_abc123"));
        assert!(is_credential_header("authorization", "Basic dXNlcjpwYXNz"));
        assert!(is_credential_header("AUTHORIZATION", "Token abc123"));
    }

    #[test]
    fn test_credential_header_by_name() {
        assert!(is_credential_header("X-API-Key", "some-value"));
        assert!(is_credential_header("X-Auth-Token", "some-value"));
        assert!(is_credential_header("X-Secret", "some-value"));
    }

    #[test]
    fn test_non_credential_header() {
        assert!(!is_credential_header("Content-Type", "application/json"));
        assert!(!is_credential_header("Accept", "text/html"));
        assert!(!is_credential_header("User-Agent", "my-app/1.0"));
        assert!(!is_credential_header("X-Request-ID", "abc-123"));
    }

    #[test]
    fn test_credential_header_by_value() {
        assert!(is_credential_header("X-Custom", "Bearer ghp_abc123"));
        assert!(is_credential_header("X-Custom", "sk-abc123"));
        assert!(!is_credential_header("X-Custom", "plain-value"));
    }

    // -- format_credential_name tests --

    #[test]
    fn test_credential_name_formatting() {
        assert_eq!(
            format_credential_name("github", "GITHUB_TOKEN"),
            "github-github-token"
        );
        assert_eq!(
            format_credential_name("mock-api", "MOCK_API_KEY"),
            "mock-api-mock-api-key"
        );
        assert_eq!(
            format_credential_name("Slack", "SLACK_BOT_TOKEN"),
            "slack-slack-bot-token"
        );
    }
}
