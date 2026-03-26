use std::collections::HashMap;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use rhai::packages::{
    ArithmeticPackage, BasicArrayPackage, BasicMapPackage, BasicMathPackage, BasicStringPackage,
    LogicPackage, MoreStringPackage, Package,
};
use rhai::{Dynamic, Engine, Map, Scope};
use sha2::{Digest, Sha256};

use crate::error::TransformError;
use crate::transform::builtins;
use crate::transform::TransformOutput;

/// Maximum operations for Rhai script execution (prevents infinite loops).
const DEFAULT_MAX_OPERATIONS: u64 = 10_000;

/// Maximum string length in Rhai (1 MB).
const MAX_STRING_SIZE: usize = 1_048_576;

/// Maximum array size in Rhai elements.
const MAX_ARRAY_SIZE: usize = 256;

/// Maximum map size in Rhai entries.
const MAX_MAP_SIZE: usize = 256;

/// Maximum call stack depth.
const MAX_CALL_LEVELS: usize = 16;

/// Maximum expression nesting depth.
const MAX_EXPR_DEPTH: usize = 32;

/// Create a sandboxed Rhai `Engine` with resource limits and helper functions registered.
///
/// SECURITY: Uses `Engine::new_raw()` to avoid loading standard I/O packages
/// (print, debug, eval, timestamp, etc.). Only safe computation packages are
/// loaded explicitly. The `on_print` and `on_debug` callbacks are set to no-ops
/// as defense-in-depth.
fn create_engine() -> Engine {
    // new_raw() starts with a completely empty engine — no built-in functions.
    // This prevents access to: print, debug, eval, timestamp, and any I/O.
    let mut engine = Engine::new_raw();

    // Selectively register only safe computation packages.
    // These provide arithmetic, string ops, logic, arrays, maps — no I/O.
    engine.register_global_module(ArithmeticPackage::new().as_shared_module());
    engine.register_global_module(LogicPackage::new().as_shared_module());
    engine.register_global_module(BasicStringPackage::new().as_shared_module());
    engine.register_global_module(MoreStringPackage::new().as_shared_module());
    engine.register_global_module(BasicArrayPackage::new().as_shared_module());
    engine.register_global_module(BasicMapPackage::new().as_shared_module());
    engine.register_global_module(BasicMathPackage::new().as_shared_module());

    // Resource limits — prevent DoS via infinite loops, memory exhaustion, deep recursion
    engine.set_max_operations(DEFAULT_MAX_OPERATIONS);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_EXPR_DEPTH);

    // Defense-in-depth: neutralize print/debug even though they shouldn't be
    // registered by new_raw(). This prevents any secret exfiltration via stdout/stderr.
    engine.on_print(|_| {});
    engine.on_debug(|_, _, _| {});

    // Register helper functions
    engine.register_fn("hmac_sha256", hmac_sha256_fn);
    engine.register_fn("sha256", sha256_fn);
    engine.register_fn("base64_encode", base64_encode_fn);
    engine.register_fn("base64_decode", base64_decode_fn);
    engine.register_fn("hex_encode", hex_encode_fn);
    engine.register_fn("url_encode", url_encode_fn);
    engine.register_fn("url_decode", url_decode_fn);

    engine
}

/// HMAC-SHA256 helper: returns hex-encoded MAC.
fn hmac_sha256_fn(key: String, data: String) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// SHA-256 helper: returns hex-encoded hash.
fn sha256_fn(data: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Base64 encode helper.
fn base64_encode_fn(data: String) -> String {
    base64::engine::general_purpose::STANDARD.encode(data.as_bytes())
}

/// Base64 decode helper (returns empty string on invalid input).
fn base64_decode_fn(data: String) -> String {
    match base64::engine::general_purpose::STANDARD.decode(data.as_bytes()) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Hex encode helper.
fn hex_encode_fn(data: String) -> String {
    hex::encode(data.as_bytes())
}

/// URL encode helper (percent-encoding).
fn url_encode_fn(data: String) -> String {
    url::form_urlencoded::byte_serialize(data.as_bytes()).collect()
}

/// URL decode helper.
fn url_decode_fn(data: String) -> String {
    url::form_urlencoded::parse(data.as_bytes())
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{}={}", k, v)
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Sanitize a Rhai error message by removing any secret material.
///
/// SECURITY: Rhai's `throw` statement embeds the thrown value in the error
/// message. A malicious script could do `throw secret` to exfiltrate the
/// decrypted credential value through error messages or logs. This function
/// replaces any occurrence of the secret (and other sensitive scope variables)
/// with `[REDACTED]`.
fn sanitize_error_message(msg: &str, secret: &str) -> String {
    let mut sanitized = msg.to_string();

    // Redact the secret value if it appears anywhere in the error message.
    // Only redact non-empty secrets to avoid replacing empty strings everywhere.
    if !secret.is_empty() {
        sanitized = sanitized.replace(secret, "[REDACTED]");
    }

    sanitized
}

/// Execute a Rhai transform script with the given context.
///
/// The script has access to variables: `secret`, `method`, `url`, `headers` (Map), `body`.
/// It must return a String value.
///
/// SECURITY: Error messages are sanitized to remove secret material before
/// being returned. This prevents exfiltration via `throw secret` or similar
/// patterns in malicious scripts.
pub fn execute_transform(
    script: &str,
    secret: &str,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<TransformOutput, TransformError> {
    // Defense-in-depth: reject oversized scripts even if the handler didn't catch it.
    if script.len() > crate::transform::MAX_TRANSFORM_SCRIPT_SIZE {
        return Err(TransformError::ScriptError(format!(
            "transform script exceeds maximum size of {} bytes",
            crate::transform::MAX_TRANSFORM_SCRIPT_SIZE
        )));
    }

    let engine = create_engine();
    let mut scope = Scope::new();

    scope.push("secret", secret.to_string());
    scope.push("method", method.to_string());
    scope.push("url", url.to_string());
    scope.push("body", body.to_string());

    // Convert headers to Rhai Map
    let mut rhai_headers = Map::new();
    for (k, v) in headers {
        rhai_headers.insert(k.clone().into(), Dynamic::from(v.clone()));
    }
    scope.push("headers", rhai_headers);

    let result = engine
        .eval_with_scope::<Dynamic>(&mut scope, script)
        .map_err(|e| {
            // Check if it's a timeout/resource limit error
            let msg = e.to_string();
            if msg.contains("Too many operations") {
                TransformError::Timeout
            } else {
                // SECURITY: sanitize error message to prevent secret leakage
                // via `throw secret` or similar patterns.
                TransformError::ScriptError(sanitize_error_message(&msg, secret))
            }
        })?;

    let value = result
        .into_string()
        .map_err(|_| TransformError::InvalidReturnType)?;

    Ok(value.into())
}

/// Resolve a transform: custom script > named built-in > identity (passthrough).
///
/// - If `transform_script` is `Some`, run the Rhai script.
/// - Else if `transform_name` is `Some`, run the named built-in.
/// - Else return the secret as-is (identity transform).
pub fn resolve_transform(
    transform_name: Option<&str>,
    transform_script: Option<&str>,
    secret: &str,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
) -> Result<TransformOutput, TransformError> {
    if let Some(script) = transform_script {
        return execute_transform(script, secret, method, url, headers, body);
    }

    if let Some(name) = transform_name {
        return match name {
            "identity" => Ok(builtins::identity(secret)),
            "basic-auth" => Ok(builtins::basic_auth(secret)),
            "bearer" => Ok(builtins::bearer(secret)),
            "aws-sigv4" => {
                builtins::aws_sigv4(secret, method, url, headers, body, None).map_err(|e| match e {
                    TransformError::ScriptError(msg) => {
                        TransformError::ScriptError(sanitize_error_message(&msg, secret))
                    }
                    other => other,
                })
            }
            other => Err(TransformError::UnknownBuiltin(other.to_string())),
        };
    }

    // No transform specified — identity
    Ok(builtins::identity(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_no_script_no_name() {
        let result = resolve_transform(
            None,
            None,
            "my-secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "my-secret");
    }

    #[test]
    fn test_builtin_bearer() {
        let result = resolve_transform(
            Some("bearer"),
            None,
            "tok123",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "Bearer tok123");
    }

    #[test]
    fn test_builtin_basic_auth() {
        let result = resolve_transform(
            Some("basic-auth"),
            None,
            "user:pass",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn test_builtin_identity() {
        let result = resolve_transform(
            Some("identity"),
            None,
            "raw",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "raw");
    }

    #[test]
    fn test_unknown_builtin() {
        let result = resolve_transform(
            Some("nonexistent"),
            None,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(matches!(result, Err(TransformError::UnknownBuiltin(_))));
    }

    #[test]
    fn test_custom_script_simple() {
        let script = r#"secret + "-transformed""#;
        let result = execute_transform(
            script,
            "my-secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "my-secret-transformed");
    }

    #[test]
    fn test_custom_script_uses_method() {
        let script = r#"method + ":" + secret"#;
        let result = execute_transform(
            script,
            "tok",
            "POST",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "POST:tok");
    }

    #[test]
    fn test_custom_script_uses_url() {
        let script = r#"url + "?key=" + secret"#;
        let result = execute_transform(
            script,
            "abc",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "https://example.com?key=abc");
    }

    #[test]
    fn test_custom_script_uses_body() {
        let script = r#"body + secret"#;
        let result = execute_transform(
            script,
            "end",
            "POST",
            "https://example.com",
            &HashMap::new(),
            "start-",
        );
        assert_eq!(result.unwrap().value, "start-end");
    }

    #[test]
    fn test_custom_script_uses_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let script = r#"headers["Content-Type"] + ":" + secret"#;
        let result = execute_transform(script, "val", "GET", "https://example.com", &headers, "");
        assert_eq!(result.unwrap().value, "application/json:val");
    }

    #[test]
    fn test_script_overrides_name() {
        // When both script and name are provided, script wins
        let script = r#""custom-" + secret"#;
        let result = resolve_transform(
            Some("bearer"),
            Some(script),
            "tok",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "custom-tok");
    }

    #[test]
    fn test_helper_base64_encode() {
        let script = r#"base64_encode(secret)"#;
        let result = execute_transform(
            script,
            "hello",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "aGVsbG8=");
    }

    #[test]
    fn test_helper_base64_decode() {
        let script = r#"base64_decode("aGVsbG8=")"#;
        let result = execute_transform(
            script,
            "",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "hello");
    }

    #[test]
    fn test_helper_sha256() {
        let script = r#"sha256(secret)"#;
        let result = execute_transform(
            script,
            "test",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        let expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        assert_eq!(result.unwrap().value, expected);
    }

    #[test]
    fn test_helper_hmac_sha256() {
        let script = r#"hmac_sha256("key", secret)"#;
        let result = execute_transform(
            script,
            "data",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        // Verify it returns a hex string of expected length (64 hex chars for SHA256)
        let output = result.unwrap().value;
        assert_eq!(output.len(), 64);
        assert!(output.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_helper_hex_encode() {
        let script = r#"hex_encode(secret)"#;
        let result = execute_transform(
            script,
            "AB",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert_eq!(result.unwrap().value, "4142");
    }

    #[test]
    fn test_helper_url_encode() {
        let script = r#"url_encode(secret)"#;
        let result = execute_transform(
            script,
            "hello world&foo=bar",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        let output = result.unwrap().value;
        assert!(output.contains("hello"));
        assert!(!output.contains(' '));
    }

    #[test]
    fn test_helper_url_decode() {
        let script = r#"url_decode("hello%20world")"#;
        let result = execute_transform(
            script,
            "",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        let output = result.unwrap().value;
        assert!(output.contains("hello world"));
    }

    #[test]
    fn test_helper_base64_decode_invalid_input() {
        let script = r#"base64_decode("!!!not-valid-base64!!!")"#;
        let result = execute_transform(
            script,
            "",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        // Invalid base64 returns empty string per implementation
        assert_eq!(result.unwrap().value, "");
    }

    #[test]
    fn test_invalid_script() {
        let script = r#"this is not valid rhai code @@!!"#;
        let result = execute_transform(
            script,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(matches!(result, Err(TransformError::ScriptError(_))));
    }

    #[test]
    fn test_non_string_return() {
        let script = r#"42"#;
        let result = execute_transform(
            script,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(matches!(result, Err(TransformError::InvalidReturnType)));
    }

    #[test]
    fn test_resource_limits_infinite_loop() {
        let script = r#"loop { } ; "never""#;
        let result = execute_transform(
            script,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(matches!(result, Err(TransformError::Timeout)));
    }

    #[test]
    fn test_throw_does_not_leak_secret() {
        // A malicious script could try to exfiltrate the secret via throw.
        // The error message MUST NOT contain the actual secret value.
        let script = r#"throw secret"#;
        let result = execute_transform(
            script,
            "SUPER_SECRET_TOKEN_12345",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        match &result {
            Err(TransformError::ScriptError(msg)) => {
                assert!(
                    !msg.contains("SUPER_SECRET_TOKEN_12345"),
                    "SECRET LEAKED in error message: {}",
                    msg
                );
            }
            other => panic!("Expected ScriptError, got: {:?}", other),
        }
    }

    #[test]
    fn test_string_concat_throw_does_not_leak_secret() {
        // Attacker concatenates secret into error message
        let script = r#"throw "stolen:" + secret"#;
        let result = execute_transform(
            script,
            "MY_API_KEY_XYZ",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        match &result {
            Err(TransformError::ScriptError(msg)) => {
                assert!(
                    !msg.contains("MY_API_KEY_XYZ"),
                    "SECRET LEAKED via string concat throw: {}",
                    msg
                );
            }
            other => panic!("Expected ScriptError, got: {:?}", other),
        }
    }

    #[test]
    fn test_print_is_noop() {
        // print() is registered via on_print callback but is a no-op.
        // It should not cause script failure, but also not produce output.
        // The callback discards all output, preventing secret exfiltration
        // through stdout/stderr.
        let script = r#"print(secret); secret"#;
        let result = execute_transform(
            script,
            "secret_value",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        // print succeeds silently (no-op), script returns the secret
        assert_eq!(result.unwrap().value, "secret_value");
    }

    #[test]
    fn test_eval_not_available() {
        // eval() allows dynamic code execution and must not be available
        let script = r#"eval("40 + 2")"#;
        let result = execute_transform(
            script,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(
            result.is_err(),
            "eval should not be available in sandboxed engine"
        );
    }

    #[test]
    fn test_oversized_script_rejected() {
        // Scripts exceeding MAX_TRANSFORM_SCRIPT_SIZE must be rejected
        let oversized = "a".repeat(crate::transform::MAX_TRANSFORM_SCRIPT_SIZE + 1);
        let result = execute_transform(
            &oversized,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        match &result {
            Err(TransformError::ScriptError(msg)) => {
                assert!(
                    msg.contains("exceeds maximum size"),
                    "Expected size error, got: {}",
                    msg
                );
            }
            other => panic!("Expected ScriptError, got: {:?}", other),
        }
    }

    #[test]
    fn test_max_size_script_accepted() {
        // A script exactly at the limit should be accepted (it will fail to parse
        // since it's just 'a' repeated, but it should not be rejected for size)
        let at_limit = "a".repeat(crate::transform::MAX_TRANSFORM_SCRIPT_SIZE);
        let result = execute_transform(
            &at_limit,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        // It should fail with a script error (parsing), NOT a size error
        if let Err(TransformError::ScriptError(msg)) = &result {
            assert!(
                !msg.contains("exceeds maximum size"),
                "Should not be a size error at exact limit"
            );
        }
        // Any other result is fine as long as it's not a size rejection
    }

    #[test]
    fn test_timestamp_not_available() {
        // timestamp() could be used for timing side-channel attacks
        let script = r#"let t = timestamp(); secret"#;
        let result = execute_transform(
            script,
            "secret",
            "GET",
            "https://example.com",
            &HashMap::new(),
            "",
        );
        assert!(
            result.is_err(),
            "timestamp should not be available in sandboxed engine"
        );
    }
}
