use super::aws_sigv4::{canonical_query_string, hmac_sha256_raw, sha256_hex, uri_encode};
use super::*;

use crate::error::TransformError;
use std::collections::HashMap;

#[test]
fn test_identity() {
    assert_eq!(identity("my-secret").value, "my-secret");
    assert_eq!(identity("").value, "");
}

#[test]
fn test_basic_auth() {
    let result = basic_auth("user:pass");
    assert_eq!(result.value, "Basic dXNlcjpwYXNz");
    assert!(result.extra_headers.is_empty());
}

#[test]
fn test_bearer() {
    assert_eq!(bearer("tok123").value, "Bearer tok123");
}

// ---- AWS SigV4 tests ----

fn aws_test_cred() -> String {
    serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "iam"
    })
    .to_string()
}

#[test]
fn test_aws_sigv4_get_list_users() {
    // AWS SigV4 test vector: GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08
    // Timestamp: 20150830T123600Z
    let secret = aws_test_cred();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    // Verify the Authorization header structure
    assert!(result.value.starts_with(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"
    ));
    assert!(result
        .value
        .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));

    // Verify extra headers
    assert_eq!(
        result.extra_headers.get("x-amz-date").unwrap(),
        "20150830T123600Z"
    );
    assert_eq!(
        result.extra_headers.get("host").unwrap(),
        "iam.amazonaws.com"
    );
    assert!(result.extra_headers.contains_key("x-amz-content-sha256"));

    // Verify deterministic signature for our signed headers set
    // (host;x-amz-content-sha256;x-amz-date — differs from AWS docs example
    // which uses content-type;host;x-amz-date)
    let expected_sig = "65f031d93b4631aedf16a8f7f830cdc8ce2bc5276c307b5a2cc2143d4b68e323";
    assert!(
        result
            .value
            .contains(&format!("Signature={}", expected_sig)),
        "Signature mismatch. Got: {}",
        result.value
    );
}

#[test]
fn test_aws_sigv4_post_with_body() {
    let secret = aws_test_cred();
    let body = r#"{"key":"value"}"#;
    let result = aws_sigv4(
        &secret,
        "POST",
        "https://iam.amazonaws.com/",
        &HashMap::new(),
        body,
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    assert!(result.value.starts_with("AWS4-HMAC-SHA256"));
    // Body hash should be of the actual body, not empty
    let body_hash = sha256_hex(body.as_bytes());
    assert_eq!(
        result.extra_headers.get("x-amz-content-sha256").unwrap(),
        &body_hash
    );
}

#[test]
fn test_aws_sigv4_invalid_json() {
    let result = aws_sigv4(
        "not-json",
        "GET",
        "https://example.com/",
        &HashMap::new(),
        "",
        None,
    );
    assert!(matches!(result, Err(TransformError::ScriptError(_))));
}

#[test]
fn test_aws_sigv4_missing_region_service_non_aws_url() {
    // region/service are now optional — but if missing and URL is not *.amazonaws.com,
    // inference fails with an error
    let secret = serde_json::json!({
        "access_key_id": "AKID",
        "secret_access_key": "secret"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://example.com/",
        &HashMap::new(),
        "",
        None,
    );
    assert!(matches!(result, Err(TransformError::ScriptError(_))));
}

#[test]
fn test_aws_sigv4_missing_region_service_inferred_from_url() {
    // region/service omitted — inferred from amazonaws.com URL
    let secret = serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-west-2.amazonaws.com/mybucket/mykey",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed with inferred region/service");

    assert!(result.value.contains("us-west-2/s3/aws4_request"));
}

#[test]
fn test_aws_sigv4_explicit_region_overrides_inference() {
    // Explicit region/service in credential JSON takes precedence over URL inference
    let secret = serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "region": "eu-west-1",
        "service": "lambda"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-west-2.amazonaws.com/mybucket/mykey",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed with explicit region/service");

    // Should use the explicit values, not inferred
    assert!(result.value.contains("eu-west-1/lambda/aws4_request"));
}

#[test]
fn test_aws_sigv4_empty_access_key() {
    let secret = serde_json::json!({
        "access_key_id": "",
        "secret_access_key": "secret",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://example.com/",
        &HashMap::new(),
        "",
        None,
    );
    assert!(matches!(result, Err(TransformError::ScriptError(_))));
}

#[test]
fn test_aws_sigv4_query_params_sorted() {
    // Query params should be sorted alphabetically
    let secret = aws_test_cred();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/?Zebra=last&Action=first",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    // The signature should be deterministic for sorted params
    assert!(result.value.starts_with("AWS4-HMAC-SHA256"));
}

#[test]
fn test_aws_sigv4_path_encoding() {
    let secret = aws_test_cred();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/test%20path/file",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    assert!(result.value.starts_with("AWS4-HMAC-SHA256"));
}

#[test]
fn test_aws_sigv4_error_does_not_leak_secret() {
    // Ensure error messages don't contain the secret access key
    let secret = serde_json::json!({
        "access_key_id": "AKID",
        "secret_access_key": "",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://example.com/",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains("AKID"),
                "access_key_id leaked in error: {}",
                msg
            );
        }
        _ => panic!("Expected ScriptError"),
    }
}

#[test]
fn test_hmac_sha256_raw_correctness() {
    // Known HMAC-SHA256 test vector
    let key = b"key";
    let data = b"The quick brown fox jumps over the lazy dog";
    let result = hmac_sha256_raw(key, data);
    let hex_result = hex::encode(&result);
    assert_eq!(
        hex_result,
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
}

#[test]
fn test_uri_encode() {
    assert_eq!(uri_encode("hello world", true), "hello%20world");
    assert_eq!(uri_encode("test/path", true), "test%2Fpath");
    assert_eq!(uri_encode("test/path", false), "test/path");
    assert_eq!(uri_encode("a-b_c.d~e", true), "a-b_c.d~e");
}

#[test]
fn test_canonical_query_string_sorting() {
    let url = url::Url::parse("https://example.com/?b=2&a=1&c=3").unwrap();
    let qs = canonical_query_string(&url);
    assert_eq!(qs, "a=1&b=2&c=3");
}

#[test]
fn test_canonical_query_string_empty() {
    let url = url::Url::parse("https://example.com/").unwrap();
    let qs = canonical_query_string(&url);
    assert_eq!(qs, "");
}

#[test]
fn test_aws_sigv4_key_derivation() {
    // Verify the SigV4 key derivation chain produces correct results.
    // Using known AWS test values: secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    // date = "20150830", region = "us-east-1", service = "iam"
    let secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let k_date = hmac_sha256_raw(format!("AWS4{}", secret_key).as_bytes(), b"20150830");
    let k_region = hmac_sha256_raw(&k_date, b"us-east-1");
    let k_service = hmac_sha256_raw(&k_region, b"iam");
    let k_signing = hmac_sha256_raw(&k_service, b"aws4_request");

    // The signing key should be 32 bytes (SHA-256 output)
    assert_eq!(k_signing.len(), 32);

    // Verify the signing key matches the AWS documentation value
    let expected_signing_key = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";
    assert_eq!(hex::encode(&k_signing), expected_signing_key);
}

#[test]
fn test_aws_sigv4_url_with_port() {
    let secret = serde_json::json!({
        "access_key_id": "AKID",
        "secret_access_key": "secret",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.amazonaws.com:8443/bucket/key",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    assert_eq!(
        result.extra_headers.get("host").unwrap(),
        "s3.amazonaws.com:8443"
    );
}

// ---- AWS region/service inference tests ----

#[test]
fn test_infer_service_region_standard() {
    let (svc, reg) = infer_aws_region_service("https://s3.us-west-2.amazonaws.com/bucket").unwrap();
    assert_eq!(svc, "s3");
    assert_eq!(reg, "us-west-2");
}

#[test]
fn test_infer_service_region_lambda() {
    let (svc, reg) =
        infer_aws_region_service("https://lambda.eu-west-1.amazonaws.com/2015-03-31/functions")
            .unwrap();
    assert_eq!(svc, "lambda");
    assert_eq!(reg, "eu-west-1");
}

#[test]
fn test_infer_global_sts() {
    let (svc, reg) = infer_aws_region_service("https://sts.amazonaws.com/").unwrap();
    assert_eq!(svc, "sts");
    assert_eq!(reg, "us-east-1");
}

#[test]
fn test_infer_global_iam() {
    let (svc, reg) =
        infer_aws_region_service("https://iam.amazonaws.com/?Action=ListUsers").unwrap();
    assert_eq!(svc, "iam");
    assert_eq!(reg, "us-east-1");
}

#[test]
fn test_infer_global_cloudfront() {
    let (svc, reg) =
        infer_aws_region_service("https://cloudfront.amazonaws.com/2020-05-31/distribution")
            .unwrap();
    assert_eq!(svc, "cloudfront");
    assert_eq!(reg, "us-east-1");
}

#[test]
fn test_infer_global_route53() {
    let (svc, reg) =
        infer_aws_region_service("https://route53.amazonaws.com/2013-04-01/hostedzone").unwrap();
    assert_eq!(svc, "route53");
    assert_eq!(reg, "us-east-1");
}

#[test]
fn test_infer_s3_no_region() {
    // s3.amazonaws.com without region defaults to us-east-1
    let (svc, reg) = infer_aws_region_service("https://s3.amazonaws.com/bucket/key").unwrap();
    assert_eq!(svc, "s3");
    assert_eq!(reg, "us-east-1");
}

#[test]
fn test_infer_regional_sts() {
    let (svc, reg) = infer_aws_region_service("https://sts.ap-southeast-1.amazonaws.com/").unwrap();
    assert_eq!(svc, "sts");
    assert_eq!(reg, "ap-southeast-1");
}

#[test]
fn test_infer_non_aws_host_fails() {
    let result = infer_aws_region_service("https://api.example.com/path");
    assert!(matches!(result, Err(TransformError::ScriptError(_))));
}

#[test]
fn test_infer_invalid_url_fails() {
    let result = infer_aws_region_service("not a url");
    assert!(matches!(result, Err(TransformError::ScriptError(_))));
}

// =====================================================================
// v0.15 Phase 1.5 — Serde error path tests (Sprint item #8)
// Verify that aws_sigv4() deserialization errors do NOT leak secret values.
// =====================================================================

#[test]
fn test_aws_sigv4_malformed_json_does_not_leak_secret_value() {
    let secret_value = "this-is-a-super-secret-api-key-12345";
    let result = aws_sigv4(
        secret_value,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains(secret_value),
                "Error message must NOT contain the secret value. Got: {}",
                msg
            );
            assert!(
                !msg.contains("super-secret"),
                "Error message must NOT contain any part of the secret. Got: {}",
                msg
            );
        }
        other => panic!("Expected ScriptError, got: {:?}", other),
    }
}

#[test]
fn test_aws_sigv4_malformed_json_array_does_not_leak() {
    let secret_value = r#"["secret-key-AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI"]"#;
    let result = aws_sigv4(
        secret_value,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    if let Err(TransformError::ScriptError(msg)) = &result {
        assert!(
            !msg.contains("AKIAIOSFODNN7EXAMPLE"),
            "Error must not leak access key from array. Got: {}",
            msg
        );
        assert!(
            !msg.contains("wJalrXUtnFEMI"),
            "Error must not leak secret key from array. Got: {}",
            msg
        );
    }
    // If Ok, serde positional deserialization succeeded — acceptable behavior.
}

#[test]
fn test_aws_sigv4_missing_access_key_id_does_not_leak_secret_key() {
    let secret = serde_json::json!({
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains("wJalrXUtnFEMI"),
                "Error must not leak secret_access_key. Got: {}",
                msg
            );
        }
        other => panic!(
            "Expected ScriptError for missing access_key_id, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_aws_sigv4_missing_secret_access_key_does_not_leak_access_key() {
    let secret = serde_json::json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains("AKIAIOSFODNN7EXAMPLE"),
                "Error must not leak access_key_id. Got: {}",
                msg
            );
        }
        other => panic!(
            "Expected ScriptError for missing secret_access_key, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_aws_sigv4_empty_access_key_does_not_leak_secret_key() {
    let secret = serde_json::json!({
        "access_key_id": "",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains("wJalrXUtnFEMI"),
                "Error for empty access_key_id must not leak secret_access_key. Got: {}",
                msg
            );
        }
        other => panic!(
            "Expected ScriptError for empty access_key_id, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_aws_sigv4_empty_secret_key_does_not_leak_access_key() {
    let secret = serde_json::json!({
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains("AKIAIOSFODNN7EXAMPLE"),
                "Error for empty secret_access_key must not leak access_key_id. Got: {}",
                msg
            );
        }
        other => panic!(
            "Expected ScriptError for empty secret_access_key, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_aws_sigv4_extra_fields_json_does_not_leak_values() {
    let secret = serde_json::json!({
        "access_key_id": "AKID",
        "secret_access_key": "secret",
        "region": "us-east-1",
        "service": "s3",
        "unexpected_token": "SUPER_SECRET_SHOULD_NOT_LEAK"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket",
        &HashMap::new(),
        "",
        None,
    );
    // Whether this succeeds (ignoring extra fields) or fails, the error
    // must not contain the extra field value.
    if let Err(TransformError::ScriptError(msg)) = &result {
        assert!(
            !msg.contains("SUPER_SECRET_SHOULD_NOT_LEAK"),
            "Error must not leak unexpected field values. Got: {}",
            msg
        );
    }
    // If it succeeds, that's fine too (serde ignores extra fields by default)
}
