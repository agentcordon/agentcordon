use super::aws_sigv4::{
    canonical_headers, canonical_query_string, canonical_request, canonical_uri_path,
    hmac_sha256_raw, sha256_hex, uri_encode,
};
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
    assert!(result.value.contains("SignedHeaders=host;x-amz-date"));

    // Verify extra headers
    assert_eq!(
        result.extra_headers.get("x-amz-date").unwrap(),
        "20150830T123600Z"
    );
    assert_eq!(
        result.extra_headers.get("host").unwrap(),
        "iam.amazonaws.com"
    );
    // IAM is not S3: no x-amz-content-sha256 header is added or signed.
    assert!(!result.extra_headers.contains_key("x-amz-content-sha256"));

    // Deterministic signature for the host;x-amz-date header set (the AWS docs
    // example additionally signs content-type; see the conformance test).
    let expected_sig = "b2e4af44cfad96d9ffa3c5653674a927b9b0995c33de22e1f843745ce37c1d5e";
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
    let secret = serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "region": "us-east-1",
        "service": "s3"
    })
    .to_string();
    let body = r#"{"key":"value"}"#;
    let result = aws_sigv4(
        &secret,
        "POST",
        "https://s3.amazonaws.com/bucket/key",
        &HashMap::new(),
        body,
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");

    assert!(result.value.starts_with("AWS4-HMAC-SHA256"));
    assert!(result
        .value
        .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
    // Body hash should be of the actual body, not empty
    let body_hash = sha256_hex(body.as_bytes());
    assert_eq!(
        result.extra_headers.get("x-amz-content-sha256").unwrap(),
        &body_hash
    );
}

#[test]
fn test_aws_sigv4_content_sha256_header_only_for_s3() {
    let body = "payload";
    let for_service = |service: &str, url: &str| {
        let secret = serde_json::json!({
            "access_key_id": "AKIDEXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "service": service
        })
        .to_string();
        aws_sigv4(
            &secret,
            "POST",
            url,
            &HashMap::new(),
            body,
            Some("20150830T123600Z"),
        )
        .expect("sigv4 should succeed")
    };

    let s3 = for_service("s3", "https://s3.us-east-1.amazonaws.com/bucket/key");
    assert!(s3.value.contains("x-amz-content-sha256"));
    assert_eq!(
        s3.extra_headers.get("x-amz-content-sha256").unwrap(),
        &sha256_hex(body.as_bytes())
    );

    let lambda = for_service(
        "lambda",
        "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/f/invocations",
    );
    assert!(!lambda.value.contains("x-amz-content-sha256"));
    assert!(!lambda.extra_headers.contains_key("x-amz-content-sha256"));
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

// =====================================================================
// Session-token support
// =====================================================================

const SESSION_TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtoken";
const SESSION_TOKEN_SIGNATURE: &str =
    "01bf99c7cc7c7eeef85f0bc752af65a9f32bf40c075a99bce00c4d1263ecf2c1";

fn assert_session_token_signed(result: &TransformOutput) {
    assert_eq!(
        result.extra_headers.get("x-amz-security-token").unwrap(),
        SESSION_TOKEN
    );
    assert!(
        result
            .value
            .contains("SignedHeaders=host;x-amz-date;x-amz-security-token"),
        "session token must be in the signed headers. Got: {}",
        result.value
    );
    assert!(
        result
            .value
            .contains(&format!("Signature={}", SESSION_TOKEN_SIGNATURE)),
        "Signature mismatch. Got: {}",
        result.value
    );
}

#[test]
fn test_aws_sigv4_session_token_adds_security_token_header() {
    let secret = serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "session_token": SESSION_TOKEN,
        "region": "us-east-1",
        "service": "iam"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert_session_token_signed(&result);
}

#[test]
fn test_aws_sigv4_session_token_accepts_aws_session_token_key() {
    let secret = serde_json::json!({
        "access_key_id": "AKIDEXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "aws_session_token": SESSION_TOKEN,
        "region": "us-east-1",
        "service": "iam"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert_session_token_signed(&result);
}

#[test]
fn test_aws_sigv4_session_token_is_part_of_canonical_request() {
    let url = url::Url::parse("https://iam.amazonaws.com/?Action=ListUsers").unwrap();
    let headers = canonical_headers(
        &HashMap::new(),
        &[
            ("host", "iam.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-security-token", SESSION_TOKEN),
        ],
    );
    let canonical = canonical_request(
        "GET",
        &url,
        &headers,
        &sha256_hex(b""),
        /* double_encode */ true,
    );
    assert!(canonical
        .request
        .contains(&format!("\nx-amz-security-token:{}\n", SESSION_TOKEN)));
    assert_eq!(
        canonical.signed_headers,
        "host;x-amz-date;x-amz-security-token"
    );
}

#[test]
fn test_aws_sigv4_no_session_token_omits_security_token_header() {
    let result = aws_sigv4(
        &aws_test_cred(),
        "GET",
        "https://iam.amazonaws.com/",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert!(!result.extra_headers.contains_key("x-amz-security-token"));
    assert!(!result.value.contains("x-amz-security-token"));
}

#[test]
fn test_aws_sigv4_error_does_not_leak_session_token() {
    let secret = serde_json::json!({
        "access_key_id": "",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "session_token": SESSION_TOKEN,
        "region": "us-east-1",
        "service": "iam"
    })
    .to_string();
    let result = aws_sigv4(
        &secret,
        "GET",
        "https://iam.amazonaws.com/",
        &HashMap::new(),
        "",
        None,
    );
    match result {
        Err(TransformError::ScriptError(msg)) => {
            assert!(
                !msg.contains(SESSION_TOKEN),
                "session token leaked: {}",
                msg
            );
            assert!(!msg.contains("wJalrXUtnFEMI"), "secret key leaked: {}", msg);
        }
        other => panic!("Expected ScriptError, got: {:?}", other),
    }
}

// =====================================================================
// Canonical URI and query-string encoding
// =====================================================================

#[test]
fn test_canonical_uri_double_encodes_path_for_non_s3() {
    // A space and a '+' in a path segment: encoded once to %20 / %2B, then the
    // '%' is itself encoded, giving %2520 / %252B.
    let url =
        url::Url::parse("https://lambda.us-east-1.amazonaws.com/functions/my fn+1/invoke").unwrap();
    assert_eq!(
        canonical_uri_path(&url, true),
        "/functions/my%2520fn%252B1/invoke"
    );
}

#[test]
fn test_canonical_uri_single_encodes_path_for_s3() {
    let url = url::Url::parse("https://s3.us-east-1.amazonaws.com/bucket/my key+1").unwrap();
    assert_eq!(canonical_uri_path(&url, false), "/bucket/my%20key%2B1");
}

#[test]
fn test_canonical_uri_reserved_characters_are_uppercase_hex() {
    // Unreserved characters stay; everything else is %XX with uppercase hex.
    let url = url::Url::parse("https://x.amazonaws.com/a-b_c.d~e/%c3%a9:@!$&'()*,;=").unwrap();
    assert_eq!(
        canonical_uri_path(&url, false),
        "/a-b_c.d~e/%C3%A9%3A%40%21%24%26%27%28%29%2A%2C%3B%3D"
    );
}

#[test]
fn test_canonical_uri_root_and_empty_path() {
    let root = url::Url::parse("https://iam.amazonaws.com/").unwrap();
    assert_eq!(canonical_uri_path(&root, true), "/");
    let none = url::Url::parse("https://iam.amazonaws.com").unwrap();
    assert_eq!(canonical_uri_path(&none, true), "/");
}

#[test]
fn test_aws_sigv4_path_encoding_differs_for_s3_and_lambda() {
    let cred = |service: &str| {
        serde_json::json!({
            "access_key_id": "AKIDEXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "service": service
        })
        .to_string()
    };

    let lambda = aws_sigv4(
        &cred("lambda"),
        "GET",
        "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my fn+1/invocations",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert!(
        lambda.value.ends_with(
            "Signature=f3ca1f804229df3506179ca2484de7c017318d8956c48a6741f2c386e56c209a"
        ),
        "lambda signature mismatch. Got: {}",
        lambda.value
    );

    let s3 = aws_sigv4(
        &cred("s3"),
        "GET",
        "https://s3.us-east-1.amazonaws.com/bucket/my key+1",
        &HashMap::new(),
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert!(
        s3.value.ends_with(
            "Signature=bdf5db1548721848acd5132529778556137682c88871fd02a75390eb05e3ed48"
        ),
        "s3 signature mismatch. Got: {}",
        s3.value
    );
}

#[test]
fn test_canonical_query_string_unsorted_keys_and_empty_value() {
    let url = url::Url::parse("https://example.com/?b=2&a=&c=3").unwrap();
    assert_eq!(canonical_query_string(&url), "a=&b=2&c=3");
}

#[test]
fn test_canonical_query_string_key_without_equals_gets_one() {
    let url = url::Url::parse("https://example.com/?Param1").unwrap();
    assert_eq!(canonical_query_string(&url), "Param1=");
}

#[test]
fn test_canonical_query_string_sorts_by_key_then_value() {
    let url = url::Url::parse("https://example.com/?a=2&a=1&B=x").unwrap();
    // Byte order: 'B' (0x42) sorts before 'a' (0x61).
    assert_eq!(canonical_query_string(&url), "B=x&a=1&a=2");
}

#[test]
fn test_canonical_query_string_encodes_once_with_uppercase_hex() {
    let url = url::Url::parse("https://example.com/?k%20ey=a b&x=%c3%a9+").unwrap();
    assert_eq!(canonical_query_string(&url), "k%20ey=a%20b&x=%C3%A9%2B");
}

// =====================================================================
// Canonical headers
// =====================================================================

#[test]
fn test_canonical_headers_trim_and_collapse_whitespace() {
    let mut caller = HashMap::new();
    caller.insert("My-Header1".to_string(), "   value1   ".to_string());
    caller.insert("My-Header2".to_string(), "  \"a   b   c\"  ".to_string());
    let headers = canonical_headers(&caller, &[("host", "example.amazonaws.com")]);
    assert_eq!(headers.get("my-header1").unwrap(), "value1");
    assert_eq!(headers.get("my-header2").unwrap(), "\"a b c\"");
}

#[test]
fn test_canonical_headers_computed_override_caller() {
    let mut caller = HashMap::new();
    caller.insert("Host".to_string(), "evil.example.com".to_string());
    caller.insert("X-Amz-Date".to_string(), "19700101T000000Z".to_string());
    let headers = canonical_headers(
        &caller,
        &[
            ("host", "iam.amazonaws.com"),
            ("x-amz-date", "20150830T123600Z"),
        ],
    );
    assert_eq!(headers.len(), 2);
    assert_eq!(headers.get("host").unwrap(), "iam.amazonaws.com");
    assert_eq!(headers.get("x-amz-date").unwrap(), "20150830T123600Z");
}

#[test]
fn test_aws_sigv4_unsignable_caller_headers_are_skipped() {
    let mut caller = HashMap::new();
    caller.insert("Authorization".to_string(), "Bearer stale".to_string());
    caller.insert("User-Agent".to_string(), "agentcordon/1".to_string());
    caller.insert("Content-Length".to_string(), "0".to_string());
    caller.insert("Expect".to_string(), "100-continue".to_string());
    caller.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    caller.insert("Connection".to_string(), "keep-alive".to_string());
    caller.insert("Accept".to_string(), "application/json".to_string());
    let result = aws_sigv4(
        &aws_test_cred(),
        "GET",
        "https://iam.amazonaws.com/",
        &caller,
        "",
        Some("20150830T123600Z"),
    )
    .expect("sigv4 should succeed");
    assert!(
        result
            .value
            .contains("SignedHeaders=accept;host;x-amz-date,"),
        "Got: {}",
        result.value
    );
}

// =====================================================================
// Conformance: AWS documentation worked example
// (docs.aws.amazon.com "Example: signature calculation", IAM ListUsers)
// =====================================================================

const DOCS_ACCESS_KEY: &str = "AKIDEXAMPLE";
const DOCS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const DOCS_DATE: &str = "20150830T123600Z";

fn docs_cred(service: &str) -> String {
    serde_json::json!({
        "access_key_id": DOCS_ACCESS_KEY,
        "secret_access_key": DOCS_SECRET_KEY,
        "region": "us-east-1",
        "service": service
    })
    .to_string()
}

#[test]
fn test_aws_sigv4_conformance_docs_iam_list_users_canonical_request() {
    let url =
        url::Url::parse("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08").unwrap();
    let mut caller = HashMap::new();
    caller.insert(
        "content-type".to_string(),
        "application/x-www-form-urlencoded; charset=utf-8".to_string(),
    );
    let headers = canonical_headers(
        &caller,
        &[("host", "iam.amazonaws.com"), ("x-amz-date", DOCS_DATE)],
    );
    let canonical = canonical_request("GET", &url, &headers, &sha256_hex(b""), true);

    assert_eq!(
        canonical.request,
        "GET\n\
         /\n\
         Action=ListUsers&Version=2010-05-08\n\
         content-type:application/x-www-form-urlencoded; charset=utf-8\n\
         host:iam.amazonaws.com\n\
         x-amz-date:20150830T123600Z\n\
         \n\
         content-type;host;x-amz-date\n\
         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(canonical.request.as_bytes()),
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
    );
    assert_eq!(canonical.signed_headers, "content-type;host;x-amz-date");
}

#[test]
fn test_aws_sigv4_conformance_docs_iam_list_users_string_to_sign_and_signature() {
    let mut caller = HashMap::new();
    caller.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded; charset=utf-8".to_string(),
    );
    let result = aws_sigv4(
        &docs_cred("iam"),
        "GET",
        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
        &caller,
        "",
        Some(DOCS_DATE),
    )
    .expect("sigv4 should succeed");

    assert_eq!(
        result.value,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
         SignedHeaders=content-type;host;x-amz-date, \
         Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );

    // The string to sign from the docs, checked through the same signing key.
    let string_to_sign = "AWS4-HMAC-SHA256\n\
                          20150830T123600Z\n\
                          20150830/us-east-1/iam/aws4_request\n\
                          f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
    let k_date = hmac_sha256_raw(format!("AWS4{}", DOCS_SECRET_KEY).as_bytes(), b"20150830");
    let k_region = hmac_sha256_raw(&k_date, b"us-east-1");
    let k_service = hmac_sha256_raw(&k_region, b"iam");
    let k_signing = hmac_sha256_raw(&k_service, b"aws4_request");
    assert_eq!(
        hex::encode(hmac_sha256_raw(&k_signing, string_to_sign.as_bytes())),
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

// =====================================================================
// Conformance: AWS SigV4 test suite (aws-sig-v4-test-suite)
// Credential AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
// 20150830T123600Z, us-east-1, service "service", host example.amazonaws.com.
// =====================================================================

fn suite_sign(method: &str, url: &str, caller: &HashMap<String, String>, body: &str) -> String {
    aws_sigv4(
        &docs_cred("service"),
        method,
        url,
        caller,
        body,
        Some(DOCS_DATE),
    )
    .expect("sigv4 should succeed")
    .value
}

fn suite_authorization(signed_headers: &str, signature: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
         SignedHeaders={}, Signature={}",
        signed_headers, signature
    )
}

#[test]
fn test_aws_sigv4_suite_get_vanilla() {
    assert_eq!(
        suite_sign("GET", "https://example.amazonaws.com/", &HashMap::new(), ""),
        suite_authorization(
            "host;x-amz-date",
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_get_vanilla_canonical_request_hash() {
    let url = url::Url::parse("https://example.amazonaws.com/").unwrap();
    let headers = canonical_headers(
        &HashMap::new(),
        &[("host", "example.amazonaws.com"), ("x-amz-date", DOCS_DATE)],
    );
    let canonical = canonical_request("GET", &url, &headers, &sha256_hex(b""), true);
    assert_eq!(
        sha256_hex(canonical.request.as_bytes()),
        "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    );
}

#[test]
fn test_aws_sigv4_suite_post_vanilla() {
    assert_eq!(
        suite_sign(
            "POST",
            "https://example.amazonaws.com/",
            &HashMap::new(),
            ""
        ),
        suite_authorization(
            "host;x-amz-date",
            "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_get_vanilla_query_order_key_case() {
    assert_eq!(
        suite_sign(
            "GET",
            "https://example.amazonaws.com/?Param2=value2&Param1=value1",
            &HashMap::new(),
            ""
        ),
        suite_authorization(
            "host;x-amz-date",
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_get_vanilla_empty_query_key() {
    assert_eq!(
        suite_sign(
            "GET",
            "https://example.amazonaws.com/?Param1=value1",
            &HashMap::new(),
            ""
        ),
        suite_authorization(
            "host;x-amz-date",
            "a67d582fa61cc504c4bae71f336f98b97f1ea3c7a6bfe1b6e45aec72011b9aeb"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_get_vanilla_query_unreserved() {
    let unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    assert_eq!(
        suite_sign(
            "GET",
            &format!(
                "https://example.amazonaws.com/?{}={}",
                unreserved, unreserved
            ),
            &HashMap::new(),
            ""
        ),
        suite_authorization(
            "host;x-amz-date",
            "9c3e54bfcdf0b19771a7f523ee5669cdf59bc7cc0884027167c21bb143a40197"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_post_vanilla_query() {
    assert_eq!(
        suite_sign(
            "POST",
            "https://example.amazonaws.com/?Param1=value1",
            &HashMap::new(),
            ""
        ),
        suite_authorization(
            "host;x-amz-date",
            "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_post_x_www_form_urlencoded() {
    let mut caller = HashMap::new();
    caller.insert(
        "Content-Type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );
    assert_eq!(
        suite_sign(
            "POST",
            "https://example.amazonaws.com/",
            &caller,
            "Param1=value1"
        ),
        suite_authorization(
            "content-type;host;x-amz-date",
            "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        )
    );
}

#[test]
fn test_aws_sigv4_suite_get_header_key_duplicate() {
    // The suite sends My-Header1 three times (value2, value2, value1); a
    // HashMap cannot carry duplicates, so the already-joined value is used.
    // The canonical header line is identical: my-header1:value2,value2,value1
    let mut caller = HashMap::new();
    caller.insert("My-Header1".to_string(), "value2,value2,value1".to_string());
    assert_eq!(
        suite_sign("GET", "https://example.amazonaws.com/", &caller, ""),
        suite_authorization(
            "host;my-header1;x-amz-date",
            "c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        )
    );
}
