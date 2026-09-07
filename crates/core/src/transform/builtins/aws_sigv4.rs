use std::collections::{BTreeMap, HashMap};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::super::TransformOutput;
use crate::error::TransformError;

// ---------------------------------------------------------------------------
// HMAC-SHA256 helper (raw bytes, not hex)
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 that returns raw bytes (for SigV4 key derivation chain).
pub(super) fn hmac_sha256_raw(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SHA-256 returning hex-encoded hash.
pub(super) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// AWS SigV4 built-in transform
// ---------------------------------------------------------------------------

/// AWS credential JSON structure.
#[derive(serde::Deserialize)]
struct AwsCredential {
    access_key_id: String,
    secret_access_key: String,
    /// Temporary-credential session token. Sent and signed as
    /// `x-amz-security-token`. Either JSON key is accepted.
    #[serde(default, alias = "aws_session_token")]
    session_token: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    service: Option<String>,
}

/// Caller headers that are never signed: they are hop-by-hop, or the HTTP
/// client rewrites them before the request leaves the broker, so a signature
/// over them would not match what the service receives.
const UNSIGNABLE_HEADERS: &[&str] = &[
    "authorization",
    "connection",
    "content-length",
    "expect",
    "transfer-encoding",
    "user-agent",
    "x-amzn-trace-id",
];

/// Services that follow the S3 signing conventions: the canonical URI is
/// encoded once, and the payload hash is also sent as `x-amz-content-sha256`.
/// Every other service double-encodes the path and needs no payload header.
fn uses_s3_conventions(service: &str) -> bool {
    matches!(
        service,
        "s3" | "s3express" | "s3-object-lambda" | "s3-outposts"
    )
}

/// Infer AWS region and service from a target URL hostname.
///
/// Supported patterns:
/// - `{service}.{region}.amazonaws.com` → (service, region)
/// - `{service}.amazonaws.com` → (service, us-east-1) for global services, or (service, us-east-1) as default
pub fn infer_aws_region_service(url: &str) -> Result<(String, String), TransformError> {
    let parsed = url::Url::parse(url).map_err(|e| {
        TransformError::ScriptError(format!("aws-sigv4: invalid URL for inference: {}", e))
    })?;

    let host = parsed.host_str().ok_or_else(|| {
        TransformError::ScriptError(
            "aws-sigv4: URL has no host for region/service inference".to_string(),
        )
    })?;

    // Must end with .amazonaws.com
    if !host.ends_with(".amazonaws.com") {
        return Err(TransformError::ScriptError(format!(
            "aws-sigv4: cannot infer region/service from host '{}': expected *.amazonaws.com",
            host
        )));
    }

    // Strip the .amazonaws.com suffix
    let prefix = &host[..host.len() - ".amazonaws.com".len()];

    // Split prefix into parts: could be "{service}" or "{service}.{region}"
    let parts: Vec<&str> = prefix.splitn(2, '.').collect();
    match parts.len() {
        1 => {
            // {service}.amazonaws.com — global or default us-east-1
            let service = parts[0].to_string();
            Ok((service, "us-east-1".to_string()))
        }
        2 => {
            let first = parts[0];
            let second = parts[1];
            // {service}.{region}.amazonaws.com
            Ok((first.to_string(), second.to_string()))
        }
        _ => Err(TransformError::ScriptError(format!(
            "aws-sigv4: cannot parse AWS hostname: {}",
            host
        ))),
    }
}

/// AWS SigV4 signing transform.
///
/// `secret` is a JSON string with fields: access_key_id, secret_access_key,
/// optional session_token (alias aws_session_token), region, service.
/// `timestamp_override` allows injecting a fixed timestamp for deterministic testing.
///
/// Signed headers are `host`, `x-amz-date`, `x-amz-security-token` (when the
/// credential has a session token), `x-amz-content-sha256` (S3-family services
/// only), and every caller header except the unsignable set (`UNSIGNABLE_HEADERS`).
///
/// Returns a `TransformOutput` with:
/// - `value`: The Authorization header value
/// - `extra_headers`: host, x-amz-date, and the x-amz-security-token /
///   x-amz-content-sha256 headers when they were signed
pub fn aws_sigv4(
    secret: &str,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
    timestamp_override: Option<&str>,
) -> Result<TransformOutput, TransformError> {
    // Parse the credential JSON — SECURITY: error messages must NOT contain secret material
    // SECURITY: discard serde error details to prevent any possibility of secret
    // material appearing in error messages or logs (defense-in-depth).
    let cred: AwsCredential = serde_json::from_str(secret).map_err(|_| {
        TransformError::ScriptError(
            "aws-sigv4: invalid credential JSON: expected object with fields: access_key_id, secret_access_key (session_token, region and service are optional)".to_string()
        )
    })?;

    // Validate required fields are non-empty
    if cred.access_key_id.is_empty() {
        return Err(TransformError::ScriptError(
            "aws-sigv4: access_key_id is empty".to_string(),
        ));
    }
    if cred.secret_access_key.is_empty() {
        return Err(TransformError::ScriptError(
            "aws-sigv4: secret_access_key is empty".to_string(),
        ));
    }
    let session_token = cred.session_token.as_deref().filter(|t| !t.is_empty());

    // Resolve region and service: credential JSON takes precedence, then infer from URL
    let (service, region): (String, String) = match (&cred.region, &cred.service) {
        (Some(r), Some(s)) if !r.is_empty() && !s.is_empty() => (s.clone(), r.clone()),
        _ => {
            // Try to infer from URL
            let (inf_svc, inf_reg) = infer_aws_region_service(url)?;
            let region = match &cred.region {
                Some(r) if !r.is_empty() => r.clone(),
                _ => inf_reg,
            };
            let service = match &cred.service {
                Some(s) if !s.is_empty() => s.clone(),
                _ => inf_svc,
            };
            (service, region)
        }
    };
    let s3_conventions = uses_s3_conventions(&service);

    // Parse URL
    let parsed_url = url::Url::parse(url)
        .map_err(|e| TransformError::ScriptError(format!("aws-sigv4: invalid URL: {}", e)))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| TransformError::ScriptError("aws-sigv4: URL has no host".to_string()))?
        .to_string();

    let host_with_port = if let Some(port) = parsed_url.port() {
        format!("{}:{}", host, port)
    } else {
        host.clone()
    };

    // Timestamp
    let amz_date = match timestamp_override {
        Some(ts) => ts.to_string(),
        None => chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
    };
    let date_stamp = &amz_date[..8]; // YYYYMMDD

    // Payload hash
    let payload_hash = sha256_hex(body.as_bytes());

    // Headers this signer computes; they replace any caller header of the same name.
    let mut computed: Vec<(&str, &str)> =
        vec![("host", &host_with_port), ("x-amz-date", &amz_date)];
    if s3_conventions {
        computed.push(("x-amz-content-sha256", &payload_hash));
    }
    if let Some(token) = session_token {
        computed.push(("x-amz-security-token", token));
    }

    // --- Step 1: Canonical Request ---
    let headers_to_sign = canonical_headers(headers, &computed);
    let canonical = canonical_request(
        method,
        &parsed_url,
        &headers_to_sign,
        &payload_hash,
        !s3_conventions,
    );

    // --- Step 2: String to Sign ---
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        sha256_hex(canonical.request.as_bytes())
    );

    // --- Step 3: Signing Key (raw bytes chain) ---
    let k_date = hmac_sha256_raw(
        format!("AWS4{}", cred.secret_access_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256_raw(&k_date, region.as_bytes());
    let k_service = hmac_sha256_raw(&k_region, service.as_bytes());
    let k_signing = hmac_sha256_raw(&k_service, b"aws4_request");

    // --- Step 4: Signature ---
    let signature = hex::encode(hmac_sha256_raw(&k_signing, string_to_sign.as_bytes()));

    // --- Step 5: Authorization Header ---
    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        cred.access_key_id, credential_scope, canonical.signed_headers, signature
    );

    let extra_headers: HashMap<String, String> = computed
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();

    Ok(TransformOutput {
        value: auth_header,
        extra_headers,
    })
}

/// The canonical request and the `SignedHeaders` list derived from it.
pub(super) struct CanonicalRequest {
    pub request: String,
    pub signed_headers: String,
}

/// Build the SigV4 canonical request.
///
/// `headers` must already be canonical (see [`canonical_headers`]).
/// `double_encode` selects the non-S3 path encoding.
pub(super) fn canonical_request(
    method: &str,
    url: &url::Url,
    headers: &BTreeMap<String, String>,
    payload_hash: &str,
    double_encode: bool,
) -> CanonicalRequest {
    let canonical_header_lines: String = headers
        .iter()
        .map(|(name, value)| format!("{}:{}\n", name, value))
        .collect();
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");

    let request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        canonical_uri_path(url, double_encode),
        canonical_query_string(url),
        canonical_header_lines,
        signed_headers,
        payload_hash
    );

    CanonicalRequest {
        request,
        signed_headers,
    }
}

/// Canonicalize headers for signing: names lowercased, values trimmed with
/// internal whitespace runs collapsed to one space, sorted by name.
///
/// `computed` headers always win over a caller header of the same name;
/// caller headers in `UNSIGNABLE_HEADERS` are left out. When the caller map
/// carries the same name in different casings, the values are joined with
/// commas in name order.
pub(super) fn canonical_headers(
    caller: &HashMap<String, String>,
    computed: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let mut merged: BTreeMap<String, Vec<(&String, &String)>> = BTreeMap::new();
    for (name, value) in caller {
        let lower = name.to_ascii_lowercase();
        if UNSIGNABLE_HEADERS.contains(&lower.as_str()) || computed.iter().any(|(c, _)| *c == lower)
        {
            continue;
        }
        merged.entry(lower).or_default().push((name, value));
    }

    let mut out: BTreeMap<String, String> = merged
        .into_iter()
        .map(|(name, mut values)| {
            values.sort_by(|a, b| a.0.cmp(b.0));
            let joined = values
                .into_iter()
                .map(|(_, v)| canonical_header_value(v))
                .collect::<Vec<_>>()
                .join(",");
            (name, joined)
        })
        .collect();

    for (name, value) in computed {
        out.insert(name.to_string(), canonical_header_value(value));
    }
    out
}

/// Trim a header value and collapse runs of whitespace to a single space.
fn canonical_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Canonicalize the URI path per AWS SigV4 spec.
///
/// Each path segment is URI-encoded (except '/'). With `double_encode` the
/// encoded segment is encoded a second time, which is the rule for every
/// service other than S3.
pub(super) fn canonical_uri_path(url: &url::Url, double_encode: bool) -> String {
    let path = url.path();
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }

    let segments: Vec<String> = path
        .split('/')
        .map(|segment| {
            // Decode first (in case the URL already has some encoding), then re-encode
            let decoded = percent_decode(segment);
            let once = uri_encode(&decoded, false);
            if double_encode {
                uri_encode(&once, false)
            } else {
                once
            }
        })
        .collect();

    segments.join("/")
}

/// Canonicalize query string: sort params by key, then by value.
pub(super) fn canonical_query_string(url: &url::Url) -> String {
    let query = match url.query() {
        Some(q) if !q.is_empty() => q,
        _ => return String::new(),
    };

    let mut params: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        // Decode then re-encode per AWS spec
        let decoded_key = percent_decode(key);
        let decoded_value = percent_decode(value);
        params.push((
            uri_encode(&decoded_key, true),
            uri_encode(&decoded_value, true),
        ));
    }
    params.sort();

    params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Simple percent-decode implementation (avoids extra dependency).
fn percent_decode(input: &str) -> String {
    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

/// URI-encode a string per AWS SigV4 spec (RFC 3986).
/// Unreserved characters (A-Z, a-z, 0-9, '-', '_', '.', '~') are not encoded.
pub(super) fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b'/' if !encode_slash => {
                encoded.push('/');
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}
