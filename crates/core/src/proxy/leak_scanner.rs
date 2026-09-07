//! Redaction of injected secrets from upstream responses.
//!
//! An upstream that echoes its request (debug endpoints, error pages, some
//! proxies) would otherwise hand the injected credential straight back to
//! the caller, defeating the point of brokering it. The scanner knows every
//! value the broker injected and replaces each occurrence in the response,
//! including the base64 and percent-encoded forms an echo commonly takes.

use std::borrow::Cow;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;

/// What a matched secret is replaced with.
pub const REDACTED: &str = "[REDACTED]";

/// Needles shorter than this are not searched for: a very short value would
/// match ordinary response text far too often.
const MIN_SCAN_LENGTH: usize = 4;

/// The set of strings that would betray an injected value.
///
/// **Security invariant:** the scanner never logs or returns a needle; a
/// caller learns only whether something was redacted.
#[derive(Debug, Clone)]
pub struct LeakScanner {
    needles: Vec<String>,
}

impl LeakScanner {
    /// Build a scanner for these injected values. Every value is searched
    /// for raw and in its standard base64, URL-safe base64, and
    /// percent-encoded forms.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut needles: Vec<String> = values
            .into_iter()
            .flat_map(|v| encoded_forms(v.as_ref()))
            .filter(|n| n.len() >= MIN_SCAN_LENGTH)
            .collect();
        // Longest first, so a whole header value such as `Bearer <token>` is
        // replaced in one piece instead of the bare token being carved out
        // of it, and a padded base64 form wins over its unpadded prefix.
        needles.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        needles.dedup();
        Self { needles }
    }

    /// Replace every occurrence of every needle. Borrowed when the text was
    /// clean, owned when something was redacted.
    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut out = Cow::Borrowed(text);
        for needle in &self.needles {
            if out.contains(needle.as_str()) {
                out = Cow::Owned(out.replace(needle.as_str(), REDACTED));
            }
        }
        out
    }
}

/// Header names an injection computes whose value is **not** secret.
///
/// A SigV4 signer emits `host`, `x-amz-date` and, for the S3 family,
/// `x-amz-content-sha256` alongside the signature. All three are derived
/// from the request the caller already made — its URL, its clock, its body —
/// so blanking them protects nothing, and blanking the timestamp actively
/// misleads: the same date appears inside `credential_scope` in the
/// `Authorization` value, so a user debugging a signature saw one copy
/// redacted and one copy intact and concluded the clock was wrong.
///
/// Anything not named here is treated as secret, so a transform that invents
/// a header still fails safe.
const PUBLIC_INJECTED_HEADERS: [&str; 3] = ["host", "x-amz-date", "x-amz-content-sha256"];

/// Field names inside a structured credential value that are secret on their
/// own. An AWS credential is a JSON object, and an upstream error page that
/// quotes just the `secret_access_key` would otherwise slip past a scanner
/// that only knows the whole object.
const SECRET_CREDENTIAL_FIELDS: [&str; 10] = [
    "secret_access_key",
    "session_token",
    "aws_session_token",
    "client_secret",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
];

/// True when this header's injected value carries no secret material.
fn is_public_injected_header(name: &str) -> bool {
    PUBLIC_INJECTED_HEADERS
        .iter()
        .any(|public| name.eq_ignore_ascii_case(public))
}

/// The needle set for one credential injection: the credential value, the
/// secret fields inside it when it is a JSON object, every header value the
/// transform produced that is not publicly derived (`PUBLIC_INJECTED_HEADERS`),
/// and every query-parameter value it produced (a query parameter only ever
/// carries the key itself).
///
/// This is the one place that decides what counts as secret, so the proxy
/// route and the MCP route cannot drift apart.
pub fn injected_needles<'a>(
    credential_value: &str,
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    query_values: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut needles = vec![credential_value.to_string()];
    needles.extend(secret_fields(credential_value));
    for (name, value) in headers {
        if !is_public_injected_header(name) {
            needles.push(value.to_string());
        }
    }
    needles.extend(query_values.into_iter().map(str::to_string));
    needles
}

/// The secret-named string fields of a credential value that is a JSON
/// object. A value that is not such an object contributes nothing.
fn secret_fields(credential_value: &str) -> Vec<String> {
    let Ok(serde_json::Value::Object(fields)) =
        serde_json::from_str::<serde_json::Value>(credential_value)
    else {
        return Vec::new();
    };
    fields
        .into_iter()
        .filter(|(name, _)| {
            SECRET_CREDENTIAL_FIELDS
                .iter()
                .any(|secret| name.eq_ignore_ascii_case(secret))
        })
        .filter_map(|(_, value)| match value {
            serde_json::Value::String(s) => Some(s),
            _ => None,
        })
        .collect()
}

fn encoded_forms(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    vec![
        value.to_string(),
        STANDARD.encode(bytes),
        STANDARD_NO_PAD.encode(bytes),
        URL_SAFE.encode(bytes),
        URL_SAFE_NO_PAD.encode(bytes),
        percent_encode(value),
    ]
}

/// RFC 3986 percent-encoding of everything but the unreserved set, with
/// uppercase hex, which is what `urlencoding`, browsers, and most HTTP
/// clients produce.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_is_borrowed() {
        let scanner = LeakScanner::new(["ghp_abc123def456"]);
        let out = scanner.redact(r#"{"status": "ok"}"#);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn raw_and_encoded_forms_are_redacted() {
        let scanner = LeakScanner::new(["Bearer tok/en+1"]);
        let text = format!(
            "raw={} std={} url={} pct={}",
            "Bearer tok/en+1",
            STANDARD.encode("Bearer tok/en+1"),
            URL_SAFE_NO_PAD.encode("Bearer tok/en+1"),
            "Bearer%20tok%2Fen%2B1",
        );
        assert_eq!(
            scanner.redact(&text),
            "raw=[REDACTED] std=[REDACTED] url=[REDACTED] pct=[REDACTED]"
        );
    }

    #[test]
    fn longer_needle_wins_over_its_substring() {
        let scanner = LeakScanner::new(["Bearer secret-token", "secret-token"]);
        assert_eq!(
            scanner.redact("auth: Bearer secret-token; again: secret-token"),
            "auth: [REDACTED]; again: [REDACTED]"
        );
    }

    #[test]
    fn signing_headers_the_caller_already_knows_are_not_needles() {
        let needles = injected_needles(
            "opaque-credential-value",
            [
                ("Authorization", "AWS4-HMAC-SHA256 Signature=deadbeefcafe"),
                ("host", "api.example.com"),
                ("x-amz-date", "20260906T101112Z"),
                ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb924"),
            ],
            [],
        );
        assert!(needles.contains(&"AWS4-HMAC-SHA256 Signature=deadbeefcafe".to_string()));
        assert!(!needles.iter().any(|n| n == "api.example.com"));
        assert!(!needles.iter().any(|n| n == "20260906T101112Z"));
        assert!(!needles
            .iter()
            .any(|n| n == "e3b0c44298fc1c149afbf4c8996fb924"));
    }

    #[test]
    fn secret_fields_inside_a_json_credential_are_needles_on_their_own() {
        let credential = r#"{"access_key_id":"AKIAEXAMPLE","secret_access_key":"wJalrXUtnFEMI","region":"us-east-1"}"#;
        let scanner = LeakScanner::new(injected_needles(credential, [], []));
        let out = scanner.redact("no signer for key wJalrXUtnFEMI in us-east-1");
        assert_eq!(out, "no signer for key [REDACTED] in us-east-1");
    }

    #[test]
    fn a_session_token_header_is_still_a_needle() {
        let needles = injected_needles(
            "{}",
            [("x-amz-security-token", "FwoGZXIvYXdzEExampleToken")],
            [],
        );
        assert!(needles.contains(&"FwoGZXIvYXdzEExampleToken".to_string()));
    }

    #[test]
    fn short_values_are_not_searched_for() {
        let scanner = LeakScanner::new(["abc"]);
        assert_eq!(
            scanner.redact("abc is everywhere abc"),
            "abc is everywhere abc"
        );
    }
}
