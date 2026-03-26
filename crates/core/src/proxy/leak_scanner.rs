/// Minimum credential value length to scan for.
///
/// Values shorter than this are skipped to avoid false positives
/// (e.g., a 2-character credential value would match far too many substrings).
const MIN_SCAN_LENGTH: usize = 4;

/// Scan a response body for leaked credential values.
///
/// Each entry in `credentials` is a `(name, value)` pair. The function checks
/// whether any credential value appears as a substring in `response_body`.
///
/// Returns `Some(credential_name)` for the first leaked credential found, or
/// `None` if the response is clean.
///
/// **Security invariant:** This function never logs, stores, or returns the
/// credential value itself -- only the name.
///
/// Values shorter than `MIN_SCAN_LENGTH` (4 characters) are skipped to
/// avoid false positives.
pub fn scan_for_leaked_credentials(
    response_body: &str,
    credentials: &[(String, String)],
) -> Option<String> {
    if response_body.is_empty() {
        return None;
    }

    for (name, value) in credentials {
        if value.len() < MIN_SCAN_LENGTH {
            continue;
        }
        if response_body.contains(value.as_str()) {
            return Some(name.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_response_returns_none() {
        let creds = vec![("github-pat".to_string(), "ghp_abc123def456".to_string())];
        let body = r#"{"status": "ok", "data": "hello world"}"#;
        assert!(scan_for_leaked_credentials(body, &creds).is_none());
    }

    #[test]
    fn leaked_credential_returns_name() {
        let creds = vec![("github-pat".to_string(), "ghp_abc123def456".to_string())];
        let body = r#"{"token": "ghp_abc123def456", "ok": true}"#;
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("github-pat".to_string())
        );
    }

    #[test]
    fn checks_all_credentials() {
        let creds = vec![
            ("safe-one".to_string(), "safe_value_xxxx".to_string()),
            ("leaked-one".to_string(), "leaked_value_yyyy".to_string()),
        ];
        let body = "the response contains leaked_value_yyyy somewhere";
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("leaked-one".to_string())
        );
    }

    #[test]
    fn short_values_are_skipped() {
        // A 3-character value should not trigger a match (MIN_SCAN_LENGTH = 4).
        let creds = vec![("tiny-cred".to_string(), "abc".to_string())];
        let body = "abc is everywhere abc abc";
        assert!(scan_for_leaked_credentials(body, &creds).is_none());
    }

    #[test]
    fn four_char_value_is_scanned() {
        let creds = vec![("short-cred".to_string(), "abcd".to_string())];
        let body = "found abcd in response";
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("short-cred".to_string())
        );
    }

    #[test]
    fn empty_response_body_returns_none() {
        let creds = vec![("cred".to_string(), "secret_value".to_string())];
        assert!(scan_for_leaked_credentials("", &creds).is_none());
    }

    #[test]
    fn empty_credentials_list_returns_none() {
        let body = "any body content here";
        assert!(scan_for_leaked_credentials(body, &[]).is_none());
    }

    #[test]
    fn partial_match_does_not_trigger() {
        // "ghp_abc" is a prefix of the credential value but not the full value.
        let creds = vec![("github-pat".to_string(), "ghp_abc123def456".to_string())];
        let body = "partial: ghp_abc";
        assert!(scan_for_leaked_credentials(body, &creds).is_none());
    }

    #[test]
    fn multiple_credentials_first_leaked_is_returned() {
        let creds = vec![
            ("cred-a".to_string(), "value_aaaa".to_string()),
            ("cred-b".to_string(), "value_bbbb".to_string()),
        ];
        // Both values appear, but the first one found is returned.
        let body = "has value_aaaa and value_bbbb";
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("cred-a".to_string())
        );
    }

    #[test]
    fn credential_value_as_substring_is_detected() {
        let creds = vec![("api-key".to_string(), "sk_live_12345".to_string())];
        let body = "prefix_sk_live_12345_suffix";
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("api-key".to_string())
        );
    }

    #[test]
    fn values_that_are_substrings_of_each_other() {
        // "abcdef" contains "abcd" as a substring. Both should be checked independently.
        let creds = vec![
            ("short".to_string(), "abcd".to_string()),
            ("long".to_string(), "abcdef".to_string()),
        ];

        // Body contains only the short value.
        let body = "found abcd here";
        assert_eq!(
            scan_for_leaked_credentials(body, &creds),
            Some("short".to_string())
        );

        // Body contains the long value (which also contains the short one).
        let body2 = "found abcdef here";
        // Short matches first since it's checked first.
        assert_eq!(
            scan_for_leaked_credentials(body2, &creds),
            Some("short".to_string())
        );
    }
}
