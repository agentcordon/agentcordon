/// Parse a specific cookie value from a Cookie header string.
///
/// Splits the header by `;`, trims whitespace, and finds the cookie with the
/// given name. Returns `None` if the cookie is not present.
pub fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_single() {
        let header = "agtcrdn_session=abc123";
        assert_eq!(parse_cookie(header, "agtcrdn_session"), Some("abc123"));
    }

    #[test]
    fn parse_cookie_multiple() {
        let header = "other=foo; agtcrdn_session=token_value; another=bar";
        assert_eq!(parse_cookie(header, "agtcrdn_session"), Some("token_value"));
    }

    #[test]
    fn parse_cookie_missing() {
        let header = "other=foo; different=bar";
        assert_eq!(parse_cookie(header, "agtcrdn_session"), None);
    }

    #[test]
    fn parse_cookie_prefix_mismatch() {
        // "agtcrdn_session_extra" should NOT match "agtcrdn_session"
        let header = "agtcrdn_session_extra=nope";
        assert_eq!(parse_cookie(header, "agtcrdn_session"), None);
    }

    #[test]
    fn parse_csrf_cookie() {
        let header = "agtcrdn_session=abc; agtcrdn_csrf=mytoken123";
        assert_eq!(parse_cookie(header, "agtcrdn_csrf"), Some("mytoken123"));
    }

    #[test]
    fn parse_csrf_cookie_missing() {
        let header = "agtcrdn_session=abc";
        assert_eq!(parse_cookie(header, "agtcrdn_csrf"), None);
    }

    #[test]
    fn parse_session_cookie() {
        let header = "agtcrdn_csrf=tok; agtcrdn_session=sess123";
        assert_eq!(parse_cookie(header, "agtcrdn_session"), Some("sess123"));
    }

    #[test]
    fn parse_cookie_prefix_mismatch_csrf() {
        let header = "agtcrdn_csrf_extra=nope";
        assert_eq!(parse_cookie(header, "agtcrdn_csrf"), None);
    }
}
