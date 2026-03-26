use regex::Regex;

/// Check whether a URL matches a glob-style pattern.
///
/// Behavior:
/// - If `pattern` is empty, returns `true` (any URL allowed -- backward compat).
/// - `*` matches any sequence of characters (greedy, including `/`).
/// - No wildcard means exact match.
/// - Scheme is significant: `https://` does not match `http://`.
///
/// The function converts the glob pattern to a regex internally:
/// all regex metacharacters are escaped, then `*` is replaced with `.*`.
/// The resulting regex is anchored at both ends.
pub fn url_matches_pattern(url: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }

    let escaped = regex::escape(pattern);
    // regex::escape will turn `*` into `\*`; undo that to get `.*`.
    let regex_str = format!("^{}$", escaped.replace(r"\*", ".*"));

    match Regex::new(&regex_str) {
        Ok(re) => re.is_match(url),
        // If the pattern somehow produces invalid regex, deny by default.
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pattern_matches_any_url() {
        assert!(url_matches_pattern("https://example.com/foo", ""));
        assert!(url_matches_pattern("http://localhost:8080/bar", ""));
    }

    #[test]
    fn exact_match() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo",
            "https://api.github.com/repos/foo"
        ));
    }

    #[test]
    fn exact_mismatch() {
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/bar",
            "https://api.github.com/repos/foo"
        ));
    }

    #[test]
    fn wildcard_at_end() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo",
            "https://api.github.com/*"
        ));
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo/bar/baz",
            "https://api.github.com/*"
        ));
    }

    #[test]
    fn wildcard_in_middle() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/myrepo/pulls",
            "https://api.github.com/repos/*/pulls"
        ));
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/myrepo/issues",
            "https://api.github.com/repos/*/pulls"
        ));
    }

    #[test]
    fn scheme_mismatch() {
        assert!(!url_matches_pattern(
            "http://api.github.com/repos/foo",
            "https://api.github.com/*"
        ));
    }

    #[test]
    fn special_regex_characters_in_url_are_handled() {
        // The `.` in `api.github.com` should not match arbitrary characters.
        assert!(!url_matches_pattern(
            "https://apiXgithubYcom/repos/foo",
            "https://api.github.com/*"
        ));

        // Query strings with `?` should be matched literally.
        assert!(url_matches_pattern(
            "https://api.example.com/search?q=test",
            "https://api.example.com/search?q=test"
        ));
    }

    #[test]
    fn wildcard_matches_query_strings() {
        assert!(url_matches_pattern(
            "https://api.example.com/search?q=hello&limit=10",
            "https://api.example.com/*"
        ));
    }

    #[test]
    fn multiple_wildcards() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/owner/repo/pulls/42",
            "https://api.github.com/repos/*/repo/pulls/*"
        ));
    }

    #[test]
    fn trailing_slash_matters() {
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/foo/",
            "https://api.github.com/repos/foo"
        ));
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo/",
            "https://api.github.com/repos/foo/"
        ));
    }

    #[test]
    fn pattern_with_port() {
        assert!(url_matches_pattern(
            "http://localhost:3000/api/v1/data",
            "http://localhost:3000/*"
        ));
        assert!(!url_matches_pattern(
            "http://localhost:8080/api/v1/data",
            "http://localhost:3000/*"
        ));
    }

    #[test]
    fn fragment_in_url() {
        assert!(url_matches_pattern(
            "https://example.com/page#section",
            "https://example.com/*"
        ));
    }

    #[test]
    fn pattern_must_match_entire_url() {
        // Pattern without wildcard should not match a longer URL.
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/foo/bar",
            "https://api.github.com/repos/foo"
        ));
    }
}
