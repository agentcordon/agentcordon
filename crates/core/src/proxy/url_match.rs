//! Structural matching of a target URL against a credential's allowed
//! URL pattern.
//!
//! The pattern is parsed like a URL. Scheme, host, and port are compared
//! as values, so `https://api.github.com/*` cannot be satisfied by a
//! different scheme or port, or by a host that merely contains the text.
//! A `*` in the host stands for exactly one DNS label, and a leading `**`
//! stands for one or more labels. A `*` in the path (and query) stands for
//! any run of characters. A textual glob over the whole URL let
//! `https://*.github.com/*` match any URL whose query string happened to
//! contain `.github.com/`.

use url::Url;

/// Check whether `url` is allowed by `pattern`.
///
/// - An empty pattern allows any URL (no restriction was configured).
/// - Scheme must match exactly. Port must match the effective port.
/// - Host labels are compared one to one; a pattern label `*` matches any
///   single label. `*.example.com` matches `api.example.com` and not
///   `example.com` or `a.b.example.com`. A leading `**` matches one or more
///   labels: `**.example.com` matches `api.example.com` and
///   `a.b.example.com`, and still not the apex `example.com`.
/// - Path plus query is matched by a glob where `*` matches any sequence,
///   anchored at both ends. No wildcard means an exact match. A pattern
///   with no path matches only the root path.
/// - Anything that does not parse as a URL is refused.
pub fn url_matches_pattern(url: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let (Ok(target), Ok(pat)) = (Url::parse(url), Url::parse(pattern)) else {
        return false;
    };
    if target.scheme() != pat.scheme() {
        return false;
    }
    if target.port_or_known_default() != pat.port_or_known_default() {
        return false;
    }
    let (Some(target_host), Some(pat_host)) = (target.host_str(), pat.host_str()) else {
        return false;
    };
    if !host_matches(target_host, pat_host) {
        return false;
    }
    glob_matches(&path_and_query(&target), &path_and_query(&pat))
}

/// The grammar [`validate_url_pattern`] enforces, in one line, for help text
/// and for the message a refusal carries.
pub const URL_PATTERN_GRAMMAR: &str =
    "scheme://host[:port]/path — http or https, a `*` in the host stands for exactly one DNS \
     label (https://*.example.com/*), a leading `**` stands for one or more labels \
     (https://**.amazonaws.com/*), and a `*` in the path or query stands for any run of \
     characters (https://api.example.com/repos/*/pulls)";

/// Check that `pattern` is a pattern [`url_matches_pattern`] could ever
/// satisfy, and say what is wrong when it is not.
///
/// The matcher answers `false` for anything it cannot parse, so an
/// unparseable pattern is not a lax restriction — it is a credential that
/// can never be vended. That failure used to surface only at vend time, on
/// the far side of the console, which is why this is checked where the
/// pattern is written.
///
/// An empty pattern is "no restriction configured" and is accepted; the
/// caller decides whether to store it as `NULL`.
pub fn validate_url_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Ok(());
    }
    if pattern.trim() != pattern {
        return Err("must not begin or end with whitespace".to_string());
    }
    let parsed = Url::parse(pattern)
        .map_err(|e| format!("is not a URL ({e}); expected {URL_PATTERN_GRAMMAR}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "has scheme '{other}'; only http and https can be proxied"
            ))
        }
    }

    let Some(host) = parsed.host_str() else {
        return Err(format!("names no host; expected {URL_PATTERN_GRAMMAR}"));
    };
    if host.is_empty() {
        return Err(format!("names no host; expected {URL_PATTERN_GRAMMAR}"));
    }
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if *label == ANY_DEPTH && i != 0 {
            return Err(
                "has `**` after the first host label; `**` may only be the leftmost label, \
                 where it stands for one or more DNS labels"
                    .to_string(),
            );
        }
        if label.contains('*') && *label != "*" && *label != ANY_DEPTH {
            return Err(format!(
                "has a partial wildcard in the host label '{label}'; a `*` in the host stands for \
                 exactly one whole DNS label"
            ));
        }
    }
    // `https://*/` parses, but a host made only of wildcards restricts
    // nothing a reader would recognise as a restriction.
    if labels.iter().all(|l| *l == "*" || *l == ANY_DEPTH) {
        return Err(format!(
            "names no literal host label; expected {URL_PATTERN_GRAMMAR}"
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("must not carry a username or password".to_string());
    }
    if parsed.fragment().is_some() {
        return Err("must not carry a fragment; only the path and query are matched".to_string());
    }
    Ok(())
}

fn path_and_query(u: &Url) -> String {
    match u.query() {
        Some(q) => format!("{}?{}", u.path(), q),
        None => u.path().to_string(),
    }
}

/// The host label that stands for one or more DNS labels. Only meaningful as
/// the leftmost label; [`validate_url_pattern`] refuses it anywhere else.
const ANY_DEPTH: &str = "**";

fn host_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let h: Vec<&str> = host.split('.').collect();
    let p: Vec<&str> = pattern.split('.').collect();
    let (h, p) = match p.split_first() {
        // `**.example.com`: the host needs at least one label of its own in
        // front of the literal tail, so the apex never matches.
        Some((&ANY_DEPTH, tail)) if h.len() > tail.len() => (&h[h.len() - tail.len()..], tail),
        Some((&ANY_DEPTH, _)) => return false,
        _ => (&h[..], &p[..]),
    };
    h.len() == p.len() && h.iter().zip(p).all(|(hl, pl)| *pl == "*" || hl == pl)
}

/// Whether `pattern` names one literal host: a host with no wildcard label,
/// so every URL the pattern can ever match goes to that one host and port.
///
/// An admin who writes such a pattern has said where the credential goes,
/// and the broker's SSRF guard defers to it (ADR-0014): a pinned host is
/// forwarded to even when it resolves to a private or reserved address,
/// which is what a service on a tailnet or a LAN is. A wildcard pattern
/// pins nothing, and so does an empty one.
pub fn pattern_pins_host(pattern: &str) -> bool {
    let Ok(parsed) = Url::parse(pattern) else {
        return false;
    };
    match parsed.host_str() {
        Some(host) if !host.is_empty() => !host.contains('*'),
        _ => false,
    }
}

/// Anchored glob where `*` matches any (possibly empty) run of characters.
fn glob_matches(text: &str, pattern: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut ti, mut pi) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_p = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
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
    fn exact_match_and_mismatch() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo",
            "https://api.github.com/repos/foo"
        ));
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/bar",
            "https://api.github.com/repos/foo"
        ));
    }

    #[test]
    fn path_wildcards() {
        assert!(url_matches_pattern(
            "https://api.github.com/repos/foo/bar/baz",
            "https://api.github.com/*"
        ));
        assert!(url_matches_pattern(
            "https://api.github.com/repos/myrepo/pulls",
            "https://api.github.com/repos/*/pulls"
        ));
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/myrepo/issues",
            "https://api.github.com/repos/*/pulls"
        ));
        assert!(url_matches_pattern(
            "https://api.github.com/repos/owner/repo/pulls/42",
            "https://api.github.com/repos/*/repo/pulls/*"
        ));
        assert!(!url_matches_pattern(
            "https://api.github.com/repos/foo/bar",
            "https://api.github.com/repos/foo"
        ));
    }

    #[test]
    fn scheme_and_port_are_compared_as_values() {
        assert!(!url_matches_pattern(
            "http://api.github.com/repos/foo",
            "https://api.github.com/*"
        ));
        assert!(url_matches_pattern(
            "http://localhost:3000/api/v1/data",
            "http://localhost:3000/*"
        ));
        assert!(!url_matches_pattern(
            "http://localhost:8080/api/v1/data",
            "http://localhost:3000/*"
        ));
        assert!(
            url_matches_pattern("https://example.com:443/x", "https://example.com/*"),
            "explicit default port is the same port"
        );
        assert!(!url_matches_pattern(
            "https://api.github.com:8443/repos",
            "https://*.github.com/*"
        ));
    }

    #[test]
    fn host_wildcard_is_one_label() {
        let p = "https://*.github.com/*";
        assert!(url_matches_pattern("https://api.github.com/repos", p));
        assert!(url_matches_pattern("https://API.GitHub.com/repos", p));
        assert!(!url_matches_pattern("https://github.com/repos", p));
        assert!(!url_matches_pattern("https://a.b.github.com/repos", p));
        assert!(!url_matches_pattern(
            "https://api.github.com.attacker.example/repos",
            p
        ));
    }

    /// `**` is one or more labels: any depth under the literal tail, and
    /// never the tail on its own. A regional AWS endpoint is the case that
    /// made the form necessary: `service.region.amazonaws.com` is two
    /// labels in front of the tail, which one `*` can never cover.
    #[test]
    fn leading_double_star_is_one_or_more_labels() {
        let p = "https://**.amazonaws.com/*";
        assert!(url_matches_pattern("https://sts.amazonaws.com/", p));
        assert!(url_matches_pattern(
            "https://ssm.us-east-1.amazonaws.com/",
            p
        ));
        assert!(url_matches_pattern(
            "https://bucket.s3.eu-west-2.amazonaws.com/key",
            p
        ));
        assert!(url_matches_pattern(
            "https://SSM.US-EAST-1.AmazonAWS.com/",
            p
        ));
        assert!(
            !url_matches_pattern("https://amazonaws.com/", p),
            "the apex"
        );
        assert!(!url_matches_pattern(
            "https://ssm.amazonaws.com.attacker.example/",
            p
        ));
        assert!(!url_matches_pattern(
            "https://amazonaws.com.attacker.example/",
            p
        ));
        assert!(!url_matches_pattern(
            "http://ssm.us-east-1.amazonaws.com/",
            p
        ));

        // `**` composes with `*` in the tail, and with a literal tail of any length.
        assert!(url_matches_pattern(
            "https://a.b.c.example.com/",
            "https://**.*.example.com/*"
        ));
        assert!(!url_matches_pattern(
            "https://a.example.com/",
            "https://**.*.example.com/*"
        ));
    }

    /// `**` anywhere but the leftmost label is refused when written, and the
    /// matcher, which compares such a label as literal text, never matches
    /// a real host with it.
    #[test]
    fn double_star_is_leftmost_only() {
        assert!(validate_url_pattern("https://**.amazonaws.com/*").is_ok());
        assert!(validate_url_pattern("https://**.*.example.com/*").is_ok());
        for pattern in [
            "https://api.**.example.com/*",
            "https://api.**/*",
            "https://**/*",
            "https://**.*/*",
            "https://a**.example.com/*",
        ] {
            assert!(
                validate_url_pattern(pattern).is_err(),
                "{pattern:?} should be refused"
            );
        }
        assert!(!url_matches_pattern(
            "https://api.x.example.com/",
            "https://api.**.example.com/*"
        ));
    }

    // -- pattern_pins_host ------------------------------------------------

    /// A pattern pins a host when nothing in its host is a wildcard. The
    /// path may still carry wildcards; the pin is about *where* the
    /// credential goes, not which paths it may touch.
    #[test]
    fn a_literal_host_pins_and_a_wildcard_host_does_not() {
        for pattern in [
            "https://homeassistant.example.ts.net/*",
            "http://localhost:8123/api/*",
            "http://192.168.1.10:8080/*",
            "http://[fd00::1]/*",
            "https://api.example.com/repos/*/pulls",
        ] {
            assert!(pattern_pins_host(pattern), "{pattern:?} pins its host");
        }
        for pattern in [
            "",
            "https://*.amazonaws.com/*",
            "https://**.amazonaws.com/*",
            "https://api.*.example.com/*",
            "not a url",
        ] {
            assert!(!pattern_pins_host(pattern), "{pattern:?} pins nothing");
        }
    }

    #[test]
    fn host_text_inside_the_query_does_not_match() {
        assert!(!url_matches_pattern(
            "https://attacker.example/?u=.github.com/",
            "https://*.github.com/*"
        ));
        assert!(!url_matches_pattern(
            "https://apiXgithubYcom/repos/foo",
            "https://api.github.com/*"
        ));
    }

    #[test]
    fn query_strings_and_fragments() {
        assert!(url_matches_pattern(
            "https://api.example.com/search?q=test",
            "https://api.example.com/search?q=test"
        ));
        assert!(url_matches_pattern(
            "https://api.example.com/search?q=hello&limit=10",
            "https://api.example.com/*"
        ));
        assert!(url_matches_pattern(
            "https://example.com/page#section",
            "https://example.com/*"
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
    fn unparseable_input_is_refused() {
        assert!(!url_matches_pattern("not a url", "https://example.com/*"));
        assert!(!url_matches_pattern("https://example.com/x", "*"));
    }

    // -- validate_url_pattern --------------------------------------------

    #[test]
    fn the_documented_patterns_validate() {
        for pattern in [
            "",
            "https://api.github.com/*",
            "https://*.amazonaws.com/*",
            "https://api.example.com/repos/*/pulls",
            "http://localhost:8080/*",
            "https://api.example.com/v1/x?tenant=*",
        ] {
            assert!(
                validate_url_pattern(pattern).is_ok(),
                "{pattern:?} should validate: {:?}",
                validate_url_pattern(pattern)
            );
        }
    }

    /// Every pattern the validator refuses is one `url_matches_pattern` can
    /// never satisfy, so the two must not disagree.
    #[test]
    fn a_refused_pattern_would_never_have_matched() {
        for pattern in [
            "not a url",
            "api.github.com/*",
            "ftp://example.com/*",
            "https:///*",
            "*",
            "https://api-*.github.com/*",
        ] {
            assert!(
                validate_url_pattern(pattern).is_err(),
                "{pattern:?} should be refused"
            );
        }
        // The partial wildcard parses as a URL, so only the validator catches
        // it — the matcher just answers "no" to every URL forever.
        assert!(!url_matches_pattern(
            "https://api-v3.github.com/x",
            "https://api-*.github.com/*"
        ));
    }

    #[test]
    fn credentials_and_fragments_are_refused() {
        assert!(validate_url_pattern("https://user:pw@example.com/*").is_err());
        assert!(validate_url_pattern("https://example.com/*#frag").is_err());
        assert!(validate_url_pattern(" https://example.com/*").is_err());
    }
}
