//! The path-and-query form that goes into the signed payload.

/// Canonicalise a request path-and-query for inclusion in the signed payload.
///
/// The CLI applies this to the path it is about to request; the broker
/// applies it to `Uri::path()` / `Uri::query()` of the request it received.
/// Both sides call this one function, so the two can only agree.
///
/// - Strip a single trailing `/` from `path` unless `path == "/"`.
/// - If `query` is `Some(non-empty)`, append `"?"` + the query verbatim
///   (percent-encoding untouched, parameters NOT re-sorted).
/// - If `query` is `None` or `Some("")`, append nothing.
///
/// Fragments never appear in `Uri::query()` and are not included in the
/// outgoing CLI path, so no fragment-stripping is needed.
pub fn canonicalise_path_and_query(path: &str, query: Option<&str>) -> String {
    let trimmed: &str = if path.len() > 1 && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    };
    match query {
        Some(q) if !q.is_empty() => format!("{trimmed}?{q}"),
        _ => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalise_plain_path() {
        assert_eq!(canonicalise_path_and_query("/foo/bar", None), "/foo/bar");
    }

    #[test]
    fn canonicalise_strips_trailing_slash() {
        assert_eq!(canonicalise_path_and_query("/foo/bar/", None), "/foo/bar");
    }

    #[test]
    fn canonicalise_with_query() {
        assert_eq!(
            canonicalise_path_and_query("/foo/bar", Some("a=1&b=2")),
            "/foo/bar?a=1&b=2"
        );
    }

    #[test]
    fn canonicalise_strips_trailing_slash_with_query() {
        assert_eq!(
            canonicalise_path_and_query("/foo/bar/", Some("a=1&b=2")),
            "/foo/bar?a=1&b=2"
        );
    }

    #[test]
    fn canonicalise_root_path() {
        assert_eq!(canonicalise_path_and_query("/", None), "/");
    }

    #[test]
    fn canonicalise_root_with_query() {
        assert_eq!(canonicalise_path_and_query("/", Some("a=1")), "/?a=1");
    }

    #[test]
    fn canonicalise_root_with_empty_query() {
        assert_eq!(canonicalise_path_and_query("/", Some("")), "/");
    }
}
