use std::collections::HashMap;

use regex::Regex;

/// Extract all unique placeholder names from the text.
///
/// Placeholders use the syntax `{{name}}`. The name is trimmed of
/// leading/trailing whitespace. Duplicate names are deduplicated while
/// preserving first-occurrence order.
pub fn extract_placeholders(text: &str) -> Vec<String> {
    let re = Regex::new(r"\{\{([^}]+)\}\}").expect("valid regex");
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for cap in re.captures_iter(text) {
        let name = cap[1].trim().to_string();
        if !name.is_empty() && seen.insert(name.clone()) {
            result.push(name);
        }
    }

    result
}

/// Replace all `{{name}}` placeholders in `text` with the corresponding value
/// from `values`.
///
/// If a placeholder name is not found in the map, it is left as-is (the caller
/// is expected to resolve all placeholders before calling this function).
pub fn substitute_placeholders(text: &str, values: &HashMap<String, String>) -> String {
    let re = Regex::new(r"\{\{([^}]+)\}\}").expect("valid regex");
    re.replace_all(text, |caps: &regex::Captures| {
        let name = caps[1].trim();
        match values.get(name) {
            Some(val) => val.clone(),
            None => caps[0].to_string(),
        }
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_placeholder() {
        let names = extract_placeholders("token {{github-pat}}");
        assert_eq!(names, vec!["github-pat"]);
    }

    #[test]
    fn multiple_distinct_placeholders() {
        let names = extract_placeholders("{{a}} and {{b}}");
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn duplicate_placeholders_are_deduplicated() {
        let names = extract_placeholders("{{a}} and {{b}} and {{a}}");
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn no_placeholders() {
        let names = extract_placeholders("no placeholders here");
        assert!(names.is_empty());
    }

    #[test]
    fn placeholder_in_url() {
        let names = extract_placeholders("https://api.example.com/v1?token={{api-key}}");
        assert_eq!(names, vec!["api-key"]);
    }

    #[test]
    fn placeholder_in_header_value() {
        let names = extract_placeholders("Bearer {{access-token}}");
        assert_eq!(names, vec!["access-token"]);
    }

    #[test]
    fn placeholder_in_body() {
        let text = r#"{"auth": "{{secret}}", "data": "hello"}"#;
        let names = extract_placeholders(text);
        assert_eq!(names, vec!["secret"]);
    }

    #[test]
    fn whitespace_in_placeholder_is_trimmed() {
        let names = extract_placeholders("{{ spaced }}");
        assert_eq!(names, vec!["spaced"]);
    }

    #[test]
    fn empty_placeholder_is_ignored() {
        // `{{}}` has no content between the braces -- our regex requires at least one char.
        let names = extract_placeholders("{{}}");
        assert!(names.is_empty());
    }

    #[test]
    fn unclosed_placeholder_is_not_matched() {
        let names = extract_placeholders("{{unclosed");
        assert!(names.is_empty());
    }

    #[test]
    fn substitute_single() {
        let mut values = HashMap::new();
        values.insert("pat".to_string(), "ghp_xxx".to_string());
        assert_eq!(
            substitute_placeholders("Bearer {{pat}}", &values),
            "Bearer ghp_xxx"
        );
    }

    #[test]
    fn substitute_multiple_occurrences() {
        let mut values = HashMap::new();
        values.insert("tok".to_string(), "abc".to_string());
        assert_eq!(
            substitute_placeholders("{{tok}}:{{tok}}", &values),
            "abc:abc"
        );
    }

    #[test]
    fn substitute_multiple_distinct() {
        let mut values = HashMap::new();
        values.insert("a".to_string(), "1".to_string());
        values.insert("b".to_string(), "2".to_string());
        assert_eq!(substitute_placeholders("{{a}}+{{b}}", &values), "1+2");
    }

    #[test]
    fn substitute_missing_key_left_as_is() {
        let values = HashMap::new();
        assert_eq!(
            substitute_placeholders("{{unknown}}", &values),
            "{{unknown}}"
        );
    }

    #[test]
    fn substitute_no_placeholders() {
        let values = HashMap::new();
        assert_eq!(substitute_placeholders("plain text", &values), "plain text");
    }

    #[test]
    fn substitute_in_url() {
        let mut values = HashMap::new();
        values.insert("key".to_string(), "secret123".to_string());
        assert_eq!(
            substitute_placeholders("https://api.example.com/v1?token={{key}}", &values),
            "https://api.example.com/v1?token=secret123"
        );
    }

    #[test]
    fn substitute_with_whitespace_in_placeholder() {
        let mut values = HashMap::new();
        values.insert("spaced".to_string(), "val".to_string());
        assert_eq!(substitute_placeholders("{{ spaced }}", &values), "val");
    }

    #[test]
    fn triple_braces_edge_case() {
        // `{{{name}}}` -- the regex matches `{{{name}}` (capturing `{name`).
        // Since `{name` is not a valid placeholder name in the values map,
        // the text is left as-is. This is safe behavior.
        let mut values = HashMap::new();
        values.insert("name".to_string(), "val".to_string());
        let result = substitute_placeholders("{{{name}}}", &values);
        assert_eq!(result, "{{{name}}}");
    }
}
