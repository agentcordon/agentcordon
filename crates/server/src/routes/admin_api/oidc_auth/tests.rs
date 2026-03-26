use super::*;
use agent_cordon_core::auth::oidc::IdTokenClaims;
use serde_json::json;
use std::collections::HashMap;

/// Build a minimal IdTokenClaims with optional extra claims.
fn make_claims(extra: HashMap<String, serde_json::Value>) -> IdTokenClaims {
    IdTokenClaims {
        sub: "test-sub".to_string(),
        iss: "https://idp.example.com".to_string(),
        aud: json!("test-client"),
        exp: 9999999999,
        iat: Some(1000000000),
        nonce: Some("test-nonce".to_string()),
        email: Some("user@example.com".to_string()),
        name: Some("Test User".to_string()),
        preferred_username: Some("testuser".to_string()),
        extra,
    }
}

#[test]
fn test_resolve_role_with_group_claim_match() {
    let mut extra = HashMap::new();
    extra.insert("groups".to_string(), json!("AgentCordon-Admins"));

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "groups",
        "mappings": {
            "AgentCordon-Admins": "admin",
            "AgentCordon-Ops": "operator"
        },
        "default_role": "viewer"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Admin);
}

#[test]
fn test_resolve_role_with_no_match_uses_default() {
    let mut extra = HashMap::new();
    extra.insert("groups".to_string(), json!("SomeOtherGroup"));

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "groups",
        "mappings": {
            "AgentCordon-Admins": "admin",
            "AgentCordon-Ops": "operator"
        },
        "default_role": "operator"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Operator);
}

#[test]
fn test_resolve_role_with_empty_mapping() {
    let claims = make_claims(HashMap::new());
    let role_mapping = json!({});

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Viewer);
}

#[test]
fn test_resolve_role_with_array_claim() {
    let mut extra = HashMap::new();
    extra.insert(
        "groups".to_string(),
        json!(["Users", "AgentCordon-Ops", "Developers"]),
    );

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "groups",
        "mappings": {
            "AgentCordon-Admins": "admin",
            "AgentCordon-Ops": "operator"
        },
        "default_role": "viewer"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Operator);
}

#[test]
fn test_resolve_role_with_string_claim() {
    let mut extra = HashMap::new();
    extra.insert("department".to_string(), json!("engineering"));

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "department",
        "mappings": {
            "engineering": "operator",
            "security": "admin"
        },
        "default_role": "viewer"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Operator);
}

#[test]
fn test_resolve_role_no_claim_no_mappings_with_default() {
    let claims = make_claims(HashMap::new());
    let role_mapping = json!({
        "default_role": "admin"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Admin);
}

#[test]
fn test_resolve_role_claim_missing_from_token() {
    let claims = make_claims(HashMap::new());
    let role_mapping = json!({
        "claim": "groups",
        "mappings": {
            "AgentCordon-Admins": "admin"
        },
        "default_role": "operator"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Operator);
}

#[test]
fn test_resolve_role_first_match_wins() {
    let mut extra = HashMap::new();
    extra.insert(
        "roles".to_string(),
        json!(["viewer-role", "admin-role", "operator-role"]),
    );

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "roles",
        "mappings": {
            "admin-role": "admin",
            "operator-role": "operator",
            "viewer-role": "viewer"
        },
        "default_role": "viewer"
    });

    // "viewer-role" appears first in the array and maps to viewer
    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Viewer);
}

#[test]
fn test_resolve_role_null_role_mapping() {
    let claims = make_claims(HashMap::new());
    let role_mapping = serde_json::Value::Null;

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Viewer);
}

#[test]
fn test_resolve_role_with_well_known_email_claim() {
    let claims = make_claims(HashMap::new());
    let role_mapping = json!({
        "claim": "email",
        "mappings": {
            "user@example.com": "admin",
            "other@example.com": "operator"
        },
        "default_role": "viewer"
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Admin);
}

#[test]
fn test_resolve_role_no_default_role_no_match_defaults_viewer() {
    let mut extra = HashMap::new();
    extra.insert("groups".to_string(), json!("Unknown-Group"));

    let claims = make_claims(extra);
    let role_mapping = json!({
        "claim": "groups",
        "mappings": {
            "AgentCordon-Admins": "admin"
        }
    });

    let role = resolve_role(&role_mapping, &claims);
    assert_eq!(role, UserRole::Viewer);
}
