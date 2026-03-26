use super::auth;
use super::client::ApiClient;
use super::state::WorkspaceState;
use super::GlobalFlags;

pub async fn run(
    flags: &GlobalFlags,
    name: &str,
    service: &str,
    secret: &str,
    cred_type: &str,
    scopes: Option<&str>,
) -> Result<(), String> {
    let token = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    // Build scopes array from comma-separated string
    let scopes_json: Vec<&str> = scopes
        .map(|s| s.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();

    let body = serde_json::json!({
        "name": name,
        "service": service,
        "secret_value": secret,
        "credential_type": cred_type,
        "scopes": scopes_json,
    });

    let client = ApiClient::new(&server_url);
    let (status, resp_body) = client
        .post_auth_raw("/api/v1/credentials/agent-store", &token, &body)
        .await
        .map_err(|e| format!("failed to store credential: {}", e))?;

    if status == 200 || status == 201 {
        if flags.json {
            let parsed: serde_json::Value =
                serde_json::from_str(&resp_body).unwrap_or(serde_json::json!({"status": "ok"}));
            println!(
                "{}",
                serde_json::to_string_pretty(&parsed).expect("JSON serialization cannot fail")
            );
        } else {
            println!("Credential stored successfully. Tagged as llm_exposed — rotate this secret.");
        }
        Ok(())
    } else {
        // Try to extract error message
        let err_msg = serde_json::from_str::<serde_json::Value>(&resp_body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str().map(String::from))
            })
            .unwrap_or(resp_body);
        Err(format!(
            "Failed to store credential (HTTP {}): {}",
            status, err_msg
        ))
    }
}
