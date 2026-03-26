use super::auth;
use super::client::ApiClient;
use super::state::WorkspaceState;
use super::GlobalFlags;

pub async fn run(flags: &GlobalFlags) -> Result<(), String> {
    let token = auth::ensure_jwt(flags).await?;
    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    let client = ApiClient::new(&server_url);
    let resp: serde_json::Value = client
        .get_auth("/api/v1/credentials", &token)
        .await
        .map_err(|e| format!("failed to list credentials: {}", e))?;

    if flags.json {
        let data = resp.get("data").unwrap_or(&resp);
        println!(
            "{}",
            serde_json::to_string_pretty(data).expect("JSON serialization cannot fail")
        );
        return Ok(());
    }

    // Human-readable display
    let data = resp.get("data").unwrap_or(&resp);
    if let Some(arr) = data.as_array() {
        if arr.is_empty() {
            println!("No credentials available. Ask your admin to grant access.");
            return Ok(());
        }
        println!("Available credentials:");
        for cred in arr {
            let name = cred
                .get("name")
                .or_else(|| cred.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let cred_type = cred
                .get("credential_type")
                .or_else(|| cred.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let service = cred.get("service").and_then(|v| v.as_str()).unwrap_or("?");
            println!("  {}  ({})  service: {}", name, cred_type, service);
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_default()
        );
    }

    Ok(())
}
