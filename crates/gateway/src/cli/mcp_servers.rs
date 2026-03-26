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
        .get_auth("/api/v1/mcp-servers", &token)
        .await
        .map_err(|e| format!("failed to list MCP servers: {}", e))?;

    if flags.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).expect("JSON serialization cannot fail")
        );
        return Ok(());
    }

    // Extract servers array from response
    let servers = extract_servers(&resp);
    if servers.is_empty() {
        println!("No MCP servers available.");
        return Ok(());
    }

    println!("Available MCP servers:");
    for srv in &servers {
        let name = srv.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let tools_str = srv
            .get("tools")
            .and_then(|v| v.as_array())
            .map(|tools| {
                let names: Vec<&str> = tools
                    .iter()
                    .filter_map(|t| {
                        t.get("name")
                            .and_then(|n| n.as_str())
                            .or_else(|| t.as_str())
                    })
                    .collect();
                if names.is_empty() {
                    String::new()
                } else {
                    format!("\n    tools: {}", names.join(", "))
                }
            })
            .unwrap_or_default();
        println!("  {}{}", name, tools_str);
    }

    Ok(())
}

/// Extract servers array from various response shapes.
pub fn extract_servers(resp: &serde_json::Value) -> Vec<&serde_json::Value> {
    // Try .data as array
    if let Some(arr) = resp.get("data").and_then(|d| d.as_array()) {
        return arr.iter().collect();
    }
    // Try .data.servers
    if let Some(arr) = resp
        .get("data")
        .and_then(|d| d.get("servers"))
        .and_then(|s| s.as_array())
    {
        return arr.iter().collect();
    }
    // Try top-level array
    if let Some(arr) = resp.as_array() {
        return arr.iter().collect();
    }
    // Try .servers
    if let Some(arr) = resp.get("servers").and_then(|s| s.as_array()) {
        return arr.iter().collect();
    }
    vec![]
}
