use super::client::ApiClient;
use super::output;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

pub async fn run(flags: &GlobalFlags) -> Result<(), String> {
    if !state::has_workspace_key() {
        output::print_result(
            flags.json,
            "Not enrolled. Run 'init' + 'register'.",
            &serde_json::json!({"workspace_identity": false}),
        );
        return Ok(());
    }

    let st = WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    let (health_status, version) = check_server_health(&server_url).await;
    let (jwt_status, jwt_remaining) = check_jwt_status(&st);

    let workspace_id = st.agent_id.as_deref().unwrap_or("?");
    let pk_hash = st.workspace_pk_hash.as_deref().unwrap_or("?");

    if flags.json {
        output::print_result(
            true,
            "",
            &serde_json::json!({
                "workspace_identity": true,
                "workspace_id": workspace_id,
                "server_url": server_url,
                "server_health": health_status,
                "server_version": version,
                "jwt_status": jwt_status,
                "jwt_remaining_seconds": jwt_remaining,
                "workspace_pk_hash": pk_hash,
            }),
        );
        return Ok(());
    }

    println!("AgentCordon Status");
    println!(
        "  Server:       {} ({}, v{})",
        server_url, health_status, version
    );
    if workspace_id != "?" {
        println!("  Workspace ID: {}", workspace_id);
    } else {
        println!("  Workspace ID: Not registered");
    }
    println!("  Identity:     {}", pk_hash);
    println!("  Auth mode:    workspace identity (Ed25519)");
    match jwt_status.as_str() {
        "valid" => println!(
            "  JWT:          valid (expires in {}m {}s)",
            jwt_remaining / 60,
            jwt_remaining % 60
        ),
        "expired" => println!("  JWT:          expired (will auto-refresh on next command)"),
        _ => println!("  JWT:          not yet obtained (run 'auth' or any command)"),
    }

    Ok(())
}

async fn check_server_health(server_url: &str) -> (String, String) {
    let client = ApiClient::new(server_url);
    match client.get_raw("/health").await {
        Ok((200, body)) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                let health = parsed
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let version = parsed
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                (health, version)
            } else {
                ("unknown".to_string(), "?".to_string())
            }
        }
        _ => ("unreachable".to_string(), "?".to_string()),
    }
}

fn check_jwt_status(st: &WorkspaceState) -> (String, i64) {
    let jwt = match &st.jwt {
        Some(j) if !j.is_empty() => j,
        _ => return ("none".to_string(), 0),
    };
    let _ = jwt;

    let expires_at = match &st.jwt_expires_at {
        Some(e) => match e.parse::<i64>() {
            Ok(v) => v,
            Err(_) => return ("none".to_string(), 0),
        },
        None => return ("none".to_string(), 0),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if now < expires_at {
        ("valid".to_string(), expires_at - now)
    } else {
        ("expired".to_string(), 0)
    }
}
