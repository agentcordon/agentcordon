use serde::Deserialize;

use crate::broker::BrokerClient;
use crate::error::CliError;

#[derive(Deserialize)]
struct CreateEnvelope {
    #[allow(dead_code)]
    data: serde_json::Value,
}

/// What the success line says about the new credential's URL fence.
///
/// A credential made without `--allowed-url-pattern` can be proxied to any
/// URL. That used to be both the default and invisible: the safest-looking
/// command in the CLI produced the least safe credential and said nothing
/// about it.
fn creation_summary(name: &str, service: &str, pattern: Option<&str>) -> String {
    match pattern {
        Some(p) => format!("Created credential '{name}' (service: {service}, allowed URLs: {p})"),
        None => format!(
            "Created credential '{name}' (service: {service}, allowed URLs: UNRESTRICTED \
             — this credential can be proxied to any URL; narrow it with \
             --allowed-url-pattern)"
        ),
    }
}

/// Create a credential via the broker passthrough.
pub async fn create(
    name: String,
    service: String,
    value: String,
    allowed_url_pattern: Option<String>,
) -> Result<(), CliError> {
    if name.is_empty() || service.is_empty() || value.is_empty() {
        return Err(CliError::general(
            "--name, --service, and --value must all be non-empty",
        ));
    }
    // A blank pattern is the same as no pattern; the server normalises it the
    // same way, and sending it would only look like a fence that isn't one.
    let pattern = allowed_url_pattern
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());

    let client = BrokerClient::connect().await?;
    let mut req_body = serde_json::json!({
        "name": name,
        "service": service,
        "secret_value": value,
        "credential_type": "generic",
    });
    if let Some(ref p) = pattern {
        req_body["allowed_url_pattern"] = serde_json::Value::String(p.clone());
    }
    let _: CreateEnvelope = client.post("/credentials/create", &req_body).await?;
    println!("{}", creation_summary(&name, &service, pattern.as_deref()));
    Ok(())
}

#[derive(Deserialize)]
struct CredentialsResponse {
    data: Vec<Credential>,
}

#[derive(Deserialize)]
struct Credential {
    name: String,
    service: String,
    credential_type: String,
    vault: Option<String>,
    expires_at: Option<String>,
}

/// List available credentials.
pub async fn run() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: CredentialsResponse = client.get("/credentials").await?;

    if resp.data.is_empty() {
        println!("No credentials available.");
        return Ok(());
    }

    // Calculate column widths
    let name_w = resp
        .data
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let svc_w = resp
        .data
        .iter()
        .map(|c| c.service.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let type_w = resp
        .data
        .iter()
        .map(|c| c.credential_type.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let vault_w = resp
        .data
        .iter()
        .map(|c| c.vault.as_deref().unwrap_or("-").len())
        .max()
        .unwrap_or(5)
        .max(5);

    // Header
    println!(
        "{:<name_w$}  {:<svc_w$}  {:<type_w$}  {:<vault_w$}  EXPIRES",
        "NAME", "SERVICE", "TYPE", "VAULT"
    );

    // Rows
    for cred in &resp.data {
        let vault = cred.vault.as_deref().unwrap_or("-");
        let expires = cred.expires_at.as_deref().unwrap_or("never");
        println!(
            "{:<name_w$}  {:<svc_w$}  {:<type_w$}  {:<vault_w$}  {expires}",
            cred.name, cred.service, cred.credential_type, vault
        );
    }

    Ok(())
}
