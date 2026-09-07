use serde::{Deserialize, Serialize};

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

#[derive(Deserialize, Serialize)]
struct CredentialsResponse {
    data: Vec<Credential>,
}

#[derive(Deserialize, Serialize)]
struct Credential {
    name: String,
    service: String,
    credential_type: String,
    /// The glob a proxied URL must match. `None` means the credential may be
    /// sent anywhere, which is the least safe state and so the loudest cell.
    #[serde(default)]
    allowed_url_pattern: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    vault: Option<String>,
    expires_at: Option<String>,
    #[serde(default)]
    expired: bool,
}

/// What the `ALLOWED URL` cell says when a credential has no fence.
///
/// Not `-`: an empty-looking cell reads as "no information", and this is the
/// opposite — it is the credential that may be proxied to any URL at all.
const UNRESTRICTED: &str = "* (any URL)";

/// The listing an agent chooses from.
///
/// `NAME SERVICE TYPE VAULT EXPIRES` was every column except the one the
/// instructions tell an agent to choose by. The skill says "read the ALLOWED
/// URL column, pick the credential whose fence covers your target, then the
/// least privileged of those"; with one credential that was invisible, with
/// six it was the difference between one call and six
/// (uat/artifacts/reviews/ONBOARDING-empirical.md F5).
///
/// There is no DESCRIPTION column: the broker's projection withholds
/// `description` from an agent on purpose, alongside `transform_script`,
/// `metadata`, `owner_username` and `tags`
/// (`wire_contract::credential_listing_projects_the_servers_summary`).
fn render_table(creds: &[Credential]) -> String {
    let allowed = |c: &Credential| c.allowed_url_pattern.clone().unwrap_or(UNRESTRICTED.into());
    let width = |header: &str, f: &dyn Fn(&Credential) -> String| {
        creds
            .iter()
            .map(|c| f(c).len())
            .max()
            .unwrap_or(0)
            .max(header.len())
    };

    let name_w = width("NAME", &|c| c.name.clone());
    let svc_w = width("SERVICE", &|c| c.service.clone());
    let type_w = width("TYPE", &|c| c.credential_type.clone());
    let url_w = width("ALLOWED URL", &allowed);
    let vault_w = width("VAULT", &|c| c.vault.clone().unwrap_or_else(|| "-".into()));
    let expires_w = width("EXPIRES", &|c| {
        c.expires_at.clone().unwrap_or_else(|| "never".into())
    });

    let mut out = String::new();
    out.push_str(&format!(
        "{:<name_w$}  {:<svc_w$}  {:<type_w$}  {:<url_w$}  {:<vault_w$}  {:<expires_w$}",
        "NAME", "SERVICE", "TYPE", "ALLOWED URL", "VAULT", "EXPIRES"
    ));
    out.push('\n');

    for c in creds {
        let expires = if c.expired {
            format!("{} (EXPIRED)", c.expires_at.as_deref().unwrap_or("?"))
        } else {
            c.expires_at.clone().unwrap_or_else(|| "never".into())
        };
        out.push_str(&format!(
            "{:<name_w$}  {:<svc_w$}  {:<type_w$}  {:<url_w$}  {:<vault_w$}  {:<expires_w$}",
            c.name,
            c.service,
            c.credential_type,
            allowed(c),
            c.vault.as_deref().unwrap_or("-"),
            expires,
        ));
        out.push('\n');
    }
    out.push_str(&format!(
        "\n{UNRESTRICTED} means the credential is not fenced and may be proxied anywhere. \
         Prefer the narrowest fence that covers your target URL.\n"
    ));
    out
}

/// List available credentials.
pub async fn run(json: bool) -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let resp: CredentialsResponse = client.get("/credentials").await?;

    if json {
        // The whole envelope, so a caller can `jq '.data[]'` the same shape
        // the broker returned. Printed even when empty: a script asking for
        // JSON must get JSON.
        println!(
            "{}",
            serde_json::to_string_pretty(&resp)
                .map_err(|e| CliError::general(format!("failed to render JSON: {e}")))?
        );
        return Ok(());
    }

    if resp.data.is_empty() {
        println!("No credentials available.");
        return Ok(());
    }

    print!("{}", render_table(&resp.data));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(name: &str, pattern: Option<&str>) -> Credential {
        Credential {
            name: name.into(),
            service: "internal".into(),
            credential_type: "generic".into(),
            allowed_url_pattern: pattern.map(Into::into),
            scopes: Vec::new(),
            vault: Some("default".into()),
            expires_at: None,
            expired: false,
        }
    }

    /// The column the skill tells an agent to choose by.
    #[test]
    fn the_table_shows_the_url_fence() {
        let table = render_table(&[cred("narrow", Some("https://api.example.com/v1/*"))]);
        assert!(table.contains("ALLOWED URL"));
        assert!(table.contains("https://api.example.com/v1/*"));
    }

    /// An unfenced credential is the least safe one, so its cell says so
    /// rather than looking like a missing value.
    #[test]
    fn an_unfenced_credential_says_so_instead_of_showing_a_dash() {
        let table = render_table(&[cred("wide", None)]);
        assert!(table.contains(UNRESTRICTED));
        assert!(
            !table.lines().next().unwrap().contains('-'),
            "no dash where a fence should be"
        );
        assert!(table.contains("Prefer the narrowest fence"));
    }

    /// The broker withholds `description` from an agent, so the CLI has no
    /// column for it: a header over a permanently empty cell is worse than no
    /// header.
    #[test]
    fn there_is_no_description_column() {
        let table = render_table(&[cred("a", Some("https://x/*"))]);
        assert!(!table.contains("DESCRIPTION"));
    }

    /// Columns stay aligned when one value is much longer than its header.
    #[test]
    fn columns_are_wide_enough_for_their_widest_value() {
        let table = render_table(&[
            cred(
                "a",
                Some("https://a-very-long-host.example.com/some/path/*"),
            ),
            cred("b", Some("https://x/*")),
        ]);
        let rows: Vec<&str> = table.lines().take(3).collect();
        let column = rows[0].find("ALLOWED URL").unwrap();
        assert!(rows[1][column..].starts_with("https://a-very-long-host"));
        assert!(rows[2][column..].starts_with("https://x/*"));
    }

    /// An expired credential is not a candidate, and the table has to say so
    /// where the agent is looking.
    #[test]
    fn an_expired_credential_is_marked_in_the_expires_column() {
        let mut c = cred("stale", Some("https://x/*"));
        c.expires_at = Some("2020-01-01T00:00:00Z".into());
        c.expired = true;
        assert!(render_table(&[c]).contains("2020-01-01T00:00:00Z (EXPIRED)"));
    }
}
