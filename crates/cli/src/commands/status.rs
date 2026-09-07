use serde::Deserialize;

use crate::broker::BrokerClient;
use crate::error::CliError;

#[derive(Deserialize)]
struct StatusResponse {
    data: StatusData,
}

#[derive(Deserialize)]
struct StatusData {
    registered: bool,
    #[serde(default)]
    scopes: Vec<String>,
    token_expires_at: Option<String>,
    token_status: Option<String>,
    server_url: Option<String>,
}

/// This CLI's own version, compared with the broker's on every `status`.
const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Warn when the CLI and the broker are different builds.
///
/// The pair is installed together and expected to move together: v0.4.0
/// changed the signed request payload, so a CLI and a broker on opposite
/// sides of it cannot communicate at all. A mismatch is easy to acquire —
/// `install.sh` and a `cargo build --release` produce different binaries in
/// the same `~/.local/bin` — and hard to recognise from the failure it
/// eventually causes, so `status` says it plainly.
///
/// `None` when the versions agree, or when the broker is too old to report
/// one (that broker is refused earlier, at the `/health` fingerprint check,
/// with its own upgrade hint).
fn version_skew_warning(broker_version: Option<&str>, cli_version: &str) -> Option<String> {
    let broker_version = broker_version?;
    if broker_version == cli_version {
        return None;
    }
    Some(format!(
        "! Version mismatch: broker {broker_version}, CLI {cli_version}.\n  \
         They are installed as a pair and v0.4.0 changed the signed request format, \
         so mismatched\n  builds may fail to talk to each other. \
         See docs/upgrading.md."
    ))
}

/// Check workspace registration and broker connectivity.
pub async fn run() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;

    let resp: StatusResponse = client.get("/status").await?;
    let data = resp.data;

    println!("Broker: {} (healthy)", client.base_url());

    if let Some(warning) = version_skew_warning(client.broker_version(), CLI_VERSION) {
        eprintln!("{warning}");
    }

    if let Some(server_url) = &data.server_url {
        println!("Server: {server_url} (reachable)");
    }

    println!("Workspace: {}", client.keypair().identity());
    println!("Registered: {}", if data.registered { "yes" } else { "no" });

    if !data.scopes.is_empty() {
        println!("Scopes: {}", data.scopes.join(", "));
    }

    if let Some(token_status) = &data.token_status {
        let expires = data
            .token_expires_at
            .as_deref()
            .map(format_expiry)
            .unwrap_or_default();
        println!("Token: {token_status}{expires}");
    }

    Ok(())
}

/// Format an ISO 8601 expiry time as a human-readable duration.
fn format_expiry(expires_at: &str) -> String {
    if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        let now = chrono::Utc::now();
        let diff = expiry.signed_duration_since(now);
        if diff.num_seconds() <= 0 {
            return " (expired)".to_string();
        }
        let mins = diff.num_minutes();
        let secs = diff.num_seconds() % 60;
        format!(" (expires in {mins}m {secs:02}s)")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::version_skew_warning;

    #[test]
    fn matching_versions_say_nothing() {
        assert!(version_skew_warning(Some("0.4.0"), "0.4.0").is_none());
    }

    #[test]
    fn a_mismatch_names_both_versions_and_points_at_the_upgrade_guide() {
        // The shape a doc-following user lands in: `install.sh` gave them the
        // last published release while the server, and their own rebuilt CLI,
        // are on the next one.
        let warning = version_skew_warning(Some("0.3.3"), "0.4.0").expect("a warning");
        assert!(warning.contains("0.3.3"), "names the broker: {warning}");
        assert!(warning.contains("0.4.0"), "names the CLI: {warning}");
        assert!(
            warning.contains("docs/upgrading.md"),
            "points at the upgrade guide: {warning}"
        );
    }

    #[test]
    fn a_broker_that_reports_no_version_is_not_warned_about() {
        // It is refused earlier, by the /health fingerprint check, with its
        // own upgrade hint. A second guess here would only be noise.
        assert!(version_skew_warning(None, "0.4.0").is_none());
    }
}
