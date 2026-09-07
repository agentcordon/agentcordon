use serde::Deserialize;

use crate::broker::BrokerClient;
use crate::config::{self, ServerUrl};
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

/// The line `status` prints about the *configured* server URL — the one a
/// `register` or an `init` would use — and where it came from.
///
/// The broker's `server_url` (the `Server:` line) is the server the running
/// broker is actually bound to. The two can disagree: an
/// `AGTCRDN_SERVER_URL` left over in a shell, or a config file written by a
/// second server's installer, sends the next enrolment somewhere the current
/// broker is not. Naming the source is how that becomes visible.
fn configured_server_line(configured: Option<&ServerUrl>) -> String {
    match configured {
        Some(c) => format!(
            "Configured server: {} (from {})",
            c.url,
            c.source.describe()
        ),
        None => format!(
            "Configured server: none. {}",
            config::missing_server_url_hint()
        ),
    }
}

/// The report, as text.
///
/// `mcp-serve`'s `agentcordon_status` tool answers with this same block, so
/// the two cannot drift into describing the workspace differently: one
/// report, two ways of asking for it. The version-skew warning stays with
/// the command, because it is about the terminal's two binaries rather than
/// about the workspace.
pub(crate) async fn report(client: &BrokerClient) -> Result<String, CliError> {
    let resp: StatusResponse = client.get("/status").await?;
    let data = resp.data;

    let mut lines = vec![format!("Broker: {} (healthy)", client.base_url())];

    if let Some(server_url) = &data.server_url {
        lines.push(format!("Server: {server_url} (reachable)"));
    }

    lines.push(configured_server_line(
        config::resolve_server_url(None).as_ref(),
    ));
    lines.push(format!("Workspace: {}", client.keypair().identity()));
    lines.push(format!(
        "Registered: {}",
        if data.registered { "yes" } else { "no" }
    ));

    if !data.scopes.is_empty() {
        lines.push(format!("Scopes: {}", data.scopes.join(", ")));
    }

    if let Some(token_status) = &data.token_status {
        let expires = data
            .token_expires_at
            .as_deref()
            .map(format_expiry)
            .unwrap_or_default();
        lines.push(format!("Token: {token_status}{expires}"));
    }

    Ok(lines.join("\n"))
}

/// Check workspace registration and broker connectivity.
pub async fn run() -> Result<(), CliError> {
    let client = BrokerClient::connect().await?;
    let report = report(&client).await?;

    if let Some(warning) = version_skew_warning(client.broker_version(), CLI_VERSION) {
        eprintln!("{warning}");
    }

    println!("{report}");
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
    use super::{configured_server_line, version_skew_warning};
    use crate::config::{ServerUrl, ServerUrlSource};

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

    /// The three sources `status` must be able to tell apart. Without this
    /// line a stale `AGTCRDN_SERVER_URL` and a config file written by another
    /// server's installer look identical from the terminal.
    #[test]
    fn the_configured_server_line_names_its_source() {
        for (source, expected) in [
            (ServerUrlSource::Flag, "--server-url"),
            (ServerUrlSource::Env, "AGTCRDN_SERVER_URL"),
            (ServerUrlSource::ConfigFile, "~/.agentcordon/config.toml"),
        ] {
            let line = configured_server_line(Some(&ServerUrl {
                url: "https://cordon.example.com".to_string(),
                source,
            }));
            assert!(line.contains("https://cordon.example.com"), "{line}");
            assert!(line.contains(expected), "{line}");
            assert_eq!(line.lines().count(), 1, "one line: {line}");
        }
    }

    /// Nothing configured is a state to report, not a blank: it is exactly
    /// the state in which `agentcordon init` cannot enrol.
    #[test]
    fn no_configured_server_says_so_and_hints() {
        let line = configured_server_line(None);
        assert!(line.contains("none"), "{line}");
        assert!(line.contains("--server-url"), "{line}");
    }
}
