use agent_cordon_core::proxy::url_match::url_matches_pattern;
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
pub(crate) struct CredentialsResponse {
    pub(crate) data: Vec<Credential>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub(crate) struct Credential {
    pub(crate) name: String,
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
    pub(crate) expired: bool,
}

impl Credential {
    /// The URL fence, or `None` when this credential may be sent anywhere.
    ///
    /// A stored empty string is the same as no fence — `url_matches_pattern`
    /// answers `true` for an empty pattern — so it is normalised here rather
    /// than at every reader.
    pub(crate) fn fence(&self) -> Option<&str> {
        self.allowed_url_pattern
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
    }
}

/// One credential `--auto` could have chosen, as the refusal names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) name: String,
    /// The fence, or `None` for an unfenced credential.
    pub(crate) fence: Option<String>,
}

impl Candidate {
    fn of(c: &Credential) -> Self {
        Self {
            name: c.name.clone(),
            fence: c.fence().map(str::to_string),
        }
    }

    fn line(&self) -> String {
        format!(
            "  {}  {}",
            self.name,
            self.fence.as_deref().unwrap_or(UNRESTRICTED)
        )
    }
}

/// Why `--auto` did not end up with exactly one credential.
///
/// Both arms are the agent's problem to fix, not the broker's, so neither is
/// a broker error: they are decided here, from the listing, before anything
/// is vended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoSingleMatch {
    /// Nothing covers the target.
    None {
        /// How many credentials were skipped because they have expired. A
        /// fence that would have matched but is expired is the confusing
        /// case, so it is counted rather than swallowed.
        expired: usize,
    },
    /// More than one covers it; the agent must name one.
    Several(Vec<Candidate>),
}

impl NoSingleMatch {
    /// The one line (or short block) the agent reads.
    pub(crate) fn message(&self, url: &str) -> String {
        match self {
            NoSingleMatch::None { expired } => {
                let mut m =
                    format!("no credential is fenced for {url}; run agentcordon credentials");
                if *expired > 0 {
                    m.push_str(&format!(
                        " ({expired} credential(s) whose fence covers it have expired)"
                    ));
                }
                m
            }
            NoSingleMatch::Several(candidates) => {
                let mut m = format!("several credentials are fenced for {url}; name one:");
                for c in candidates {
                    m.push('\n');
                    m.push_str(&c.line());
                }
                m.push_str(&format!(
                    "\n\nRun: agentcordon proxy {} <METHOD> {url}",
                    candidates
                        .first()
                        .map(|c| c.name.as_str())
                        .unwrap_or("<CREDENTIAL>")
                ));
                m
            }
        }
    }
}

/// Pick the one credential whose fence covers `url`.
///
/// The rule is deterministic and stated once, here, because `proxy --auto`
/// is the command an agent runs without reading a listing first:
///
/// 1. An expired credential is never a candidate — it cannot be vended.
/// 2. A **fenced** credential is a candidate when the structural matcher
///    ([`url_matches_pattern`]) says its pattern covers the target. Never a
///    string prefix: `https://*.github.com/*` must not be satisfied by
///    `api.github.com.attacker.example`, and the port is compared as a value.
/// 3. Exactly one fenced candidate wins.
/// 4. With **no** fenced candidate, an **unfenced** credential (`*`, any URL)
///    is considered — last, because it is the least privileged choice
///    available rather than the least privileged credential.
/// 5. Zero or several candidates is a refusal, never a guess.
///
/// Order is the broker's listing order, which is the server's; the refusal
/// lists candidates in that order so two runs read the same.
pub(crate) fn select_for_target<'a>(
    creds: &'a [Credential],
    url: &str,
) -> Result<&'a Credential, NoSingleMatch> {
    let live: Vec<&Credential> = creds.iter().filter(|c| !c.expired).collect();

    let fenced: Vec<&Credential> = live
        .iter()
        .copied()
        .filter(|c| c.fence().is_some_and(|p| url_matches_pattern(url, p)))
        .collect();
    if let Some(one) = single(&fenced) {
        return Ok(one);
    }
    if fenced.len() > 1 {
        return Err(NoSingleMatch::Several(
            fenced.iter().map(|c| Candidate::of(c)).collect(),
        ));
    }

    let unfenced: Vec<&Credential> = live
        .iter()
        .copied()
        .filter(|c| c.fence().is_none())
        .collect();
    if let Some(one) = single(&unfenced) {
        return Ok(one);
    }
    if unfenced.len() > 1 {
        return Err(NoSingleMatch::Several(
            unfenced.iter().map(|c| Candidate::of(c)).collect(),
        ));
    }

    Err(NoSingleMatch::None {
        expired: creds
            .iter()
            .filter(|c| c.expired)
            .filter(|c| match c.fence() {
                Some(p) => url_matches_pattern(url, p),
                None => true,
            })
            .count(),
    })
}

fn single<'a>(matches: &[&'a Credential]) -> Option<&'a Credential> {
    match matches {
        [one] => Some(one),
        _ => None,
    }
}

/// Fetch the listing the broker holds for this workspace.
///
/// One call, one process: `proxy --auto` asks once and selects locally, so
/// picking a credential adds no broker→server round trip of its own (the
/// broker caches the listing; see `crates/broker/src/routes/credentials.rs`).
pub(crate) async fn fetch(client: &BrokerClient) -> Result<Vec<Credential>, CliError> {
    let resp: CredentialsResponse = client.get("/credentials").await?;
    Ok(resp.data)
}

/// What the `ALLOWED URL` cell says when a credential has no fence.
///
/// Not `-`: an empty-looking cell reads as "no information", and this is the
/// opposite — it is the credential that may be proxied to any URL at all.
pub(crate) const UNRESTRICTED: &str = "* (any URL)";

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

#[cfg(test)]
mod selector_tests {
    use super::*;

    fn c(name: &str, pattern: Option<&str>) -> Credential {
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

    /// The one fenced credential whose pattern covers the target wins.
    #[test]
    fn exactly_one_fence_covering_the_target_is_chosen() {
        let creds = [
            c("github", Some("https://api.github.com/*")),
            c("slack", Some("https://slack.com/api/*")),
        ];
        let chosen = select_for_target(&creds, "https://api.github.com/user").expect("one match");
        assert_eq!(chosen.name, "github");
    }

    /// Zero matches is its own outcome, not a silent fallback.
    #[test]
    fn no_fence_covering_the_target_is_reported_as_none() {
        let creds = [c("github", Some("https://api.github.com/*"))];
        let err = select_for_target(&creds, "https://api.gitlab.com/user").unwrap_err();
        assert!(matches!(err, NoSingleMatch::None { .. }));
    }

    /// Several matches must be named, so the agent can pick one.
    #[test]
    fn several_fences_covering_the_target_list_the_candidates() {
        let creds = [
            c("gh-read", Some("https://api.github.com/*")),
            c("gh-write", Some("https://api.github.com/repos/*")),
        ];
        let err = select_for_target(&creds, "https://api.github.com/repos/a/b").unwrap_err();
        match err {
            NoSingleMatch::Several(candidates) => {
                let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
                assert_eq!(names, ["gh-read", "gh-write"]);
            }
            other => panic!("expected several, got {other:?}"),
        }
    }

    /// An unfenced credential is a last resort: a fenced match always wins.
    #[test]
    fn a_fenced_match_beats_an_unfenced_credential() {
        let creds = [
            c("anything", None),
            c("github", Some("https://api.github.com/*")),
        ];
        let chosen = select_for_target(&creds, "https://api.github.com/user").expect("one match");
        assert_eq!(chosen.name, "github");
    }

    /// With no fenced match, the single unfenced credential is used and the
    /// caller is told it is unfenced.
    #[test]
    fn the_only_unfenced_credential_is_used_when_nothing_is_fenced_for_the_target() {
        let creds = [c("anything", None)];
        let chosen = select_for_target(&creds, "https://api.github.com/user").expect("one match");
        assert_eq!(chosen.name, "anything");
        assert!(chosen.fence().is_none(), "it is the unfenced one");
    }

    /// Two unfenced credentials are as ambiguous as two fenced ones.
    #[test]
    fn several_unfenced_credentials_are_ambiguous_too() {
        let creds = [c("a", None), c("b", None)];
        let err = select_for_target(&creds, "https://api.github.com/user").unwrap_err();
        match err {
            NoSingleMatch::Several(candidates) => assert_eq!(candidates.len(), 2),
            other => panic!("expected several, got {other:?}"),
        }
    }

    /// The matcher is structural: a host that merely contains the pattern
    /// text, or the pattern text inside a query string, is not a match.
    /// This is `url_matches_pattern`, not a string prefix.
    #[test]
    fn selection_uses_the_structural_matcher() {
        let creds = [c("github", Some("https://*.github.com/*"))];
        assert!(select_for_target(&creds, "https://api.github.com/x").is_ok());
        assert!(select_for_target(&creds, "https://api.github.com.evil.test/x").is_err());
        assert!(select_for_target(&creds, "https://evil.test/?u=.github.com/").is_err());
        assert!(
            select_for_target(&creds, "https://api.github.com:8443/x").is_err(),
            "the port is compared as a value"
        );
    }

    /// Every fence form `docs/cli-reference.md` documents selects the way the
    /// matcher says it does.
    #[test]
    fn every_documented_fence_form_selects() {
        let cases = [
            (
                "https://api.github.com/*",
                "https://api.github.com/user",
                true,
            ),
            (
                "https://*.amazonaws.com/*",
                "https://s3.amazonaws.com/b",
                true,
            ),
            (
                "https://*.amazonaws.com/*",
                "https://amazonaws.com/b",
                false,
            ),
            (
                "https://*.amazonaws.com/*",
                "https://ssm.us-east-1.amazonaws.com/",
                false,
            ),
            (
                "https://**.amazonaws.com/*",
                "https://ssm.us-east-1.amazonaws.com/",
                true,
            ),
            (
                "https://**.amazonaws.com/*",
                "https://amazonaws.com/",
                false,
            ),
            (
                "https://api.example.com/repos/*/pulls",
                "https://api.example.com/repos/x/pulls",
                true,
            ),
            (
                "https://api.example.com/repos/*/pulls",
                "https://api.example.com/repos/x/issues",
                false,
            ),
            (
                "http://localhost:8080/*",
                "http://localhost:8080/echo",
                true,
            ),
            (
                "http://localhost:8080/*",
                "http://localhost:9090/echo",
                false,
            ),
            (
                "https://api.example.com/v1/x?tenant=*",
                "https://api.example.com/v1/x?tenant=acme",
                true,
            ),
        ];
        for (fence, url, expected) in cases {
            let creds = [c("only", Some(fence))];
            assert_eq!(
                select_for_target(&creds, url).is_ok(),
                expected,
                "fence {fence} against {url}"
            );
        }
    }

    /// An expired credential cannot be vended, so it is not a candidate —
    /// and its absence is explained rather than silent.
    #[test]
    fn an_expired_credential_is_not_a_candidate() {
        let mut expired = c("stale", Some("https://api.github.com/*"));
        expired.expired = true;
        let err = select_for_target(&[expired], "https://api.github.com/user").unwrap_err();
        match err {
            NoSingleMatch::None { expired, .. } => assert_eq!(expired, 1),
            other => panic!("expected none, got {other:?}"),
        }
    }

    /// The refusal is the line the agent reads, verbatim.
    #[test]
    fn the_no_match_message_names_the_url_and_the_next_command() {
        let err = select_for_target(&[], "https://api.github.com/user").unwrap_err();
        assert_eq!(
            err.message("https://api.github.com/user"),
            "no credential is fenced for https://api.github.com/user; \
             run agentcordon credentials"
        );
    }

    /// The ambiguous refusal names every candidate and its fence.
    #[test]
    fn the_several_message_lists_names_and_fences() {
        let creds = [
            c("gh-read", Some("https://api.github.com/*")),
            c("gh-write", Some("https://api.github.com/repos/*")),
        ];
        let err = select_for_target(&creds, "https://api.github.com/repos/a/b").unwrap_err();
        let msg = err.message("https://api.github.com/repos/a/b");
        assert!(msg.contains("gh-read  https://api.github.com/*"), "{msg}");
        assert!(
            msg.contains("gh-write  https://api.github.com/repos/*"),
            "{msg}"
        );
        assert!(msg.contains("name one"), "{msg}");
    }

    /// An unfenced candidate is reported as unfenced in the ambiguity list,
    /// so the agent is not told a `*` credential has a fence.
    #[test]
    fn unfenced_candidates_are_reported_as_unfenced() {
        let creds = [c("a", None), c("b", None)];
        let err = select_for_target(&creds, "https://api.github.com/u").unwrap_err();
        let msg = err.message("https://api.github.com/u");
        assert!(msg.contains(UNRESTRICTED), "{msg}");
    }
}
