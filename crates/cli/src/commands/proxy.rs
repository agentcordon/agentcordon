use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::broker::BrokerClient;
use crate::commands::credentials;
use crate::error::{self, CliError};

#[derive(Serialize)]
struct ProxyRequest {
    method: String,
    url: String,
    credential: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Deserialize)]
struct ProxyResponse {
    data: ProxyData,
}

#[derive(Deserialize)]
struct ProxyData {
    status_code: u16,
    /// `[name, value]` pairs in arrival order; a repeated header (Set-Cookie,
    /// Link) is one entry per value.
    headers: Vec<(String, String)>,
    body: serde_json::Value,
}

/// What `agentcordon proxy` was asked to do.
pub struct ProxyArgs {
    /// `[CREDENTIAL, METHOD, URL]`, or `[METHOD, URL]` when `auto` is set.
    pub args: Vec<String>,
    pub auto: bool,
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub json: bool,
    pub raw: bool,
}

/// The three things a proxied call needs, however they were spelled.
struct Target {
    credential: Option<String>,
    method: String,
    url: String,
}

/// Split the positional arguments according to `--auto`.
///
/// Clap cannot express "three positionals, unless this flag, then two", so
/// the arity is checked here — and reported as the command the caller
/// should have typed rather than as a clap usage string.
fn parse_target(args: &[String], auto: bool) -> Result<Target, CliError> {
    match (auto, args) {
        (true, [method, url]) => Ok(Target {
            credential: None,
            method: method.clone(),
            url: url.clone(),
        }),
        (false, [credential, method, url]) => Ok(Target {
            credential: Some(credential.clone()),
            method: method.clone(),
            url: url.clone(),
        }),
        (true, _) => Err(CliError::general(
            "usage: agentcordon proxy --auto <METHOD> <URL>",
        )),
        (false, _) => Err(CliError::general(
            "usage: agentcordon proxy <CREDENTIAL> <METHOD> <URL> \
             (or: agentcordon proxy --auto <METHOD> <URL>)",
        )),
    }
}

/// Proxy an HTTP request through the broker with credential injection.
pub async fn run(args: ProxyArgs) -> Result<(), CliError> {
    let ProxyArgs {
        args: positional,
        auto,
        headers: extra_headers,
        body,
        json: json_output,
        raw: raw_output,
    } = args;
    let target = parse_target(&positional, auto)?;
    let (method, url) = (target.method, target.url);

    let client = BrokerClient::connect().await?;

    // With `--auto` the credential is chosen from the listing the broker
    // already holds, structurally, before anything is vended. One extra
    // request, no extra round trip to the server (the broker caches it).
    let credential = match target.credential {
        Some(name) => name,
        None => {
            let creds = credentials::fetch(&client).await?;
            let chosen = credentials::select_for_target(&creds, &url)
                .map_err(|e| CliError::no_credential_match(e.message(&url)))?;
            if chosen.fence().is_none() {
                eprintln!(
                    "Note: '{}' is not fenced ({}); no fenced credential covers {url}.",
                    chosen.name,
                    credentials::UNRESTRICTED
                );
            }
            chosen.name.clone()
        }
    };

    // Parse extra headers
    let mut headers = HashMap::new();
    for h in &extra_headers {
        let (key, value) = h.split_once(':').ok_or_else(|| {
            CliError::general(format!("invalid header format: {h} (expected KEY:VALUE)"))
        })?;
        headers.insert(key.trim().to_string(), value.trim().to_string());
    }

    // Handle @file body
    let body =
        match body {
            Some(b) if b.starts_with('@') => {
                let path = &b[1..];
                Some(std::fs::read_to_string(path).map_err(|e| {
                    CliError::general(format!("failed to read body file {path}: {e}"))
                })?)
            }
            other => other,
        };

    let req = ProxyRequest {
        method: method.to_uppercase(),
        url,
        credential,
        headers,
        body,
    };

    let (status, body_text) = client.post_raw("/proxy", &req).await?;
    if !(200..300).contains(&status) {
        return Err(render_broker_error(status, &body_text));
    }

    let resp: ProxyResponse = serde_json::from_str(&body_text)
        .map_err(|e| CliError::general(format!("invalid proxy response: {e}")))?;
    let data = resp.data;
    let body_str = match &data.body {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    };

    if raw_output {
        print!("{body_str}");
        return Ok(());
    }

    if json_output {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        println!(
            "{}",
            serde_json::to_string_pretty(&data.body).unwrap_or(body_str)
        );
    } else {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        println!("{body_str}");
    }

    if data.status_code >= 400 {
        return Err(CliError::upstream_error(format!(
            "upstream returned HTTP {}",
            data.status_code
        )));
    }

    Ok(())
}

/// The error `main` prints for a broker refusal, as the one line
/// `docs/cli-reference.md` documents for this command:
/// `Error: <message> (<code>)`.
///
/// The rendering is here rather than at the call site because the command
/// used to print that line itself and *also* return an error for `main` to
/// print, so every refusal arrived as two lines, the second one restating
/// the HTTP status as if it were a separate failure. Returning the finished
/// message leaves exactly one printer.
///
/// The exit code comes from `error::exit_code_for`, the same classifier
/// `mcp-call` uses, so one broker refusal has one exit code whichever
/// command met it. Any helpful fields the envelope carries (the
/// `candidates` list on an ambiguous credential name) are appended to the
/// message so they stay attached to the error.
fn render_broker_error(status: u16, body_text: &str) -> CliError {
    let fallback = || CliError::general(format!("broker returned HTTP {status}: {body_text}"));
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return fallback();
    };
    let Some(err) = parsed.get("error") else {
        return fallback();
    };
    let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("error");
    let message = err
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("request failed");

    let mut rendered = format!("{message} ({code})");
    if let Some(candidates) = err.get("candidates").and_then(|c| c.as_array()) {
        if !candidates.is_empty() {
            rendered.push_str("\n\nHint: multiple credentials match. Use one of these IDs:");
            for cand in candidates {
                let name = cand
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("(unknown)");
                let id = cand
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("(unknown)");
                rendered.push_str(&format!("\n  {id}  {name}"));
            }
        }
    }

    CliError {
        code: error::exit_code_for(status, code, message),
        message: rendered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ExitCode;

    fn envelope(code: &str, message: &str) -> String {
        serde_json::json!({ "error": { "code": code, "message": message } }).to_string()
    }

    /// `docs/cli-reference.md § agentcordon proxy → Error output` documents
    /// exactly one line, `Error: <message> (<code>)`. The command printed
    /// that line itself and then returned a second error, which `main` also
    /// printed, so every refusal came back as two lines and the second one
    /// restated a transport detail as if it were a separate failure.
    #[test]
    fn a_broker_refusal_renders_as_the_one_documented_line() {
        let err = render_broker_error(
            403,
            &envelope(
                "url_pattern_denied",
                "credential 'ws-oauth' is fenced to the URL pattern https://api.example.com/*",
            ),
        );

        assert_eq!(
            err.message,
            "credential 'ws-oauth' is fenced to the URL pattern https://api.example.com/* (url_pattern_denied)"
        );
        assert!(
            !err.message.contains("broker returned HTTP"),
            "the transport detail is not a second failure: {}",
            err.message
        );
        assert_eq!(err.code, ExitCode::AuthorizationDenied);
    }

    /// The SSRF guard refuses the target before anything is proxied, so
    /// `proxy` must not report it as an upstream error — and must agree with
    /// `mcp-call`, which classifies the same refusal through
    /// `from_broker_error`.
    #[test]
    fn an_ssrf_refusal_exits_the_same_way_as_mcp_call() {
        let message = "Blocked by SSRF protection: 127.0.0.1 is a loopback address";
        let from_proxy = render_broker_error(400, &envelope("bad_request", message));
        let from_mcp = crate::error::from_broker_error(
            400,
            "ssrf_blocked",
            "Blocked by SSRF protection: MCP server 'echo': 127.0.0.1 is a loopback address",
        );

        assert_eq!(
            from_proxy.code, from_mcp.code,
            "one guard, one exit code, whichever command hit it"
        );
        assert_eq!(from_proxy.code, ExitCode::GeneralError);
        assert_eq!(from_proxy.message, format!("{message} (bad_request)"));
    }

    /// An ambiguous credential name still gets its hint, on the same error.
    #[test]
    fn ambiguous_credential_candidates_are_listed_under_the_error() {
        let body = serde_json::json!({
            "error": {
                "code": "ambiguous_credential",
                "message": "two credentials are named 'shared'",
                "candidates": [
                    { "id": "cred-a", "name": "shared" },
                    { "id": "cred-b", "name": "shared" },
                ],
            }
        })
        .to_string();

        let err = render_broker_error(300, &body);

        assert!(err
            .message
            .starts_with("two credentials are named 'shared' (ambiguous_credential)"));
        assert!(err.message.contains("cred-a  shared"), "{}", err.message);
        assert!(err.message.contains("cred-b  shared"), "{}", err.message);
    }

    /// A body that is not the broker's envelope has nothing to render, so the
    /// status and the raw body are all the user gets.
    #[test]
    fn a_body_that_is_not_an_error_envelope_falls_back_to_the_status() {
        let err = render_broker_error(502, "<html>bad gateway</html>");

        assert_eq!(
            err.message,
            "broker returned HTTP 502: <html>bad gateway</html>"
        );
        assert_eq!(err.code, ExitCode::GeneralError);
    }
}
