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
pub(crate) struct ProxyData {
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
    /// `--header K:V`, repeatable: extra request headers.
    pub headers: Vec<String>,
    pub body: Option<String>,
    pub json: bool,
    pub raw: bool,
    /// `--headers`: print the status line and every response header on
    /// stdout, above the body.
    pub show_headers: bool,
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

/// One proxied call's answer: the credential that was actually used, the note
/// the caller has to be told about that choice, and the broker's data.
///
/// The note is a return value rather than a `eprintln!` because the two
/// callers show it in different places. `agentcordon proxy` prints it to
/// stderr, where a human reading a terminal sees it. `mcp-serve`'s
/// `agentcordon_proxy` speaks JSON-RPC over stdio to a model that never sees
/// stderr at all, so for it the note has to be in the tool result — otherwise
/// the one case where AgentCordon reached past a fence is the one case the
/// caller cannot learn about.
pub(crate) struct ProxyOutcome {
    pub credential: String,
    /// Set when no credential was named and the one chosen carries no URL
    /// fence, so nothing constrained where it could be sent.
    pub unfenced_note: Option<String>,
    pub data: ProxyData,
}

/// One proxied call, from choosing the credential to the broker's answer.
///
/// `agentcordon proxy` and `mcp-serve`'s `agentcordon_proxy` are the same
/// call under two names, so they share this: one selector, one request
/// shape, one rendering of a refusal.
pub(crate) async fn execute(
    client: &BrokerClient,
    credential: Option<String>,
    method: &str,
    url: &str,
    headers: HashMap<String, String>,
    body: Option<String>,
) -> Result<ProxyOutcome, CliError> {
    // With no credential named, one is chosen from the listing the broker
    // already holds, structurally, before anything is vended. One extra
    // request, no extra round trip to the server (the broker caches it).
    let mut unfenced_note = None;
    let credential = match credential {
        Some(name) => name,
        None => {
            let creds = credentials::fetch(client).await?;
            let chosen = credentials::select_for_target(&creds, url)
                .map_err(|e| CliError::no_credential_match(e.message(url)))?;
            if chosen.fence().is_none() {
                unfenced_note = Some(format!(
                    "Note: '{}' is not fenced ({}); no fenced credential covers {url}.",
                    chosen.name,
                    credentials::UNRESTRICTED
                ));
            }
            chosen.name.clone()
        }
    };

    let req = ProxyRequest {
        method: method.to_uppercase(),
        url: url.to_string(),
        credential: credential.clone(),
        headers,
        body,
    };

    let (status, body_text) = client.post_raw("/proxy", &req).await?;
    if !(200..300).contains(&status) {
        return Err(render_broker_error(status, &body_text));
    }

    let resp: ProxyResponse = serde_json::from_str(&body_text)
        .map_err(|e| CliError::general(format!("invalid proxy response: {e}")))?;
    Ok(ProxyOutcome {
        credential,
        unfenced_note,
        data: resp.data,
    })
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
        show_headers: headers_output,
    } = args;
    let target = parse_target(&positional, auto)?;
    let (method, url) = (target.method, target.url);

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

    let client = BrokerClient::connect().await?;
    let outcome = execute(&client, target.credential, &method, &url, headers, body).await?;
    let ProxyOutcome {
        credential,
        unfenced_note,
        data,
    } = outcome;
    // Straight to stderr: a human reading the terminal is who this is for,
    // and stdout carries only the body the caller asked for.
    if let Some(note) = &unfenced_note {
        eprintln!("{note}");
    }
    let body = body_bytes(&data);

    // Exactly one of these writes to stdout, and each writes only what it
    // promises: an agent that pipes `proxy` into a parser must not have to
    // strip a status line, and one that reads the terminal must not have to
    // scroll past headers it did not ask for.
    if json_output {
        println!("{}", json_envelope(&data));
    } else if headers_output {
        println!("HTTP {}", data.status_code);
        for (k, v) in &data.headers {
            println!("{k}: {v}");
        }
        println!();
        print!("{body}");
        finish_body();
    } else {
        // The summary goes first and to stderr, so the body it describes is
        // the last thing on the terminal and the only thing on stdout.
        if !raw_output {
            eprintln!(
                "{}",
                summary_line(
                    data.status_code,
                    body.len(),
                    content_type_of(&data),
                    auto.then_some(credential.as_str()),
                )
            );
        }
        print!("{body}");
        finish_body();
    }

    if data.status_code >= 400 {
        return Err(CliError::upstream_error(format!(
            "upstream returned HTTP {}",
            data.status_code
        )));
    }

    Ok(())
}

/// The response body exactly as the upstream sent it.
///
/// The broker parses a JSON body into a `Value` on the way through, so a
/// JSON body is re-rendered compactly here; anything else crossed as a
/// string and is returned unchanged. Nothing is appended: `proxy` writes
/// the body and only the body to stdout.
fn body_bytes(data: &ProxyData) -> String {
    match &data.body {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// Nothing is appended to the body — not even a newline the upstream did
/// not send — so `proxy | sha256sum` and `proxy --raw | sha256sum` agree
/// with the upstream. `print!` does not flush on its own, and the process
/// exits through `ExitCode`, so the flush is explicit.
fn finish_body() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// The response's content type, matched the way HTTP names are.
fn content_type_of(data: &ProxyData) -> Option<&str> {
    data.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
}

/// The one line `proxy` writes to stderr: everything about the response
/// that is not the body.
///
/// One line because it is read by an agent that pays for every token, and
/// on stderr because stdout belongs to the body. `via` names the credential
/// when `--auto` chose it — the only place that choice is visible.
fn summary_line(
    status: u16,
    body_len: usize,
    content_type: Option<&str>,
    via: Option<&str>,
) -> String {
    let mut parts = vec![format!("HTTP {status}"), human_size(body_len)];
    if let Some(ct) = content_type {
        parts.push(format!("content-type: {ct}"));
    }
    if let Some(name) = via {
        parts.push(format!("via {name}"));
    }
    parts.join(" \u{b7} ")
}

/// A byte count at human scale, one decimal from a kilobyte up.
fn human_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / MB)
    }
}

/// True for a content type whose body is JSON, so `--json` can nest it
/// instead of quoting it.
fn is_json_content_type(ct: &str) -> bool {
    let essence = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

/// The whole response as one compact object: `{status, headers, body}`.
///
/// `headers` maps a name to its value, or to the array of its values when
/// the same name arrived more than once (`Set-Cookie`, `Link`) — a repeat
/// must not silently disappear. `body` is the parsed JSON when the content
/// type says JSON, and a string otherwise: the content type decides, not
/// the shape, so a `text/plain` body that happens to look like JSON stays
/// text.
pub(crate) fn json_envelope(data: &ProxyData) -> serde_json::Value {
    let mut headers = serde_json::Map::new();
    for (name, value) in &data.headers {
        let value = serde_json::Value::String(value.clone());
        match headers.remove(name) {
            None => {
                headers.insert(name.clone(), value);
            }
            Some(serde_json::Value::Array(mut existing)) => {
                existing.push(value);
                headers.insert(name.clone(), serde_json::Value::Array(existing));
            }
            Some(first) => {
                headers.insert(name.clone(), serde_json::Value::Array(vec![first, value]));
            }
        }
    }

    let json_body = content_type_of(data).is_some_and(is_json_content_type);
    let body = if json_body {
        data.body.clone()
    } else {
        serde_json::Value::String(body_bytes(data))
    };

    serde_json::json!({
        "status": data.status_code,
        "headers": serde_json::Value::Object(headers),
        "body": body,
    })
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

    fn data(status: u16, headers: &[(&str, &str)], body: serde_json::Value) -> ProxyData {
        ProxyData {
            status_code: status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body,
        }
    }

    // -- the one stderr line ----------------------------------------------

    /// What an agent reads when it does not ask for more: status, size,
    /// content type, on one line.
    #[test]
    fn the_summary_is_one_line_with_status_size_and_content_type() {
        assert_eq!(
            summary_line(200, 1229, Some("application/json"), None),
            "HTTP 200 \u{b7} 1.2 KB \u{b7} content-type: application/json"
        );
    }

    /// `--auto` chose the credential, so the line says which one — that is
    /// the only place the choice is visible.
    #[test]
    fn an_auto_selected_credential_is_named_in_the_summary() {
        assert_eq!(
            summary_line(200, 27, Some("application/json"), Some("internal-api")),
            "HTTP 200 \u{b7} 27 B \u{b7} content-type: application/json \u{b7} via internal-api"
        );
    }

    /// A response with no content type says nothing about one rather than
    /// inventing a segment.
    #[test]
    fn a_response_without_a_content_type_omits_that_segment() {
        assert_eq!(summary_line(204, 0, None, None), "HTTP 204 \u{b7} 0 B");
    }

    #[test]
    fn sizes_are_human_scale() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1229), "1.2 KB");
        assert_eq!(human_size(3_500_000), "3.3 MB");
    }

    /// The content type is read case-insensitively, the way HTTP names are.
    #[test]
    fn the_content_type_header_is_found_whatever_its_case() {
        let d = data(
            200,
            &[("Content-Type", "text/plain")],
            serde_json::json!("x"),
        );
        assert_eq!(content_type_of(&d), Some("text/plain"));
    }

    // -- --json -----------------------------------------------------------

    /// One compact object, so an agent can pipe it straight into `jq`.
    #[test]
    fn json_output_is_one_object_of_status_headers_and_body() {
        let d = data(
            201,
            &[("content-type", "application/json")],
            serde_json::json!({"id": 7}),
        );
        let rendered = json_envelope(&d);
        assert_eq!(rendered["status"], 201);
        assert_eq!(rendered["headers"]["content-type"], "application/json");
        assert_eq!(
            rendered["body"],
            serde_json::json!({"id": 7}),
            "a JSON content type keeps the body parsed"
        );
    }

    /// A non-JSON body is a string, not a guess at structure.
    #[test]
    fn a_non_json_body_is_a_string_in_json_output() {
        let d = data(
            200,
            &[("content-type", "text/plain")],
            serde_json::json!("hello"),
        );
        assert_eq!(json_envelope(&d)["body"], serde_json::json!("hello"));
    }

    /// A body that parses as JSON but arrived as `text/plain` is still a
    /// string: the content type decides, not the shape.
    #[test]
    fn the_content_type_decides_whether_the_body_is_parsed() {
        let d = data(
            200,
            &[("content-type", "text/plain")],
            serde_json::json!({"looks": "json"}),
        );
        assert!(
            json_envelope(&d)["body"].is_string(),
            "text/plain is text, whatever it contains"
        );
    }

    /// A header that arrives twice keeps both values instead of one
    /// silently winning.
    #[test]
    fn a_repeated_header_becomes_an_array() {
        let d = data(
            200,
            &[("set-cookie", "a=1"), ("set-cookie", "b=2")],
            serde_json::json!("x"),
        );
        assert_eq!(
            json_envelope(&d)["headers"]["set-cookie"],
            serde_json::json!(["a=1", "b=2"])
        );
    }

    // -- the body on stdout ----------------------------------------------

    /// The default and `--raw` put the same bytes on stdout: the body, and
    /// nothing else.
    #[test]
    fn the_body_bytes_are_what_the_upstream_sent() {
        let d = data(
            200,
            &[("content-type", "application/json")],
            serde_json::json!({"ok": true}),
        );
        assert_eq!(body_bytes(&d), r#"{"ok":true}"#);

        let text = data(200, &[], serde_json::json!("plain text"));
        assert_eq!(body_bytes(&text), "plain text");
    }

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
