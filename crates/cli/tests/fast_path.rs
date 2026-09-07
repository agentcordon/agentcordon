//! The agent fast path, at the CLI's own seam: the real `agentcordon`
//! binary against a stub broker on loopback.
//!
//! `proxy --auto` is the one command an agent runs without having read a
//! listing first, so what has to hold is that it makes **one** proxied call,
//! naming the credential its fence chose — not that it probed, retried, or
//! fell back to the first credential it saw. The stub records every request,
//! which is the only way to observe that from outside the process.
//!
//! The selector's rules are unit-tested in `commands::credentials`; this is
//! the wiring around them.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// One request the stub broker answered.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    body: String,
}

#[derive(Default)]
struct Log {
    requests: Vec<Recorded>,
}

/// A stub broker: enough of the broker's HTTP surface for the CLI to
/// discover it, list credentials, and proxy once.
struct StubBroker {
    port: u16,
    log: Arc<Mutex<Log>>,
}

impl StubBroker {
    /// Start on an ephemeral loopback port, answering `/credentials` with
    /// `listing` and every `/proxy` with a fixed 200.
    fn start(listing: serde_json::Value) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let log = Arc::new(Mutex::new(Log::default()));
        let thread_log = log.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            ready_tx.send(()).ok();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let log = thread_log.clone();
                let listing = listing.clone();
                std::thread::spawn(move || serve(stream, listing, log));
            }
        });
        ready_rx.recv().expect("listener thread started");
        Self { port, log }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn requests_to(&self, path: &str) -> Vec<Recorded> {
        self.log
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }
}

/// A whole connection: HTTP/1.1 keep-alive, one request at a time.
fn serve(stream: TcpStream, listing: serde_json::Value, log: Arc<Mutex<Log>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut out = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
            return;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();

        let mut content_length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            return;
        }
        let body = String::from_utf8_lossy(&body).to_string();

        log.lock().unwrap().requests.push(Recorded {
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
        });

        let payload = match (method.as_str(), path.as_str()) {
            ("GET", "/health") => serde_json::json!({
                "status": "ok",
                // 64 hex characters: what the CLI pins.
                "key_fingerprint": STUB_FINGERPRINT,
                "version": "0.0.0-test",
            }),
            ("GET", "/credentials") => listing.clone(),
            ("POST", "/proxy") => serde_json::json!({
                "data": {
                    "status_code": 200,
                    "headers": [["content-type", "application/json"]],
                    "body": {"ok": true},
                }
            }),
            _ => serde_json::json!({
                "error": {"code": "not_found", "message": "no such stub route"}
            }),
        };
        let rendered = payload.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            rendered.len(),
            rendered
        );
        if out.write_all(response.as_bytes()).is_err() {
            return;
        }
        let _ = out.flush();
    }
}

/// A credential as the broker lists it.
fn cred(name: &str, pattern: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "id": format!("id-{name}"),
        "name": name,
        "service": "internal",
        "credential_type": "generic",
        "scopes": [],
        "allowed_url_pattern": pattern,
        "expires_at": null,
        "expired": false,
        "vault": "default",
    })
}

fn listing(creds: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({ "data": creds })
}

/// The fingerprint the stub publishes on `/health`.
const STUB_FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A workspace directory with a key the CLI can sign with, already pinned
/// to the stub's key — a first-use pin writes a notice to stderr, and these
/// tests are about what `proxy` itself writes there.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let ws = dir.path().join(".agentcordon");
    agentcordon_identity::create_workspace_key(&ws).expect("create key");
    std::fs::write(ws.join("broker.fingerprint"), STUB_FINGERPRINT).expect("pin");
    dir
}

fn run_cli(broker: &StubBroker, dir: &tempfile::TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentcordon"))
        .args(args)
        .env("AGTCRDN_BROKER_URL", broker.url())
        .env("AGTCRDN_WORKSPACE_DIR", dir.path())
        .env("HOME", dir.path())
        .output()
        .expect("run agentcordon")
}

/// The whole point of `--auto`: one command, one proxied call, and the
/// credential named in it is the one whose fence covers the URL.
#[test]
fn auto_makes_exactly_one_proxy_call_naming_the_chosen_credential() {
    let broker = StubBroker::start(listing(vec![
        cred("wrong-host", Some("https://api.github.com/*")),
        cred("right-one", Some("http://127.0.0.1:9/*")),
        cred("unfenced", None),
    ]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "--auto", "GET", "http://127.0.0.1:9/echo"],
    );
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let proxied = broker.requests_to("/proxy");
    assert_eq!(
        proxied.len(),
        1,
        "one call, not a probe-then-call: {proxied:?}"
    );
    assert_eq!(proxied[0].method, "POST");
    let sent: serde_json::Value = serde_json::from_str(&proxied[0].body).expect("json body");
    assert_eq!(sent["credential"], "right-one");
    assert_eq!(sent["url"], "http://127.0.0.1:9/echo");
    assert_eq!(sent["method"], "GET");

    assert_eq!(
        broker.requests_to("/credentials").len(),
        1,
        "the listing is fetched once per process"
    );
}

/// Naming a credential still skips the listing entirely — `--auto` costs a
/// request, so the form that does not need it must not pay for it.
#[test]
fn naming_a_credential_does_not_fetch_the_listing() {
    let broker = StubBroker::start(listing(vec![cred("named", Some("http://127.0.0.1:9/*"))]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "named", "GET", "http://127.0.0.1:9/echo"],
    );
    assert!(out.status.success(), "{:?}", out);
    assert!(broker.requests_to("/credentials").is_empty());
    assert_eq!(broker.requests_to("/proxy").len(), 1);
}

/// Nothing fenced for the target is a refusal with its own exit code, and
/// the message names the URL and the command that lists the fences.
#[test]
fn no_fence_for_the_target_refuses_without_proxying() {
    let broker = StubBroker::start(listing(vec![cred(
        "github",
        Some("https://api.github.com/*"),
    )]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "--auto", "GET", "https://api.gitlab.com/user"],
    );
    assert_eq!(out.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no credential is fenced for https://api.gitlab.com/user"),
        "{stderr}"
    );
    assert!(stderr.contains("agentcordon credentials"), "{stderr}");
    assert!(
        broker.requests_to("/proxy").is_empty(),
        "nothing is vended when nothing was chosen"
    );
}

/// Two fences covering the target is a refusal that names both, so the next
/// command is obvious.
#[test]
fn several_fences_for_the_target_name_the_candidates() {
    let broker = StubBroker::start(listing(vec![
        cred("gh-read", Some("http://127.0.0.1:9/*")),
        cred("gh-write", Some("http://127.0.0.1:9/repos/*")),
    ]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "--auto", "GET", "http://127.0.0.1:9/repos/a"],
    );
    assert_eq!(out.status.code(), Some(7));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("gh-read"), "{stderr}");
    assert!(stderr.contains("gh-write"), "{stderr}");
    assert!(broker.requests_to("/proxy").is_empty());
}

/// Compact by default: stdout is the body and nothing else, and everything
/// about the response that is not the body is one line on stderr.
#[test]
fn the_default_output_is_the_body_on_stdout_and_one_line_on_stderr() {
    let broker = StubBroker::start(listing(vec![cred("only", Some("http://127.0.0.1:9/*"))]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "--auto", "GET", "http://127.0.0.1:9/echo"],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), r#"{"ok":true}"#);

    let stderr = String::from_utf8_lossy(&out.stderr);
    let summary: Vec<&str> = stderr.lines().filter(|l| l.starts_with("HTTP ")).collect();
    assert_eq!(
        summary,
        ["HTTP 200 \u{b7} 11 B \u{b7} content-type: application/json \u{b7} via only"],
        "one line, and it names the credential --auto chose: {stderr}"
    );
}

/// `--raw` is the byte-exact form: the body, and not even the summary.
#[test]
fn raw_prints_the_body_and_nothing_at_all_on_stderr() {
    let broker = StubBroker::start(listing(vec![cred("only", Some("http://127.0.0.1:9/*"))]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &["proxy", "--auto", "GET", "http://127.0.0.1:9/echo", "--raw"],
    );
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), r#"{"ok":true}"#);
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}

/// `--json` is one object on one line, so `proxy --json | jq` needs no
/// stripping.
#[test]
fn json_output_is_a_single_compact_object() {
    let broker = StubBroker::start(listing(vec![cred("only", Some("http://127.0.0.1:9/*"))]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &[
            "proxy",
            "--auto",
            "GET",
            "http://127.0.0.1:9/echo",
            "--json",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 1, "one line: {stdout}");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(parsed["status"], 200);
    assert_eq!(parsed["headers"]["content-type"], "application/json");
    assert_eq!(parsed["body"], serde_json::json!({"ok": true}));
}

/// `--headers` is the old shape, on stdout, for a human reading a response
/// whose headers matter (a 3xx `Location`, a rate-limit budget).
#[test]
fn headers_puts_the_status_line_and_headers_above_the_body() {
    let broker = StubBroker::start(listing(vec![cred("only", Some("http://127.0.0.1:9/*"))]));
    let dir = workspace();

    let out = run_cli(
        &broker,
        &dir,
        &[
            "proxy",
            "--auto",
            "GET",
            "http://127.0.0.1:9/echo",
            "--headers",
        ],
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("HTTP 200\ncontent-type: application/json\n\n"),
        "{stdout}"
    );
    assert!(stdout.ends_with(r#"{"ok":true}"#), "{stdout}");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "");
}
