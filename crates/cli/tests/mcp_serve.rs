//! `agentcordon mcp-serve` at the CLI's own seam: the real `agentcordon`
//! binary spawned with pipes, driven with newline-delimited JSON-RPC over
//! stdin/stdout, against a stub broker on loopback.
//!
//! The stub is the one from `tests/fast_path.rs` widened to the routes
//! `mcp-serve` needs (`/status`, `/credentials`, `/proxy`, `/mcp/*`) and made
//! settable mid-test, because the list-changed notification is only
//! observable when the broker's answer changes underneath a running server.
//! It records every request with its headers, which is the only way to
//! observe from outside the process that a tool call made exactly one signed
//! call and no more.
//!
//! Protocol: MCP 2025-06-18 (`basic/transports` § stdio, `server/tools`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// The stub broker
// ---------------------------------------------------------------------------

/// One request the stub answered.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    body: String,
    headers: HashMap<String, String>,
}

impl Recorded {
    /// The four headers `agentcordon-identity` signs a broker request with.
    fn is_signed(&self) -> bool {
        [
            "x-ac-publickey",
            "x-ac-timestamp",
            "x-ac-nonce",
            "x-ac-signature",
        ]
        .iter()
        .all(|h| self.headers.contains_key(*h))
    }
}

/// What the stub answers with, replaceable while the server is running.
#[derive(Clone)]
struct Answers {
    status: Value,
    credentials: Value,
    proxy: Value,
    servers: Value,
    tools: Value,
    call: Value,
    /// When set, every route but `/health` answers with this status and
    /// error envelope instead of its normal body: a broker that refuses.
    refusal: Option<(u16, Value)>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            status: json!({"data": {
                "registered": true,
                "scopes": ["credentials:discover", "credentials:vend"],
                "token_expires_at": "2099-01-01T00:00:00Z",
                "token_status": "valid",
                "server_url": "http://cordon.example.test",
            }}),
            credentials: json!({"data": []}),
            proxy: json!({"data": {
                "status_code": 200,
                "headers": [["content-type", "application/json"]],
                "body": {"ok": true},
            }}),
            servers: json!({"data": []}),
            tools: json!({"data": []}),
            call: json!({"data": {
                "content": [{"type": "text", "text": "done"}],
                "isError": false,
                "correlation_id": "corr-1",
            }}),
            refusal: None,
        }
    }
}

struct StubBroker {
    port: u16,
    answers: Arc<Mutex<Answers>>,
    log: Arc<Mutex<Vec<Recorded>>>,
}

impl StubBroker {
    fn start() -> Self {
        Self::with(Answers::default())
    }

    fn with(answers: Answers) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let answers = Arc::new(Mutex::new(answers));
        let log: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let thread_answers = answers.clone();
        let thread_log = log.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            ready_tx.send(()).ok();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let answers = thread_answers.clone();
                let log = thread_log.clone();
                std::thread::spawn(move || serve(stream, answers, log));
            }
        });
        ready_rx.recv().expect("listener thread started");
        Self { port, answers, log }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn set<F: FnOnce(&mut Answers)>(&self, f: F) {
        f(&mut self.answers.lock().unwrap());
    }

    fn requests_to(&self, path: &str) -> Vec<Recorded> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }
}

/// The fingerprint the stub publishes on `/health`, pinned by `workspace()`.
const STUB_FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn serve(stream: TcpStream, answers: Arc<Mutex<Answers>>, log: Arc<Mutex<Vec<Recorded>>>) {
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
        let mut headers = HashMap::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                let name = name.trim().to_ascii_lowercase();
                if name == "content-length" {
                    content_length = value.trim().parse().unwrap_or(0);
                }
                headers.insert(name, value.trim().to_string());
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 && reader.read_exact(&mut body).is_err() {
            return;
        }
        let body = String::from_utf8_lossy(&body).to_string();

        log.lock().unwrap().push(Recorded {
            method: method.clone(),
            path: path.clone(),
            body,
            headers,
        });

        let answers = answers.lock().unwrap().clone();
        let (status, payload) = match (method.as_str(), path.as_str()) {
            ("GET", "/health") => (
                200,
                json!({
                    "status": "ok",
                    "key_fingerprint": STUB_FINGERPRINT,
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            ),
            _ => match &answers.refusal {
                Some((status, envelope)) => (*status, envelope.clone()),
                None => match (method.as_str(), path.as_str()) {
                    ("GET", "/status") => (200, answers.status.clone()),
                    ("GET", "/credentials") => (200, answers.credentials.clone()),
                    ("POST", "/proxy") => (200, answers.proxy.clone()),
                    ("POST", "/mcp/list-servers") => (200, answers.servers.clone()),
                    ("POST", "/mcp/list-tools") => (200, answers.tools.clone()),
                    ("POST", "/mcp/call") => (200, answers.call.clone()),
                    _ => (
                        404,
                        json!({"error": {"code": "not_found", "message": "no such stub route"}}),
                    ),
                },
            },
        };

        let rendered = payload.to_string();
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            rendered.len(),
            rendered
        );
        if out.write_all(response.as_bytes()).is_err() {
            return;
        }
        let _ = out.flush();
    }
}

// ---------------------------------------------------------------------------
// The server under test
// ---------------------------------------------------------------------------

/// A workspace directory with a key the CLI can sign with, already pinned to
/// the stub's key so nothing writes a first-use notice.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("cordoned-workspace")
        .tempdir()
        .expect("tempdir");
    let ws = dir.path().join(".agentcordon");
    agentcordon_identity::create_workspace_key(&ws).expect("create key");
    std::fs::write(ws.join("broker.fingerprint"), STUB_FINGERPRINT).expect("pin");
    dir
}

/// A spawned `agentcordon mcp-serve`, driven over its pipes.
struct Serve {
    child: Child,
    stdin: Option<ChildStdin>,
    out: BufReader<ChildStdout>,
    /// Messages read while waiting for a response: notifications, and any
    /// response that arrived out of order.
    seen: Vec<Value>,
}

impl Serve {
    /// Spawn against a broker URL, with the extra `mcp-serve` arguments.
    fn start(broker_url: &str, dir: &tempfile::TempDir, args: &[&str]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentcordon"));
        cmd.arg("mcp-serve")
            .args(args)
            .env("AGTCRDN_BROKER_URL", broker_url)
            .env("AGTCRDN_WORKSPACE_DIR", dir.path())
            .env("HOME", dir.path())
            .env_remove("AGTCRDN_SERVER_URL")
            .env_remove("AGTCRDN_BROKER_SHARED_SECRET")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().expect("spawn agentcordon mcp-serve");
        let stdin = child.stdin.take().expect("stdin");
        let out = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin: Some(stdin),
            out,
            seen: Vec::new(),
        }
    }

    fn send(&mut self, message: &Value) {
        let line = serde_json::to_string(message).expect("serialise");
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(line.as_bytes()).expect("write");
        stdin.write_all(b"\n").expect("write newline");
        stdin.flush().expect("flush");
    }

    /// One message off stdout. Panics on EOF, because every caller is waiting
    /// for something the server promised to send.
    fn read_message(&mut self) -> Value {
        let mut line = String::new();
        let read = self.out.read_line(&mut line).expect("read stdout");
        assert!(read > 0, "server closed stdout while a reply was expected");
        assert!(
            line.ends_with('\n'),
            "messages are newline-delimited: {line:?}"
        );
        assert_eq!(
            line.trim_end_matches('\n').matches('\n').count(),
            0,
            "a message must not contain an embedded newline: {line:?}"
        );
        serde_json::from_str(line.trim_end()).unwrap_or_else(|e| {
            panic!("stdout carried something that is not JSON-RPC: {line:?} ({e})")
        })
    }

    /// Send a request and read until its response arrives, keeping anything
    /// else that turned up (notifications) in `seen`.
    fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let message = self.read_message();
            if message.get("id") == Some(&json!(id)) {
                assert_eq!(message["jsonrpc"], "2.0");
                return message;
            }
            self.seen.push(message);
        }
    }

    /// The result of a successful request, or a panic naming the error.
    fn ok(&mut self, id: i64, method: &str, params: Value) -> Value {
        let message = self.request(id, method, params);
        assert!(
            message.get("error").is_none(),
            "{method} failed: {}",
            message["error"]
        );
        message["result"].clone()
    }

    /// Call one tool and return its result object.
    fn call_tool(&mut self, id: i64, name: &str, arguments: Value) -> Value {
        self.ok(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
    }

    /// The single text block of a tool result.
    fn text_of(result: &Value) -> String {
        let content = result["content"].as_array().expect("content is an array");
        content
            .iter()
            .map(|b| b["text"].as_str().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn initialize(&mut self) -> Value {
        let result = self.ok(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-harness", "version": "0"},
            }),
        );
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        result
    }

    fn notifications(&self) -> Vec<&Value> {
        self.seen
            .iter()
            .filter(|m| m.get("id").is_none() && m.get("method").is_some())
            .collect()
    }

    /// Close stdin and wait: the server shuts down on EOF.
    fn shutdown(mut self) -> std::process::ExitStatus {
        self.stdin.take();
        self.child.wait().expect("wait for mcp-serve")
    }
}

/// A loopback port with nothing listening on it: the broker being down.
fn dead_broker_url() -> String {
    let socket = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    format!("http://127.0.0.1:{port}")
}

/// The six tools that are always listed, whatever the workspace holds.
const FIXED_TOOLS: [&str; 6] = [
    "agentcordon_status",
    "agentcordon_credentials",
    "agentcordon_proxy",
    "agentcordon_mcp_servers",
    "agentcordon_mcp_tools",
    "agentcordon_mcp_call",
];

fn tool_names(list: &Value) -> Vec<String> {
    list["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .map(|t| t["name"].as_str().expect("a tool has a name").to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Slice 1 — initialize, ping, tools/list, with the broker down
// ---------------------------------------------------------------------------

/// A runtime starts its MCP servers when the session opens, long before
/// anyone runs a broker. `initialize` describes the workspace from the files
/// in `.agentcordon/` and never touches the network, so a down broker costs
/// the session nothing but the tools it would have called.
#[test]
fn initialize_answers_with_the_broker_down() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);

    let result = serve.initialize();

    assert_eq!(result["protocolVersion"], "2025-06-18");
    assert_eq!(result["serverInfo"]["name"], "agentcordon");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        result["capabilities"]["tools"]["listChanged"],
        json!(true),
        "the tool list changes when an exposed server's tools do"
    );

    let instructions = result["instructions"].as_str().expect("instructions");
    let identity = {
        let key = agentcordon_identity::load_workspace_key(&dir.path().join(".agentcordon"))
            .expect("key");
        key.identity()
    };
    let name = dir
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    assert!(
        instructions.contains(&identity),
        "the instructions name the workspace identity: {instructions}"
    );
    assert!(
        instructions.contains(&name),
        "the instructions name the workspace: {instructions}"
    );
    assert!(
        instructions.contains("agentcordon_proxy"),
        "the instructions name the tool that makes an authenticated call: {instructions}"
    );
    assert!(
        instructions.contains("fence"),
        "the instructions say how a credential is chosen: {instructions}"
    );
    assert!(
        instructions.contains("not interchangeable"),
        "the instructions say MCP servers are not interchangeable: {instructions}"
    );

    assert!(serve.shutdown().success());
}

/// The keepalive every client uses. An empty result, and it must not need a
/// broker either.
#[test]
fn ping_answers_an_empty_result() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();

    let result = serve.ok(2, "ping", json!({}));
    assert_eq!(result, json!({}));

    assert!(serve.shutdown().success());
}

/// Without `--expose` the surface is fixed: six tools, whatever the broker
/// holds, so a session's context cost is the same for a workspace with one
/// upstream and one with twenty.
#[test]
fn tools_list_is_exactly_the_six_fixed_tools_with_the_broker_down() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();

    let list = serve.ok(2, "tools/list", json!({}));
    assert_eq!(tool_names(&list), FIXED_TOOLS);

    for tool in list["tools"].as_array().unwrap() {
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "every tool is described: {tool}"
        );
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "every tool has an object input schema: {tool}"
        );
    }

    assert!(serve.shutdown().success());
}

/// The argument shapes a runtime shows the model, frozen: they are the
/// documented interface of this server.
#[test]
fn the_fixed_tools_declare_their_arguments() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();

    let list = serve.ok(2, "tools/list", json!({}));
    let by_name: HashMap<&str, &Value> = list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["name"].as_str().unwrap(), t))
        .collect();

    let proxy = &by_name["agentcordon_proxy"]["inputSchema"];
    assert_eq!(proxy["required"], json!(["method", "url"]));
    for arg in ["credential", "method", "url", "headers", "body"] {
        assert!(
            proxy["properties"].get(arg).is_some(),
            "agentcordon_proxy takes {arg}: {proxy}"
        );
    }

    assert_eq!(
        by_name["agentcordon_mcp_tools"]["inputSchema"]["required"],
        json!(["server"])
    );
    assert_eq!(
        by_name["agentcordon_mcp_call"]["inputSchema"]["required"],
        json!(["server", "tool"])
    );
    for no_args in [
        "agentcordon_status",
        "agentcordon_credentials",
        "agentcordon_mcp_servers",
    ] {
        assert_eq!(
            by_name[no_args]["inputSchema"]["properties"],
            json!({}),
            "{no_args} takes no arguments"
        );
    }

    assert!(serve.shutdown().success());
}

/// A tool this server does not have is a protocol error, not a tool result:
/// the model asked for something that does not exist, which is not the same
/// as a call that failed.
#[test]
fn an_unknown_tool_is_a_protocol_error() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();

    let message = serve.request(
        2,
        "tools/call",
        json!({"name": "agentcordon_nope", "arguments": {}}),
    );
    assert_eq!(message["error"]["code"], -32602);
    assert!(
        message["error"]["message"]
            .as_str()
            .unwrap()
            .contains("agentcordon_nope"),
        "{}",
        message["error"]
    );
    assert!(message.get("result").is_none());

    assert!(serve.shutdown().success());
}

/// The client closes stdin to end the session; the server exits cleanly
/// rather than being killed.
#[test]
fn stdin_eof_shuts_the_server_down() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();
    assert!(serve.shutdown().success());
}

// ---------------------------------------------------------------------------
// Slice 2 — agentcordon_status and agentcordon_credentials
// ---------------------------------------------------------------------------

/// A credential as the broker lists it.
fn cred(name: &str, pattern: Option<&str>) -> Value {
    json!({
        "id": format!("id-{name}"),
        "name": name,
        "service": "internal",
        "credential_type": "generic",
        "scopes": ["read"],
        "allowed_url_pattern": pattern,
        "expires_at": null,
        "expired": false,
        "vault": "default",
    })
}

/// `agentcordon_status` is the tool a model reaches for when something else
/// refused, so it answers with the same report the command prints.
#[test]
fn status_reports_the_broker_and_the_workspace() {
    let broker = StubBroker::start();
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_status", json!({}));
    let text = Serve::text_of(&result);

    assert_eq!(result["isError"], json!(false));
    assert!(text.contains(&broker.url()), "{text}");
    assert!(text.contains("Workspace: sha256:"), "{text}");
    assert!(text.contains("Registered: yes"), "{text}");

    let asked = broker.requests_to("/status");
    assert_eq!(asked.len(), 1, "one call: {asked:?}");
    assert!(asked[0].is_signed(), "signed with the workspace key");
    assert_eq!(asked[0].method, "GET");

    assert!(serve.shutdown().success());
}

/// The listing an agent chooses a credential from: the same five fields the
/// CLI's `--json` projection carries, and nothing that would help an agent
/// reason about a secret it is never given.
#[test]
fn credentials_returns_the_five_field_projection() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.credentials = json!({"data": [
            cred("github", Some("https://api.github.com/*")),
            cred("anything", None),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_credentials", json!({}));
    assert_eq!(result["isError"], json!(false));

    let listed: Value = serde_json::from_str(&Serve::text_of(&result)).expect("JSON array");
    let entries = listed.as_array().expect("an array");
    assert_eq!(entries.len(), 2);

    let mut keys: Vec<&str> = entries[0]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "allowed_url_pattern",
            "credential_type",
            "expires_at",
            "name",
            "service"
        ]
    );
    assert_eq!(entries[0]["name"], "github");
    assert_eq!(
        entries[0]["allowed_url_pattern"],
        "https://api.github.com/*"
    );
    assert_eq!(
        entries[1]["allowed_url_pattern"],
        Value::Null,
        "an unfenced credential says so rather than being omitted"
    );

    assert!(serve.shutdown().success());
}

/// A broker that is not running is the tool call failing, not the protocol
/// failing: the session stays usable and the model is told what to fix, in
/// the CLI's own words.
#[test]
fn a_broker_that_is_not_running_is_a_tool_error() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &[]);
    serve.initialize();

    let message = serve.request(
        2,
        "tools/call",
        json!({"name": "agentcordon_status", "arguments": {}}),
    );
    assert!(
        message.get("error").is_none(),
        "a broker failure is not a protocol error: {message}"
    );
    let result = &message["result"];
    assert_eq!(result["isError"], json!(true));
    assert!(
        Serve::text_of(result).contains("broker is not running"),
        "{result}"
    );

    assert!(serve.shutdown().success());
}

// ---------------------------------------------------------------------------
// Slice 3 — agentcordon_proxy
// ---------------------------------------------------------------------------

/// The tool this server exists for. One signed `POST /proxy`, the credential
/// named in it, and the broker's answer rendered as the same
/// `{status, headers, body}` object `proxy --json` prints.
#[test]
fn proxy_makes_one_signed_call_and_returns_the_json_envelope() {
    let broker = StubBroker::start();
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({
            "credential": "named",
            "method": "post",
            "url": "https://api.example.com/things",
            "headers": {"X-Trace": "1"},
            "body": "{\"name\":\"x\"}",
        }),
    );
    assert_eq!(result["isError"], json!(false));

    let envelope: Value = serde_json::from_str(&Serve::text_of(&result)).expect("JSON envelope");
    assert_eq!(envelope["status"], 200);
    assert_eq!(envelope["headers"]["content-type"], "application/json");
    assert_eq!(envelope["body"], json!({"ok": true}));

    let proxied = broker.requests_to("/proxy");
    assert_eq!(proxied.len(), 1, "one call, no probe: {proxied:?}");
    assert!(proxied[0].is_signed(), "signed with the workspace key");
    let sent: Value = serde_json::from_str(&proxied[0].body).expect("json body");
    assert_eq!(sent["credential"], "named");
    assert_eq!(sent["method"], "POST", "the method is normalised");
    assert_eq!(sent["url"], "https://api.example.com/things");
    assert_eq!(sent["headers"]["X-Trace"], "1");
    assert_eq!(sent["body"], "{\"name\":\"x\"}");
    assert!(
        broker.requests_to("/credentials").is_empty(),
        "naming a credential does not fetch the listing"
    );

    assert!(serve.shutdown().success());
}

/// Omitting `credential` uses the same URL-fence selector as `proxy --auto`,
/// and still makes exactly one proxied call.
#[test]
fn proxy_without_a_credential_selects_by_url_fence() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.credentials = json!({"data": [
            cred("wrong-host", Some("https://api.github.com/*")),
            cred("right-one", Some("https://api.example.com/*")),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({"method": "GET", "url": "https://api.example.com/things"}),
    );
    assert_eq!(result["isError"], json!(false));

    let proxied = broker.requests_to("/proxy");
    assert_eq!(proxied.len(), 1, "{proxied:?}");
    let sent: Value = serde_json::from_str(&proxied[0].body).expect("json body");
    assert_eq!(sent["credential"], "right-one");

    assert!(serve.shutdown().success());
}

/// The body on stdout is the broker's, byte for byte. The broker is what
/// scans an upstream response for an injected credential, so anything this
/// server rewrote would be a second, weaker copy of that guarantee.
#[test]
fn the_body_reaching_stdout_is_the_brokers_redacted_body() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.credentials = json!({"data": [cred("only", Some("https://api.example.com/*"))]});
        a.proxy = json!({"data": {
            "status_code": 200,
            "headers": [["content-type", "text/plain"]],
            "body": "echoed: Bearer [REDACTED]",
        }});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({"method": "GET", "url": "https://api.example.com/echo"}),
    );
    let envelope: Value = serde_json::from_str(&Serve::text_of(&result)).expect("JSON envelope");
    assert_eq!(envelope["body"], "echoed: Bearer [REDACTED]");

    assert!(serve.shutdown().success());
}

/// Nothing fenced for the target is the selector refusing, in the words the
/// CLI uses, and nothing is proxied.
#[test]
fn proxy_refuses_when_no_fence_covers_the_url() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.credentials = json!({"data": [cred("github", Some("https://api.github.com/*"))]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({"method": "GET", "url": "https://api.gitlab.com/user"}),
    );
    assert_eq!(result["isError"], json!(true));
    assert!(
        Serve::text_of(&result).contains("no credential is fenced for https://api.gitlab.com/user"),
        "{result}"
    );
    assert!(broker.requests_to("/proxy").is_empty());

    assert!(serve.shutdown().success());
}

/// Several fences covering the target is a refusal that names them, so the
/// model's next call can pick one instead of guessing.
#[test]
fn proxy_refuses_when_several_fences_cover_the_url() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.credentials = json!({"data": [
            cred("read", Some("https://api.example.com/*")),
            cred("write", Some("https://api.example.com/repos/*")),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({"method": "GET", "url": "https://api.example.com/repos/a"}),
    );
    assert_eq!(result["isError"], json!(true));
    let text = Serve::text_of(&result);
    assert!(text.contains("several credentials are fenced"), "{text}");
    assert!(text.contains("read"), "{text}");
    assert!(text.contains("write"), "{text}");
    assert!(broker.requests_to("/proxy").is_empty());

    assert!(serve.shutdown().success());
}

/// A refusal by the broker comes back as the CLI's one line, not as a
/// JSON-RPC error: the call was well-formed, the answer was no.
#[test]
fn a_broker_refusal_is_the_clis_one_line() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.refusal = Some((
            403,
            json!({"error": {
                "code": "url_pattern_denied",
                "message": "credential 'ws' is fenced to the URL pattern https://api.example.com/*",
            }}),
        ));
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_proxy",
        json!({"credential": "named", "method": "GET", "url": "https://elsewhere.example/x"}),
    );
    assert_eq!(result["isError"], json!(true));
    assert_eq!(
        Serve::text_of(&result),
        "credential 'ws' is fenced to the URL pattern https://api.example.com/* \
         (url_pattern_denied)",
        "the line `agentcordon proxy` itself prints"
    );

    assert!(serve.shutdown().success());
}

/// A workspace the broker does not know is the exit-3 case, and every
/// broker-backed tool answers it with the message the CLI exits 3 with —
/// the one that names the command that fixes it.
#[test]
fn a_workspace_that_is_not_registered_is_told_to_register() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.refusal = Some((
            401,
            json!({"error": {
                "code": "reregistration_required",
                "message": "Workspace not registered with this broker. Run: agentcordon register",
            }}),
        ));
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    for (id, tool) in [
        (2, "agentcordon_status"),
        (3, "agentcordon_credentials"),
        (4, "agentcordon_mcp_servers"),
    ] {
        let result = serve.call_tool(id, tool, json!({}));
        let text = Serve::text_of(&result);
        assert_eq!(result["isError"], json!(true), "{tool}: {result}");
        assert!(
            text.contains("agentcordon register"),
            "{tool} names the fix: {text}"
        );
    }

    assert!(serve.shutdown().success());
}

/// A call missing an argument the tool declared as required is the model's
/// mistake about the protocol, so it is a protocol error.
#[test]
fn proxy_without_a_url_is_a_protocol_error() {
    let broker = StubBroker::start();
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let message = serve.request(
        2,
        "tools/call",
        json!({"name": "agentcordon_proxy", "arguments": {"method": "GET"}}),
    );
    assert_eq!(message["error"]["code"], -32602);
    assert!(
        message["error"]["message"]
            .as_str()
            .unwrap()
            .contains("url"),
        "{}",
        message["error"]
    );

    assert!(serve.shutdown().success());
}

// ---------------------------------------------------------------------------
// Slice 4 — the brokered MCP surface
// ---------------------------------------------------------------------------

/// One tool as the broker's `/mcp/list-tools` lists it.
fn upstream_tool(server: &str, tool: &str) -> Value {
    json!({
        "server": server,
        "tool": tool,
        "description": format!("{tool} on {server}"),
        "input_schema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        },
    })
}

/// The catalogue an agent picks a server from, as the broker listed it.
#[test]
fn mcp_servers_returns_the_brokers_listing() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.servers = json!({"data": [
            {"name": "github", "description": "GitHub", "tools": ["create_issue"],
             "transport": "http", "url": "https://mcp.example/github"},
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_mcp_servers", json!({}));
    assert_eq!(result["isError"], json!(false));
    let listed: Value = serde_json::from_str(&Serve::text_of(&result)).expect("JSON list");
    assert_eq!(listed[0]["name"], "github");
    assert_eq!(listed[0]["tools"], json!(["create_issue"]));

    let asked = broker.requests_to("/mcp/list-servers");
    assert_eq!(asked.len(), 1);
    assert!(asked[0].is_signed());

    assert!(serve.shutdown().success());
}

/// One server's tools, with the upstream schema under the name MCP gives it,
/// so a model can read the argument names instead of guessing them.
#[test]
fn mcp_tools_returns_one_servers_tools_with_their_schemas() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.tools = json!({"data": [
            upstream_tool("github", "create_issue"),
            upstream_tool("slack", "send_message"),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_mcp_tools", json!({"server": "github"}));
    assert_eq!(result["isError"], json!(false));
    let listed: Value = serde_json::from_str(&Serve::text_of(&result)).expect("JSON list");
    let tools = listed.as_array().expect("an array");
    assert_eq!(
        tools.len(),
        1,
        "only the server that was asked for: {listed}"
    );
    assert_eq!(tools[0]["name"], "create_issue");
    assert_eq!(tools[0]["description"], "create_issue on github");
    assert_eq!(tools[0]["inputSchema"]["required"], json!(["repo"]));

    assert!(serve.shutdown().success());
}

/// A misspelled server name is the common case for an empty answer, so it is
/// told rather than shown an empty list.
#[test]
fn mcp_tools_for_a_server_with_nothing_says_so() {
    let broker = StubBroker::start();
    broker.set(|a| a.tools = json!({"data": [upstream_tool("github", "create_issue")]}));
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_mcp_tools", json!({"server": "guthub"}));
    assert_eq!(result["isError"], json!(true));
    let text = Serve::text_of(&result);
    assert!(text.contains("guthub"), "{text}");
    assert!(text.contains("agentcordon_mcp_servers"), "{text}");

    assert!(serve.shutdown().success());
}

/// The upstream tool's own result, unchanged, plus the correlation id that
/// ties it to the policy decision in the server's audit log.
#[test]
fn mcp_call_returns_the_upstream_result_with_its_correlation_id() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.call = json!({"data": {
            "content": [
                {"type": "text", "text": "Issue #42 created"},
                {"type": "resource_link", "uri": "https://example.test/42"},
            ],
            "isError": false,
            "correlation_id": "corr-abc",
        }});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_mcp_call",
        json!({"server": "github", "tool": "create_issue", "arguments": {"repo": "a/b"}}),
    );

    assert_eq!(
        result["content"],
        json!([
            {"type": "text", "text": "Issue #42 created"},
            {"type": "resource_link", "uri": "https://example.test/42"},
        ]),
        "every block comes back as the upstream sent it"
    );
    assert_eq!(result["isError"], json!(false));
    assert_eq!(result["_meta"]["correlation_id"], "corr-abc");

    let called = broker.requests_to("/mcp/call");
    assert_eq!(called.len(), 1);
    assert!(called[0].is_signed());
    let sent: Value = serde_json::from_str(&called[0].body).expect("json body");
    assert_eq!(sent["server"], "github");
    assert_eq!(sent["tool"], "create_issue");
    assert_eq!(sent["arguments"], json!({"repo": "a/b"}));

    assert!(serve.shutdown().success());
}

/// A tool that answered with `isError` is reported as one: the call reached
/// the upstream and the upstream refused.
#[test]
fn mcp_call_passes_an_upstream_tool_error_through() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.call = json!({"data": {
            "content": [{"type": "text", "text": "repo not found"}],
            "isError": true,
            "correlation_id": "corr-err",
        }});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let result = serve.call_tool(
        2,
        "agentcordon_mcp_call",
        json!({"server": "github", "tool": "create_issue"}),
    );
    assert_eq!(result["isError"], json!(true));
    assert_eq!(Serve::text_of(&result), "repo not found");
    assert_eq!(result["_meta"]["correlation_id"], "corr-err");

    assert!(serve.shutdown().success());
}

/// `arguments` is optional; a tool that takes none is called with none.
#[test]
fn mcp_call_without_arguments_sends_an_empty_object() {
    let broker = StubBroker::start();
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    serve.call_tool(
        2,
        "agentcordon_mcp_call",
        json!({"server": "echo", "tool": "ping"}),
    );
    let sent: Value =
        serde_json::from_str(&broker.requests_to("/mcp/call")[0].body).expect("json body");
    assert_eq!(sent["arguments"], json!({}));

    assert!(serve.shutdown().success());
}

// ---------------------------------------------------------------------------
// Slice 5 — --expose
// ---------------------------------------------------------------------------

fn list_changed(serve: &Serve) -> usize {
    serve
        .notifications()
        .iter()
        .filter(|n| n["method"] == "notifications/tools/list_changed")
        .count()
}

/// Without `--expose`, a workspace with twenty brokered tools costs the same
/// six tools of context as one with none.
#[test]
fn without_expose_a_broker_full_of_tools_is_still_six_tools() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.tools = json!({"data": [
            upstream_tool("github", "create_issue"),
            upstream_tool("github", "list_repos"),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &[]);
    serve.initialize();

    let list = serve.ok(2, "tools/list", json!({}));
    assert_eq!(tool_names(&list), FIXED_TOOLS);
    assert!(
        broker.requests_to("/mcp/list-tools").is_empty(),
        "and it does not even ask"
    );

    assert!(serve.shutdown().success());
}

/// `--expose <server>` re-exports that server's tools as typed tools, with
/// the upstream schema verbatim — and only that server's.
#[test]
fn expose_publishes_one_tool_per_upstream_tool_of_that_server() {
    let broker = StubBroker::start();
    broker.set(|a| {
        a.tools = json!({"data": [
            upstream_tool("github", "create_issue"),
            upstream_tool("slack", "send_message"),
        ]});
    });
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &["--expose", "github"]);
    serve.initialize();

    let list = serve.ok(2, "tools/list", json!({}));
    let names = tool_names(&list);
    assert_eq!(
        names.len(),
        FIXED_TOOLS.len() + 1,
        "the six, and github's one tool: {names:?}"
    );
    assert!(
        names.contains(&"github__create_issue".to_string()),
        "{names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("slack__")),
        "a server that was not exposed is not published: {names:?}"
    );

    let exported = list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "github__create_issue")
        .expect("the exported tool");
    assert_eq!(exported["description"], "[github] create_issue on github");
    assert_eq!(
        exported["inputSchema"],
        json!({
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        }),
        "the upstream schema, verbatim"
    );

    assert!(serve.shutdown().success());
}

/// Calling a re-exported tool is the same brokered call as
/// `agentcordon_mcp_call`, with the server and tool it was named for.
#[test]
fn calling_an_exposed_tool_names_its_server_and_tool() {
    let broker = StubBroker::start();
    broker.set(|a| a.tools = json!({"data": [upstream_tool("github", "create_issue")]}));
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &["--expose", "github"]);
    serve.initialize();
    serve.ok(2, "tools/list", json!({}));

    let result = serve.call_tool(3, "github__create_issue", json!({"repo": "a/b"}));
    assert_eq!(result["isError"], json!(false));
    assert_eq!(result["_meta"]["correlation_id"], "corr-1");

    let called = broker.requests_to("/mcp/call");
    assert_eq!(called.len(), 1);
    let sent: Value = serde_json::from_str(&called[0].body).expect("json body");
    assert_eq!(sent["server"], "github");
    assert_eq!(sent["tool"], "create_issue");
    assert_eq!(sent["arguments"], json!({"repo": "a/b"}));

    assert!(serve.shutdown().success());
}

/// A tool that appears upstream after the session started is published, and
/// the client is told the list changed — which is what `listChanged: true`
/// promised at `initialize`.
#[test]
fn the_client_is_told_when_an_exposed_servers_tools_change() {
    let broker = StubBroker::start();
    broker.set(|a| a.tools = json!({"data": [upstream_tool("github", "create_issue")]}));
    let dir = workspace();
    let mut serve = Serve::start(&broker.url(), &dir, &["--expose", "github"]);
    serve.initialize();

    let first = serve.ok(2, "tools/list", json!({}));
    assert_eq!(tool_names(&first).len(), FIXED_TOOLS.len() + 1);
    assert_eq!(
        list_changed(&serve),
        0,
        "nothing has changed yet: the first list is the first list"
    );

    broker.set(|a| {
        a.tools = json!({"data": [
            upstream_tool("github", "create_issue"),
            upstream_tool("github", "list_repos"),
        ]});
    });

    let second = serve.ok(3, "tools/list", json!({}));
    assert_eq!(tool_names(&second).len(), FIXED_TOOLS.len() + 2);
    assert_eq!(
        list_changed(&serve),
        1,
        "exactly one notification for one change"
    );

    assert!(serve.shutdown().success());
}

/// A broker that cannot be reached costs the exposed tools, not the session:
/// the six fixed tools are still published and still callable.
#[test]
fn expose_with_the_broker_down_still_publishes_the_six() {
    let dir = workspace();
    let mut serve = Serve::start(&dead_broker_url(), &dir, &["--expose", "github"]);
    serve.initialize();

    let list = serve.ok(2, "tools/list", json!({}));
    assert_eq!(tool_names(&list), FIXED_TOOLS);

    assert!(serve.shutdown().success());
}

// ---------------------------------------------------------------------------
// Slice 6 — the broker the session starts for itself
// ---------------------------------------------------------------------------

/// With a server URL configured and no broker running, the first tool call
/// starts one, exactly as `init` and `register` do. What is observable from
/// outside is that it *tried*: with no `agentcordon-broker` on PATH the
/// failure names the start, not the absence.
#[test]
fn the_first_tool_call_starts_a_broker_when_a_server_is_configured() {
    let dir = workspace();
    let empty_path = tempfile::tempdir().expect("tempdir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentcordon"));
    cmd.arg("mcp-serve")
        .env("AGTCRDN_BROKER_URL", dead_broker_url())
        .env("AGTCRDN_WORKSPACE_DIR", dir.path())
        .env("HOME", dir.path())
        .env("AGTCRDN_SERVER_URL", "http://cordon.example.test:3140")
        .env("PATH", empty_path.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().expect("spawn");
    let mut serve = Serve {
        stdin: Some(child.stdin.take().expect("stdin")),
        out: BufReader::new(child.stdout.take().expect("stdout")),
        child,
        seen: Vec::new(),
    };
    serve.initialize();

    let result = serve.call_tool(2, "agentcordon_status", json!({}));
    assert_eq!(result["isError"], json!(true));
    let text = Serve::text_of(&result);
    assert!(
        text.contains("failed to start broker"),
        "the autostart was attempted: {text}"
    );

    assert!(serve.shutdown().success());
}

/// Nothing on stdout but JSON-RPC, even while the broker autostart is
/// reporting progress: stdout is the channel, stderr is the log.
#[test]
fn progress_and_errors_never_reach_stdout() {
    let dir = workspace();
    let empty_path = tempfile::tempdir().expect("tempdir");

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentcordon"));
    cmd.arg("mcp-serve")
        .env("AGTCRDN_BROKER_URL", dead_broker_url())
        .env("AGTCRDN_WORKSPACE_DIR", dir.path())
        .env("HOME", dir.path())
        .env("AGTCRDN_SERVER_URL", "http://cordon.example.test:3140")
        .env("PATH", empty_path.path())
        .env("AGTCRDN_LOG_LEVEL", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    for line in [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "agentcordon_status", "arguments": {}}}),
    ] {
        writeln!(stdin, "{line}").expect("write");
    }
    drop(stdin);

    let mut written = String::new();
    BufReader::new(stdout)
        .read_to_string(&mut written)
        .expect("read stdout");
    assert!(child.wait().expect("wait").success());

    let messages: Vec<&str> = written.lines().collect();
    assert_eq!(
        messages.len(),
        2,
        "one reply each, and nothing else: {written}"
    );
    for message in messages {
        let parsed: Value = serde_json::from_str(message)
            .unwrap_or_else(|e| panic!("stdout carried non-JSON-RPC: {message:?} ({e})"));
        assert_eq!(parsed["jsonrpc"], "2.0");
    }
}
