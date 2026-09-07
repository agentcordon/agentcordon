//! A broker on a real socket, for the enrollment tests.
//!
//! `register` and `init` are almost entirely a conversation with the broker:
//! discovery, `/health` and its key fingerprint, `POST /register`, then
//! `GET /status` until the approval lands. Everything interesting about them
//! is in that sequence, so the tests drive a real [`BrokerClient`] over real
//! HTTP against this, rather than mocking the client out and testing nothing.
//!
//! Deliberately minimal: one request per connection, `Connection: close`, no
//! signature verification. The signed-payload rules have their own frozen test
//! vectors in `agentcordon-identity`; what these tests are about is the flow.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A fake broker listening on loopback.
pub(crate) struct FakeBroker {
    pub base_url: String,
    /// How many `GET /status` requests have arrived.
    status_polls: Arc<AtomicUsize>,
    /// How many `POST /register` requests have arrived.
    register_calls: Arc<AtomicUsize>,
}

impl FakeBroker {
    pub fn status_polls(&self) -> usize {
        self.status_polls.load(Ordering::SeqCst)
    }

    pub fn register_calls(&self) -> usize {
        self.register_calls.load(Ordering::SeqCst)
    }
}

/// How the fake answers `GET /status`.
#[derive(Clone, Copy)]
pub(crate) enum Registration {
    /// `registered: true` from the first poll — the "already enrolled" case.
    Already,
    /// `registered: false` until this many polls have gone by, then true.
    /// Stands in for the human walking to a browser and clicking Approve.
    ApprovedAfter(usize),
}

/// Start a fake broker and return it once it is listening.
pub(crate) async fn spawn(registration: Registration) -> FakeBroker {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Any 64 hex characters: the CLI pins whatever /health publishes, and
    // these tests are about the flow, not the key.
    let fingerprint = "ab".repeat(32);
    let polls = Arc::new(AtomicUsize::new(0));
    let registers = Arc::new(AtomicUsize::new(0));

    let fp = fingerprint;
    let counter = Arc::clone(&polls);
    let register_counter = Arc::clone(&registers);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let fp = fp.clone();
            let counter = Arc::clone(&counter);
            let register_counter = Arc::clone(&register_counter);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let mut parts = request.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");

                let body = match (method, path) {
                    ("GET", "/health") => format!(
                        r#"{{"status":"ok","key_fingerprint":"{fp}","version":"{}"}}"#,
                        env!("CARGO_PKG_VERSION")
                    ),
                    ("POST", "/register") => {
                        register_counter.fetch_add(1, Ordering::SeqCst);
                        r#"{"data":{"user_code":"tidy-zoned-zit-ramp",
                        "verification_uri":"http://cordon.example.test/activate",
                        "verification_uri_complete":"http://cordon.example.test/activate?user_code=tidy-zoned-zit-ramp",
                        "expires_in":600,"interval":5,"status":"pending"}}"#
                        .replace(['\n', ' '], "")
                    }
                    ("GET", "/status") => {
                        let seen = counter.fetch_add(1, Ordering::SeqCst);
                        let registered = match registration {
                            Registration::Already => true,
                            Registration::ApprovedAfter(n) => seen >= n,
                        };
                        format!(
                            r#"{{"data":{{"registered":{registered},"scopes":["credentials:discover","credentials:vend","mcp:discover","mcp:invoke"]}}}}"#
                        )
                    }
                    _ => r#"{"error":{"code":"not_found","message":"no such route"}}"#.to_string(),
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    FakeBroker {
        base_url: format!("http://{addr}"),
        status_polls: polls,
        register_calls: registers,
    }
}
