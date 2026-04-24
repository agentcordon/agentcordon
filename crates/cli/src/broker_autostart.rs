//! Broker auto-start helpers used by `agentcordon register --server-url`.
//!
//! Moved out of the deleted `commands::setup` module so the same discovery +
//! spawn path is reusable from `register`. Behaviour is identical to the
//! previous `setup` implementation:
//!
//! 1. Look for an already-running broker via `AGTCRDN_BROKER_URL` env var.
//! 2. Fall back to `~/.agentcordon/broker.port`.
//! 3. If neither responds to `/health`, spawn a new `agentcordon-broker`
//!    child process bound to the given `server_url` and wait (up to 5s) for
//!    its health endpoint to come up.
//!
//! Only `ensure_broker_running` is exported; everything else is private
//! because the CLI enters this flow through a single front door.
//!
//! On Windows, `platform::spawn_broker` attaches the child to a Job Object
//! with `KILL_ON_JOB_CLOSE` so the broker cannot outlive the CLI. On Unix
//! it's a plain `Command::spawn`.

use std::path::PathBuf;

use crate::error::CliError;
use crate::platform;

/// Ensure a broker is reachable at some URL, starting one bound to
/// `server_url` if none is already running. Returns the broker's base URL
/// on success.
pub(crate) async fn ensure_broker_running(server_url: &str) -> Result<String, CliError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| CliError::general(format!("failed to create HTTP client: {e}")))?;

    // Try existing broker via env var or port file
    if let Ok(url) = discover_existing_broker(&client).await {
        return Ok(url);
    }

    // Start broker in background
    println!("  Starting broker daemon...");
    let broker_port = find_broker_port();

    let mut cmd = std::process::Command::new("agentcordon-broker");
    cmd.arg("--server-url")
        .arg(server_url)
        .arg("--port")
        .arg(broker_port.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // On Windows, attach the broker to a Job Object so it dies when the
    // CLI exits (per v0.3.0 locked decision #4). On Unix this is a plain
    // `Command::spawn`.
    platform::spawn_broker(&mut cmd).map_err(|e| {
        CliError::general(format!(
            "failed to start broker: {e}\n\
             Install it with: curl -fsSL http://your-server/install.sh | bash"
        ))
    })?;

    // Wait for health
    let broker_url = format!("http://localhost:{broker_port}");
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if client
            .get(format!("{broker_url}/health"))
            .send()
            .await
            .is_ok()
        {
            return Ok(broker_url);
        }
    }

    Err(CliError::general("broker failed to start within 5 seconds"))
}

/// Try to discover an already-running broker.
async fn discover_existing_broker(client: &reqwest::Client) -> Result<String, CliError> {
    // 1. Environment override
    if let Ok(url) = std::env::var("AGTCRDN_BROKER_URL") {
        let url = url.trim_end_matches('/').to_string();
        if client.get(format!("{url}/health")).send().await.is_ok() {
            return Ok(url);
        }
    }

    // 2. Port file
    let port_path = broker_port_path()?;
    if let Ok(port_str) = std::fs::read_to_string(&port_path) {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            let url = format!("http://localhost:{port}");
            if client.get(format!("{url}/health")).send().await.is_ok() {
                return Ok(url);
            }
        }
    }

    Err(CliError::general("no existing broker found"))
}

/// Get the broker port file path (~/.agentcordon/broker.port).
///
/// Returns an error if no user home directory can be resolved on the
/// current platform (e.g. `HOME` unset on Unix, `USERPROFILE` unset on
/// Windows). The caller surfaces this to the user rather than silently
/// writing to a nonsense path.
fn broker_port_path() -> Result<PathBuf, CliError> {
    broker_port_path_from(dirs::home_dir())
}

/// Inner form of `broker_port_path` taking the resolved home-dir lookup
/// as a parameter so the error path can be exercised under test without
/// relying on the host's `HOME` / passwd-database state.
fn broker_port_path_from(home: Option<PathBuf>) -> Result<PathBuf, CliError> {
    let home = home.ok_or_else(|| {
        CliError::general(
            "could not resolve user home directory; \
             set HOME (Unix/macOS) or USERPROFILE (Windows)",
        )
    })?;
    Ok(home.join(".agentcordon").join("broker.port"))
}

/// Pick a port for the broker (default 9876).
fn find_broker_port() -> u16 {
    9876
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serialise env-var mutation across parallel tests. `HOME` /
    /// `USERPROFILE` / `AGTCRDN_BROKER_URL` are process-global, so tests
    /// that touch them must run one at a time. Copy of the `EnvGuard`
    /// pattern in `crates/cli/src/commands/init.rs:413-435`, extended to
    /// cover the broker-URL override used by
    /// `discover_existing_broker`.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior_home: Option<String>,
        prior_userprofile: Option<String>,
        prior_broker_url: Option<String>,
    }

    impl EnvGuard {
        fn new() -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior_home = std::env::var("HOME").ok();
            let prior_userprofile = std::env::var("USERPROFILE").ok();
            let prior_broker_url = std::env::var("AGTCRDN_BROKER_URL").ok();
            // Start each test with a known-clean slate for the broker
            // URL — otherwise a stray inherited env var could spoof
            // discovery against a real broker on the host.
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                std::env::remove_var("AGTCRDN_BROKER_URL");
            }
            Self {
                _lock: lock,
                prior_home,
                prior_userprofile,
                prior_broker_url,
            }
        }

        fn set_home(&self, path: &std::path::Path) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                std::env::set_var("HOME", path);
            }
        }

        fn set_broker_url(&self, url: &str) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                std::env::set_var("AGTCRDN_BROKER_URL", url);
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: tests are serialised via the mutex above.
            unsafe {
                match &self.prior_home {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
                match &self.prior_userprofile {
                    Some(v) => std::env::set_var("USERPROFILE", v),
                    None => std::env::remove_var("USERPROFILE"),
                }
                match &self.prior_broker_url {
                    Some(v) => std::env::set_var("AGTCRDN_BROKER_URL", v),
                    None => std::env::remove_var("AGTCRDN_BROKER_URL"),
                }
            }
        }
    }

    #[test]
    fn resolves_home_when_present() {
        let dir = TempDir::new().unwrap();
        let guard = EnvGuard::new();
        guard.set_home(dir.path());

        let resolved = broker_port_path().expect("home should resolve");
        assert_eq!(
            resolved,
            dir.path().join(".agentcordon").join("broker.port")
        );
    }

    /// Pins the error path of the resolver without depending on whether
    /// the host's `dirs::home_dir()` returns `None` — on Linux the crate
    /// falls back to `getpwuid_r`, so simply clearing `HOME` does not
    /// force `None`. `broker_port_path_from` takes the lookup result as
    /// input, letting us exercise the `None` branch directly.
    #[test]
    fn errors_when_no_home() {
        let err = broker_port_path_from(None).expect_err("missing home should error");
        assert!(
            err.message.contains("home directory"),
            "unexpected error message: {}",
            err.message
        );
    }

    /// Minimal real HTTP server (no mocking — we bind a real TCP socket
    /// and speak HTTP/1.1 on the wire). Accepts `n` sequential requests
    /// and always replies `200 OK` with an empty body. Used to stand in
    /// for a live broker `/health` endpoint in the env-var discovery
    /// test. Returns the `http://127.0.0.1:<port>` base URL.
    async fn spawn_fake_health_server(requests: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            for _ in 0..requests {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                // Read enough of the request to satisfy reqwest —
                // draining up to the first blank line keeps the
                // connection well-formed.
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
            }
        });
        format!("http://{addr}")
    }

    /// Regression guard for the `register` auto-start priority order:
    /// step 1 is "broker is already running (env-var override)". A real
    /// broker reachable at `AGTCRDN_BROKER_URL` must be discovered and
    /// returned verbatim — `ensure_broker_running` short-circuits on
    /// this path and never spawns a second broker.
    #[tokio::test]
    async fn discover_finds_broker_via_env_var() {
        let guard = EnvGuard::new();
        // Park HOME on an empty tempdir so the port-file fallback can't
        // accidentally succeed and mask a broken env-var path.
        let home = TempDir::new().unwrap();
        guard.set_home(home.path());

        let url = spawn_fake_health_server(1).await;
        guard.set_broker_url(&url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let discovered = discover_existing_broker(&client)
            .await
            .expect("healthy broker at AGTCRDN_BROKER_URL must be discovered");
        assert_eq!(discovered, url);
    }

    /// Regression guard for the fail-closed path: no env var, and the
    /// port file exists but points at a port nothing is listening on.
    /// `ensure_broker_running` then falls through to spawning a new
    /// broker — so discovery MUST surface an error rather than silently
    /// claim an unreachable URL is healthy.
    #[tokio::test]
    async fn discover_errors_when_env_unset_and_port_file_unreachable() {
        let guard = EnvGuard::new();
        let home = TempDir::new().unwrap();
        guard.set_home(home.path());

        // Bind-then-drop a listener on an ephemeral port to harvest a
        // port number that is free on this host right now. Brief race
        // vs. other processes, but scoped to the test worker.
        let sock = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let dead_port = sock.local_addr().unwrap().port();
        drop(sock);

        let port_dir = home.path().join(".agentcordon");
        std::fs::create_dir_all(&port_dir).unwrap();
        std::fs::write(port_dir.join("broker.port"), dead_port.to_string()).unwrap();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let err = discover_existing_broker(&client)
            .await
            .expect_err("unreachable port-file contents must NOT count as discovery");
        assert!(
            err.message.contains("no existing broker"),
            "unexpected error message: {}",
            err.message
        );
    }
}
