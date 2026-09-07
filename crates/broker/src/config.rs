use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;

/// AgentCordon Broker — per-user persistent daemon.
#[derive(Debug, Clone, Parser)]
#[command(name = "agentcordon-broker", version, about)]
pub struct BrokerConfig {
    /// Port to bind to (0 = auto-select).
    #[arg(long, env = "AGTCRDN_BROKER_PORT", default_value = "0")]
    pub port: u16,

    /// AgentCordon server URL.
    #[arg(
        long,
        env = "AGTCRDN_SERVER_URL",
        default_value = "http://localhost:3140"
    )]
    pub server_url: String,

    /// Data directory for keys, tokens, and runtime files.
    #[arg(long, env = "AGTCRDN_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Seconds before token expiry to trigger proactive refresh.
    #[arg(long, env = "AGTCRDN_TOKEN_TTL_BUFFER", default_value = "60")]
    pub token_ttl_buffer: u64,

    /// Allow proxy requests to loopback/private addresses (for local development).
    #[arg(long, env = "AGTCRDN_PROXY_ALLOW_LOOPBACK", default_value = "false")]
    pub proxy_allow_loopback: bool,

    /// Bind address (default: 127.0.0.1). A non-loopback address (for
    /// Docker/container use) is refused unless --tls-cert/--tls-key or
    /// --shared-secret is also set.
    #[arg(long, env = "AGTCRDN_BROKER_BIND", default_value = "127.0.0.1")]
    pub bind: String,

    /// MCP config sync interval in seconds (default: 60).
    #[arg(long, env = "AGTCRDN_MCP_SYNC_INTERVAL", default_value = "60")]
    pub mcp_sync_interval: u64,

    /// PEM certificate chain for TLS. Must be given together with --tls-key.
    #[arg(long, env = "AGTCRDN_BROKER_TLS_CERT", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for TLS. Must be given together with --tls-cert.
    #[arg(long, env = "AGTCRDN_BROKER_TLS_KEY", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Shared secret every request except /health must present in the
    /// X-AgentCordon-Broker-Secret header. Required for a non-loopback bind
    /// without TLS.
    #[arg(long, env = "AGTCRDN_BROKER_SHARED_SECRET", hide_env_values = true)]
    pub shared_secret: Option<String>,
}

impl BrokerConfig {
    /// Resolved data directory, defaulting to `~/.agentcordon/`.
    pub fn data_dir(&self) -> PathBuf {
        if let Some(ref d) = self.data_dir {
            d.clone()
        } else {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".agentcordon")
        }
    }

    /// Path to the P-256 keypair file.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir().join("broker.key")
    }

    /// Path to the encrypted token store.
    pub fn token_store_path(&self) -> PathBuf {
        self.data_dir().join("tokens.enc")
    }

    /// Path to the plaintext recovery store.
    pub fn recovery_store_path(&self) -> PathBuf {
        self.data_dir().join("workspaces.json")
    }

    /// Path to the port file the CLI discovers the broker through.
    pub fn port_file_path(&self) -> PathBuf {
        self.data_dir().join("broker.port")
    }

    /// Path to the PID file.
    pub fn pid_file_path(&self) -> PathBuf {
        self.data_dir().join("broker.pid")
    }

    /// Path to the single-instance lock file.
    pub fn lock_file_path(&self) -> PathBuf {
        self.data_dir().join("broker.lock")
    }

    /// The bind address as an IP.
    pub fn bind_ip(&self) -> Result<IpAddr, String> {
        self.bind
            .parse()
            .map_err(|e| format!("invalid bind address '{}': {}", self.bind, e))
    }

    /// Whether TLS is configured (both files given).
    pub fn tls_configured(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }

    /// Whether a non-empty shared secret is configured.
    pub fn shared_secret_configured(&self) -> bool {
        self.shared_secret
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
    }

    /// Cross-field validation, run before the daemon touches the network.
    ///
    /// - The bind address must parse.
    /// - A non-loopback bind needs TLS or a shared secret: an open port
    ///   with only Ed25519 signatures would let anyone on the network start
    ///   device flows and replay within the skew window.
    /// - `--tls-cert` and `--tls-key` come as a pair and must exist.
    /// - A shared secret, if given, must not be blank.
    pub fn validate(&self) -> Result<(), String> {
        let ip = self.bind_ip()?;

        if self.shared_secret.is_some() && !self.shared_secret_configured() {
            return Err("--shared-secret (AGTCRDN_BROKER_SHARED_SECRET) must not be blank".into());
        }

        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => {
                for (label, path) in [("--tls-cert", cert), ("--tls-key", key)] {
                    if !path.is_file() {
                        return Err(format!(
                            "{label} {} does not exist or is not a file",
                            path.display()
                        ));
                    }
                }
            }
            (None, None) => {}
            _ => return Err("--tls-cert and --tls-key must be given together".into()),
        }

        if !ip.is_loopback() && !self.tls_configured() && !self.shared_secret_configured() {
            return Err(format!(
                "refusing to bind to non-loopback address {ip} without transport protection: \
                 set --tls-cert/--tls-key or --shared-secret (AGTCRDN_BROKER_SHARED_SECRET), \
                 or bind to 127.0.0.1"
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> BrokerConfig {
        let mut full = vec!["agentcordon-broker"];
        full.extend_from_slice(args);
        <BrokerConfig as clap::Parser>::try_parse_from(full).expect("parses")
    }

    #[test]
    fn loopback_bind_needs_no_transport_protection() {
        assert!(parse(&[]).validate().is_ok());
        assert!(parse(&["--bind", "127.0.0.1"]).validate().is_ok());
        assert!(parse(&["--bind", "::1"]).validate().is_ok());
    }

    #[test]
    fn non_loopback_bind_without_tls_or_secret_is_refused() {
        for bind in ["0.0.0.0", "10.0.0.5", "::", "192.168.1.2"] {
            let err = parse(&["--bind", bind])
                .validate()
                .expect_err("must refuse");
            assert!(err.contains("non-loopback"), "{err}");
            assert!(err.contains("--shared-secret"), "{err}");
        }
    }

    #[test]
    fn blank_shared_secret_is_refused() {
        let err = parse(&["--bind", "0.0.0.0", "--shared-secret", "  "])
            .validate()
            .expect_err("blank secret must refuse");
        assert!(err.contains("blank"), "{err}");
    }

    #[test]
    fn tls_cert_without_key_is_refused_at_parse() {
        let mut full = vec!["agentcordon-broker", "--tls-cert", "/tmp/x.pem"];
        assert!(<BrokerConfig as clap::Parser>::try_parse_from(full.clone()).is_err());
        full = vec!["agentcordon-broker", "--tls-key", "/tmp/x.pem"];
        assert!(<BrokerConfig as clap::Parser>::try_parse_from(full).is_err());
    }

    #[test]
    fn missing_tls_files_are_refused() {
        let err = parse(&[
            "--bind",
            "0.0.0.0",
            "--tls-cert",
            "/nonexistent/cert.pem",
            "--tls-key",
            "/nonexistent/key.pem",
        ])
        .validate()
        .expect_err("missing files must refuse");
        assert!(err.contains("--tls-cert"), "{err}");
    }

    #[test]
    fn invalid_bind_is_refused() {
        let err = parse(&["--bind", "not-an-ip"])
            .validate()
            .expect_err("must refuse");
        assert!(err.contains("invalid bind address"), "{err}");
    }
}
