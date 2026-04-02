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

    /// Bind address (default: 127.0.0.1). Set to 0.0.0.0 for Docker/container use.
    #[arg(long, env = "AGTCRDN_BROKER_BIND", default_value = "127.0.0.1")]
    pub bind: String,
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
}
