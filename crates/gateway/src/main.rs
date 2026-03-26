#![allow(dead_code, clippy::too_many_arguments)]

// Modules used by CLI subcommands (proxy, mcp-serve, init, register).
mod audit;
mod cli;
mod cp_client;
mod credential_transform;
mod http_mcp;
mod identity;
mod mcp_sync;
mod stdio;
mod vend;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "agentcordon",
    version,
    about = "AgentCordon — secure credential proxy for autonomous agents"
)]
struct Cli {
    /// Output machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    /// Server URL (overrides env/config)
    #[arg(long, global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: cli::CliCommand,
}

#[tokio::main]
async fn main() {
    init_logging();

    let cli = Cli::parse();

    let flags = cli::GlobalFlags {
        json: cli.json,
        server: cli.server,
    };
    cli::run(cli.command, &flags).await;
}

/// Initialize structured logging with a default of "info" when RUST_LOG is unset.
fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
