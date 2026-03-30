mod auth;
mod config;
mod credential_transform;
mod daemon;
mod routes;
mod server_client;
mod state;
mod token_refresh;
mod token_store;
mod vend;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use config::BrokerConfig;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = BrokerConfig::parse();

    if let Err(e) = daemon::run(config).await {
        tracing::error!(error = %e, "broker exited with error");
        std::process::exit(1);
    }
}
