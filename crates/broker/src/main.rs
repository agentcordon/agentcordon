use clap::Parser;
use tracing_subscriber::EnvFilter;

use agentcordon_broker::config::BrokerConfig;
use agentcordon_broker::daemon;

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
