// AgentCordon — credential brokering and policy enforcement for AI agents.
// Copyright (C) 2026 The AgentCordon Authors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero
// General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
