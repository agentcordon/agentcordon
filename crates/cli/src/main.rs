// AgentCordon Thin CLI — lightweight workspace agent
// Manages Ed25519 keypairs, signs requests to broker, never touches credentials

mod broker;
mod broker_autostart;
mod commands;
mod error;
mod platform;
mod signing;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::error::CliError;

#[derive(Parser)]
#[command(
    name = "agentcordon",
    about = "AgentCordon workspace CLI — identity, credentials, and MCP through the broker",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate Ed25519 keypair and prepare workspace
    Init {
        /// Target agent: claude-code (default), codex, openclaw, or all
        #[arg(long, default_value = "claude-code")]
        agent: String,
    },

    /// Register this workspace with the broker
    Register {
        /// OAuth scopes to request (default: credentials:discover credentials:vend)
        #[arg(long = "scope", num_args = 1)]
        scopes: Vec<String>,

        /// Clear any existing broker registration before re-registering.
        /// Use when the server-side workspace was deleted but the broker
        /// still holds stale state (409 Conflict on register).
        #[arg(long)]
        force: bool,

        /// Do not auto-open the authorization URL in the browser.
        /// Useful for headless / SSH / CI environments.
        #[arg(long = "no-browser")]
        no_browser: bool,

        /// AgentCordon server URL (e.g. http://server:3140). If provided
        /// and the broker is not already running, `register` will start
        /// a broker daemon pointed at this server before initiating the
        /// RFC 8628 device flow. If the broker is already running this
        /// flag is ignored.
        #[arg(long = "server-url", env = "AGTCRDN_SERVER_URL")]
        server_url: Option<String>,
    },

    /// Check workspace and broker status
    Status,

    /// List available credentials (or manage them with subcommands)
    Credentials {
        #[command(subcommand)]
        action: Option<CredentialsAction>,
    },

    /// Proxy an HTTP request through the broker with credential injection
    Proxy {
        /// Credential name to use
        credential: String,

        /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
        method: String,

        /// Target URL
        url: String,

        /// Additional headers (KEY:VALUE, repeatable)
        #[arg(long = "header", num_args = 1)]
        headers: Vec<String>,

        /// Request body (string or @file to read from file)
        #[arg(long)]
        body: Option<String>,

        /// Pretty-print response body as JSON
        #[arg(long)]
        json: bool,

        /// Print only response body (for piping)
        #[arg(long)]
        raw: bool,
    },

    /// List available MCP servers
    McpServers,

    /// List all available MCP tools
    McpTools,

    /// Call an MCP tool
    McpCall {
        /// MCP server name
        server: String,

        /// Tool name
        tool: String,

        /// Tool arguments (KEY=VALUE, repeatable)
        #[arg(long = "arg", num_args = 1)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CredentialsAction {
    /// Create a new credential in the vault via the broker
    Create {
        /// Credential name (unique within workspace)
        #[arg(long)]
        name: String,

        /// Service identifier (e.g. "github", "openai")
        #[arg(long)]
        service: String,

        /// Secret value (the credential to store)
        #[arg(long)]
        value: String,
    },
}

fn main() -> std::process::ExitCode {
    // Initialize logging from AGTCRDN_LOG_LEVEL or default to warn
    let filter =
        EnvFilter::try_from_env("AGTCRDN_LOG_LEVEL").unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init { agent } => commands::init::run(&agent),
        _ => {
            // All other commands are async
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(run_async(cli.command))
        }
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            e.code.into()
        }
    }
}

async fn run_async(command: Command) -> Result<(), CliError> {
    match command {
        Command::Init { .. } => unreachable!(),
        Command::Register {
            scopes,
            force,
            no_browser,
            server_url,
        } => commands::register::run(scopes, force, no_browser, server_url).await,
        Command::Status => commands::status::run().await,
        Command::Credentials { action } => match action {
            None => commands::credentials::run().await,
            Some(CredentialsAction::Create {
                name,
                service,
                value,
            }) => commands::credentials::create(name, service, value).await,
        },
        Command::Proxy {
            credential,
            method,
            url,
            headers,
            body,
            json,
            raw,
        } => commands::proxy::run(credential, method, url, headers, body, json, raw).await,
        Command::McpServers => commands::mcp::list_servers().await,
        Command::McpTools => commands::mcp::list_tools().await,
        Command::McpCall { server, tool, args } => commands::mcp::call(server, tool, args).await,
    }
}
