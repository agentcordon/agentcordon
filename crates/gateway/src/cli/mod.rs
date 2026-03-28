mod auth;
mod claude_md;
mod client;
pub(crate) mod cred_classify;
mod credentials;
mod init;
mod mcp_call;
pub(crate) mod mcp_install;
pub(crate) mod mcp_migrate;
mod mcp_serve;
mod mcp_servers;
mod mcp_tools;
mod output;
pub(crate) mod poll;
mod proxy;
pub(crate) mod register;
mod state;
mod status;
mod store;
mod upload_mcps;

use clap::Subcommand;

/// Global flags shared across all CLI commands.
pub struct GlobalFlags {
    pub json: bool,
    pub server: Option<String>,
}

/// Subcommands for `credentials`. Currently only `list`, which is also the default.
#[derive(Subcommand)]
pub enum CredentialsAction {
    /// List available credentials (default behavior)
    List,
}

#[derive(Subcommand)]
pub enum CliCommand {
    /// Generate workspace identity keypair and optionally register with server
    Init {
        /// Overwrite existing keypair
        #[arg(long)]
        force: bool,
        /// Server URL — triggers full onboarding (register + MCP install)
        #[arg(long)]
        server: Option<String>,
        /// Workspace display name
        #[arg(long)]
        name: Option<String>,
        /// Skip MCP gateway installation
        #[arg(long)]
        no_mcp: bool,
        /// Provisioning token for CI/CD (skip browser approval)
        #[arg(long)]
        token: Option<String>,
    },
    /// Register workspace identity with server (two-phase PKCE)
    Register {
        /// Server URL
        #[arg(long)]
        server: Option<String>,
        /// Approval code from admin (Phase 2)
        #[arg(long)]
        code: Option<String>,
        /// Agent display name
        #[arg(long)]
        name: Option<String>,
    },
    /// Refresh JWT via challenge-response
    Auth,
    /// List available credentials
    Credentials {
        /// Subcommand (optional — defaults to listing credentials)
        #[command(subcommand)]
        action: Option<CredentialsAction>,
    },
    /// Store a credential via the server
    Store {
        /// Credential name
        #[arg(long)]
        name: String,
        /// Service identifier
        #[arg(long)]
        service: String,
        /// Secret value
        #[arg(long)]
        secret: String,
        /// Credential type
        #[arg(long, default_value = "generic")]
        r#type: String,
        /// Comma-separated scopes
        #[arg(long)]
        scopes: Option<String>,
    },
    /// Proxy a request through the server
    Proxy {
        /// Credential name or ID
        credential: String,
        /// HTTP method
        method: String,
        /// Target URL
        url: String,
        /// Additional headers (repeatable)
        #[arg(long)]
        header: Vec<String>,
        /// Request body (JSON)
        #[arg(long)]
        body: Option<String>,
        /// Include status code and headers in output (full envelope)
        #[arg(short, long)]
        verbose: bool,
    },
    /// List MCP servers
    McpServers,
    /// Discover tools across MCP servers
    McpTools {
        /// Filter to a specific MCP server
        #[arg(value_name = "MCP_SERVER")]
        mcp_server: Option<String>,
    },
    /// Call an MCP tool
    McpCall {
        /// MCP server name
        #[arg(value_name = "MCP_SERVER")]
        mcp_server: String,
        /// Tool name
        tool: String,
        /// Arguments as key=value pairs
        #[arg(long)]
        arg: Vec<String>,
    },
    /// Upload local MCP configs to server
    UploadMcps {
        /// Explicit config file path
        #[arg(long)]
        file: Option<String>,
    },
    /// Run as MCP server (STDIO bridge to server)
    McpServe,
    /// Re-scan .mcp.json, migrate new credentials, and update MCP config
    McpRefresh,
    /// Enroll workspace using a provisioning token (CI/CD)
    Enroll {
        /// Provisioning token from admin
        #[arg(long)]
        provision_token: String,
        /// Server URL
        #[arg(long)]
        server: Option<String>,
        /// Workspace display name
        #[arg(long)]
        name: Option<String>,
    },
    /// Show enrollment and server status
    Status,
}

/// Run a CLI command with the given global flags.
pub async fn run(cmd: CliCommand, flags: &GlobalFlags) {
    let result = match cmd {
        CliCommand::Init {
            force,
            server,
            name,
            no_mcp,
            token,
        } => init::run(flags, force, server, name, no_mcp, token).await,
        CliCommand::Register { server, code, name } => {
            register::run(flags, server, code, name).await
        }
        CliCommand::Auth => auth::run(flags).await,
        CliCommand::Credentials { action: _ } => credentials::run(flags).await,
        CliCommand::Store {
            name,
            service,
            secret,
            r#type,
            scopes,
        } => store::run(flags, &name, &service, &secret, &r#type, scopes.as_deref()).await,
        CliCommand::Proxy {
            credential,
            method,
            url,
            header,
            body,
            verbose,
        } => {
            proxy::run(
                flags,
                &credential,
                &method,
                &url,
                &header,
                body.as_deref(),
                verbose,
            )
            .await
        }
        CliCommand::McpServers => mcp_servers::run(flags).await,
        CliCommand::McpTools { mcp_server } => mcp_tools::run(flags, mcp_server.as_deref()).await,
        CliCommand::McpCall {
            mcp_server,
            tool,
            arg,
        } => mcp_call::run(flags, &mcp_server, &tool, &arg).await,
        CliCommand::UploadMcps { file } => upload_mcps::run(flags, file.as_deref()).await,
        CliCommand::McpServe => mcp_serve::run(flags).await,
        CliCommand::Enroll {
            provision_token,
            server,
            name,
        } => {
            async {
                // Enroll is a thin wrapper: ensure keys, then provision
                init::ensure_keys_exist()?;
                let server_url = server
                    .or_else(|| flags.server.clone())
                    .ok_or_else(|| "--server is required for enroll".to_string())?
                    .trim_end_matches('/')
                    .to_string();
                init::run(
                    flags,
                    false,
                    Some(server_url),
                    name,
                    false,
                    Some(provision_token),
                )
                .await
            }
            .await
        }
        CliCommand::McpRefresh => mcp_refresh_run(flags).await,
        CliCommand::Status => status::run(flags).await,
    };

    if let Err(e) = result {
        output::print_error(flags.json, &e);
        std::process::exit(1);
    }
}

/// Run the `mcp-refresh` command: re-scan .mcp.json for new servers,
/// migrate their credentials, and update MCP gateway config.
async fn mcp_refresh_run(flags: &GlobalFlags) -> Result<(), String> {
    let token = auth::ensure_jwt(flags).await?;
    let st = state::WorkspaceState::load();
    let server_url = st.resolve_server_url(&flags.server);

    let report = mcp_migrate::migrate_mcp_credentials(flags, &server_url, &token).await?;

    if !report.migrated_servers.is_empty() {
        eprintln!(
            "Migrated {} server(s): {}",
            report.migrated_servers.len(),
            report.migrated_servers.join(", ")
        );

        // Re-install MCP gateway (adds agentcordon entry, strips migrated servers)
        match mcp_install::install_mcp_gateway(None, &report.migrated_servers) {
            Ok(result) => {
                eprintln!("MCP gateway updated: {}", result.config_path.display());
            }
            Err(e) => {
                eprintln!("Warning: MCP gateway update failed: {}", e);
            }
        }

        for warning in &report.warnings {
            eprintln!("Warning: {}", warning);
        }
    } else {
        eprintln!("No new MCP servers to migrate.");
    }

    // Discover tools from all configured servers and report to the control plane.
    // This runs even if no new servers were migrated, so existing servers get
    // their tools populated in the web UI.
    eprintln!("Discovering tools from configured MCP servers...");
    mcp_tools::run(flags, None).await?;

    Ok(())
}
