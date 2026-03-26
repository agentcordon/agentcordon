use agent_cordon_core::crypto::ed25519;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use crate::identity::WorkspaceIdentity;

use super::output;
use super::state::{self, WorkspaceState};
use super::GlobalFlags;

/// Ensure workspace keys exist. If they already exist, returns Ok(false).
/// If they don't exist, generates them and returns Ok(true).
pub fn ensure_keys_exist() -> Result<bool, String> {
    if state::has_workspace_key() {
        return Ok(false);
    }
    let dir = state::workspace_dir();

    // Generate Ed25519 keypair
    let (signing_key, _verifying_key) = ed25519::generate_workspace_keypair();
    ed25519::save_keypair(&dir, &signing_key)
        .map_err(|e| format!("failed to save Ed25519 keypair: {}", e))?;

    // Generate P-256 encryption keypair
    let mut rng = rand::rngs::OsRng;
    let encryption_key = p256::SecretKey::random(&mut rng);
    WorkspaceIdentity::save_encryption_key(&dir, &encryption_key)
        .map_err(|e| format!("failed to save P-256 encryption keypair: {}", e))?;

    // Update state with public key info
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to reload keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();
    let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);
    let pub_hex = hex::encode(pubkey.to_bytes());

    let mut st = WorkspaceState::load();
    st.workspace_public_key = Some(pub_hex);
    st.workspace_pk_hash = Some(pk_hash);
    st.save()?;

    // Add .agentcordon/ to .gitignore
    add_to_gitignore();

    Ok(true)
}

/// Build a default workspace name from hostname and current directory.
fn default_workspace_name() -> String {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    // Strip leading slash for cleaner display (e.g. "host/Users/dan/app" not "host//Users/dan/app")
    let cwd_trimmed = cwd.strip_prefix('/').unwrap_or(&cwd);
    format!("{}/{}", hostname, cwd_trimmed)
}

pub async fn run(
    flags: &GlobalFlags,
    force: bool,
    server: Option<String>,
    name: Option<String>,
    no_mcp: bool,
    token: Option<String>,
) -> Result<(), String> {
    // Step 1: Ensure keys exist (or regenerate with --force)
    let generated = if force || !state::has_workspace_key() {
        ensure_keys_exist_or_force(flags, force)?
    } else {
        false
    };

    // If no --server, just do key generation (original behavior)
    let server_url = match server {
        Some(s) => s.trim_end_matches('/').to_string(),
        None if token.is_some() => {
            return Err("--token requires --server".to_string());
        }
        None => {
            if !generated {
                print_existing_identity(flags)?;
            }
            return Ok(());
        }
    };

    // Default the workspace name to HOSTNAME/CWD if not explicitly provided
    let name = name.or_else(|| Some(default_workspace_name()));

    let st = WorkspaceState::load();

    // Step 2: Check if already registered
    if st.agent_id.is_some() && token.is_none() {
        output::print_result(
            flags.json,
            "Already registered. Skipping to MCP install.",
            &serde_json::json!({
                "status": "already_registered",
                "workspace_id": st.agent_id,
            }),
        );
    } else if let Some(provision_token) = token {
        // CI/CD provisioning flow
        run_provisioning(flags, &server_url, &provision_token, name).await?;
    } else {
        // Interactive registration flow
        run_interactive_registration(flags, &server_url, name).await?;
    }

    // Step 2.5: Migrate MCP credentials from .mcp.json (if registered)
    let mut migrated_servers = Vec::new();
    if !no_mcp {
        let st = WorkspaceState::load();
        if st.agent_id.is_some() {
            match super::auth::ensure_jwt(flags).await {
                Ok(token) => {
                    let server_url = st.resolve_server_url(&flags.server);
                    match super::mcp_migrate::migrate_mcp_credentials(flags, &server_url, &token)
                        .await
                    {
                        Ok(report) => {
                            if !report.migrated_servers.is_empty() {
                                eprintln!(
                                    "Migrated credentials for {} MCP server(s)",
                                    report.migrated_servers.len()
                                );
                            }
                            migrated_servers = report.migrated_servers;
                            for warning in &report.warnings {
                                eprintln!("Warning: {}", warning);
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: MCP credential migration failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Could not obtain JWT for credential migration: {}",
                        e
                    );
                }
            }
        }
    }

    // Step 3: MCP install (skip for --no-mcp; always skip for CI/CD --token)
    if !no_mcp {
        match super::mcp_install::install_mcp_gateway(None, &migrated_servers) {
            Ok(result) => {
                output::print_result(
                    flags.json,
                    &format!("MCP gateway installed: {}", result.config_path.display()),
                    &serde_json::json!({
                        "mcp_installed": true,
                        "config_path": result.config_path.display().to_string(),
                    }),
                );
            }
            Err(e) => {
                eprintln!(
                    "Warning: MCP install failed: {}. You can install manually with: agentcordon mcp-install",
                    e
                );
            }
        }
    }

    // Step 3.5: Discover and report MCP tools to the server
    if !no_mcp {
        let st = WorkspaceState::load();
        if st.agent_id.is_some() {
            eprintln!("Discovering MCP tools...");
            if let Err(e) = super::mcp_tools::run(flags, None).await {
                eprintln!("Warning: tool discovery failed: {}", e);
            }
        }
    }

    // Step 4: Update CLAUDE.md
    super::claude_md::update_claude_md();

    eprintln!("\n✓ Ready to go!");
    Ok(())
}

/// Generate keys if needed, or regenerate with --force. Returns true if new keys were created.
fn ensure_keys_exist_or_force(flags: &GlobalFlags, force: bool) -> Result<bool, String> {
    let dir = state::workspace_dir();

    if state::has_workspace_key() && !force {
        return Ok(false);
    }

    // Generate Ed25519 keypair
    let (signing_key, verifying_key) = ed25519::generate_workspace_keypair();
    ed25519::save_keypair(&dir, &signing_key)
        .map_err(|e| format!("failed to save Ed25519 keypair: {}", e))?;

    // Generate P-256 encryption keypair
    let mut rng = rand::rngs::OsRng;
    let encryption_key = p256::SecretKey::random(&mut rng);
    WorkspaceIdentity::save_encryption_key(&dir, &encryption_key)
        .map_err(|e| format!("failed to save P-256 encryption keypair: {}", e))?;

    // Compute identity
    let pk_hash_hex = ed25519::compute_pk_hash(&verifying_key.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);
    let pub_hex = hex::encode(verifying_key.to_bytes());

    let identity = WorkspaceIdentity {
        ed25519_key: signing_key,
        encryption_key,
        pk_hash: pk_hash.clone(),
    };
    let enc_fingerprint = identity.encryption_fingerprint();

    // Update state
    let mut st = WorkspaceState::load();
    st.workspace_public_key = Some(pub_hex.clone());
    st.workspace_pk_hash = Some(pk_hash.clone());
    st.save()?;

    add_to_gitignore();

    output::print_result(
        flags.json,
        &format!(
            "Workspace identity created in {}/\n\nAC_IDENTITY: {}\nEncryption fingerprint: {}",
            dir.display(),
            pk_hash,
            &enc_fingerprint[..16],
        ),
        &serde_json::json!({
            "status": "created",
            "identity": pk_hash,
            "public_key": pub_hex,
            "encryption_fingerprint": enc_fingerprint,
            "key_dir": dir.display().to_string(),
        }),
    );

    Ok(true)
}

/// Print existing identity info (when init is called without --force and keys exist).
fn print_existing_identity(flags: &GlobalFlags) -> Result<(), String> {
    let dir = state::workspace_dir();
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to load keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();
    let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);
    let pub_hex = hex::encode(pubkey.to_bytes());

    let has_enc = WorkspaceIdentity::has_encryption_key(&dir);
    let enc_fingerprint = if has_enc {
        WorkspaceIdentity::load_from_dir(&dir)
            .ok()
            .map(|id| id.encryption_fingerprint())
    } else {
        None
    };

    let mut json = serde_json::json!({
        "status": "exists",
        "identity": pk_hash,
        "public_key": pub_hex,
        "key_dir": dir.display().to_string(),
        "has_encryption_key": has_enc,
    });
    if let Some(ref fp) = enc_fingerprint {
        json["encryption_fingerprint"] = serde_json::Value::String(fp.clone());
    }

    output::print_result(
        flags.json,
        &format!(
            "Workspace identity already exists in {}/\n\nAC_IDENTITY: {}\nEncryption key: {}\n\nUse --force to overwrite, or --server <url> to register.",
            dir.display(),
            pk_hash,
            if has_enc { "present" } else { "missing (run init --force to regenerate)" },
        ),
        &json,
    );

    Ok(())
}

/// Interactive registration flow: start → browser → poll → complete.
async fn run_interactive_registration(
    flags: &GlobalFlags,
    server_url: &str,
    name: Option<String>,
) -> Result<(), String> {
    let dir = state::workspace_dir();
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to load keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();
    let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);
    let pub_hex = hex::encode(pubkey.to_bytes());

    // Phase 1: Start registration
    let reg_info = super::register::start_registration(&pk_hash, server_url, name.as_deref())?;

    eprintln!("Registration URL:\n  {}\n", reg_info.url);
    eprintln!("Fingerprint: {}\n", reg_info.fingerprint);

    // Attempt browser open (best effort)
    attempt_browser_open(&reg_info.url);

    eprintln!("Waiting for admin approval... (Ctrl+C to cancel)");

    // Phase 2: Poll for approval
    let approval_code = super::poll::poll_for_approval(
        server_url,
        &pk_hash,
        &reg_info.code_challenge,
        std::time::Duration::from_secs(300),
    )
    .await?;

    eprintln!("✓ Registration approved!");

    // Phase 3: Complete registration
    super::register::complete_registration(
        flags,
        &signing_key,
        &pub_hex,
        &pk_hash,
        &pk_hash_hex,
        &approval_code,
        server_url,
        name,
        true,
    )
    .await?;

    Ok(())
}

/// CI/CD provisioning flow: exchange token for workspace registration.
async fn run_provisioning(
    flags: &GlobalFlags,
    server_url: &str,
    token: &str,
    name: Option<String>,
) -> Result<(), String> {
    let dir = state::workspace_dir();
    let signing_key =
        ed25519::load_keypair(&dir).map_err(|e| format!("failed to load keypair: {}", e))?;
    let pubkey = signing_key.verifying_key();
    let pub_hex = hex::encode(pubkey.to_bytes());
    let pk_hash_hex = ed25519::compute_pk_hash(&pubkey.to_bytes());
    let pk_hash = format!("sha256:{}", pk_hash_hex);

    let mut body = serde_json::json!({
        "token": token,
        "public_key": pub_hex,
    });
    if let Some(ref n) = name {
        body["name"] = serde_json::Value::String(n.clone());
    }

    // Include encryption key if available
    if WorkspaceIdentity::has_encryption_key(&dir) {
        if let Ok(identity) = WorkspaceIdentity::load_from_dir(&dir) {
            let enc_pub = identity.encryption_key.public_key();
            let enc_point = enc_pub.to_encoded_point(false);
            body["encryption_key"] = super::register::p256_point_to_jwk(enc_point.as_bytes());
        }
    }

    let client = super::client::ApiClient::new(server_url);
    let resp: super::client::ApiResponse<serde_json::Value> = client
        .post_unauth("/api/v1/workspaces/provision/complete", &body)
        .await
        .map_err(|e| format!("provisioning failed: {}", e))?;

    let workspace_id = resp
        .data
        .get("workspace_id")
        .and_then(|v| v.as_str())
        .ok_or("missing workspace_id in response")?;
    let jwt = resp
        .data
        .get("identity_jwt")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Save state
    let mut st = WorkspaceState::load();
    st.agent_id = Some(workspace_id.to_string());
    st.workspace_public_key = Some(pub_hex);
    st.workspace_pk_hash = Some(pk_hash);
    st.server_url = Some(server_url.to_string());
    if !jwt.is_empty() {
        st.jwt = Some(jwt.to_string());
    }
    st.save()?;

    output::print_result(
        flags.json,
        &format!("✓ Provisioned! Workspace ID: {}", workspace_id),
        &serde_json::json!({
            "status": "provisioned",
            "workspace_id": workspace_id,
        }),
    );

    Ok(())
}

fn attempt_browser_open(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
}

fn add_to_gitignore() {
    let gitignore = std::path::Path::new(".gitignore");
    let entry = ".agentcordon/";

    if gitignore.exists() {
        if let Ok(contents) = std::fs::read_to_string(gitignore) {
            if contents.contains(entry) {
                return;
            }
            let separator = if contents.ends_with('\n') { "" } else { "\n" };
            let _ = std::fs::write(
                gitignore,
                format!(
                    "{}{}\n# AgentCordon workspace identity\n{}\n",
                    contents, separator, entry
                ),
            );
        }
    } else {
        let _ = std::fs::write(
            gitignore,
            format!("# AgentCordon workspace identity\n{}\n", entry),
        );
    }
}
