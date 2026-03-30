use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::CliError;
use crate::signing::workspace_dir;

/// Generate Ed25519 keypair and prepare workspace for registration.
pub fn run() -> Result<(), CliError> {
    let dir = workspace_dir();
    let key_path = dir.join("workspace.key");
    let pub_path = dir.join("workspace.pub");

    // Idempotent: if key already exists, just print identity
    if key_path.exists() {
        let pub_hex = fs::read_to_string(&pub_path)
            .map_err(|e| CliError::general(format!("failed to read public key: {e}")))?;
        let pub_bytes = hex::decode(pub_hex.trim())
            .map_err(|e| CliError::general(format!("invalid public key format: {e}")))?;
        let hash = hex::encode(Sha256::digest(&pub_bytes));
        println!("Workspace identity: sha256:{hash}");
        println!("(keypair already exists)");
        return Ok(());
    }

    // Create .agentcordon/ directory with mode 0700
    fs::create_dir_all(&dir)
        .map_err(|e| CliError::general(format!("failed to create .agentcordon/: {e}")))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| CliError::general(format!("failed to set directory permissions: {e}")))?;

    // Generate Ed25519 keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Write private key (hex seed, mode 0600)
    let seed_hex = hex::encode(signing_key.to_bytes());
    fs::write(&key_path, &seed_hex)
        .map_err(|e| CliError::general(format!("failed to write private key: {e}")))?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::general(format!("failed to set key permissions: {e}")))?;

    // Write public key (hex, mode 0644)
    let pub_hex = hex::encode(verifying_key.to_bytes());
    fs::write(&pub_path, &pub_hex)
        .map_err(|e| CliError::general(format!("failed to write public key: {e}")))?;
    fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))
        .map_err(|e| CliError::general(format!("failed to set pubkey permissions: {e}")))?;

    // Compute pk_hash
    let hash = hex::encode(Sha256::digest(verifying_key.to_bytes()));
    println!("Workspace identity: sha256:{hash}");

    // Add .agentcordon/ to .gitignore
    add_to_gitignore()?;

    Ok(())
}

/// Add `.agentcordon/` to `.gitignore` if not already present.
fn add_to_gitignore() -> Result<(), CliError> {
    let base = std::env::var("AGTCRDN_WORKSPACE_DIR").unwrap_or_else(|_| ".".to_string());
    let gitignore_path = Path::new(&base).join(".gitignore");

    let entry = ".agentcordon/";

    if gitignore_path.exists() {
        let content = fs::read_to_string(&gitignore_path)
            .map_err(|e| CliError::general(format!("failed to read .gitignore: {e}")))?;
        if content.lines().any(|line| line.trim() == entry) {
            return Ok(());
        }
        // Append with newline separation
        let separator = if content.ends_with('\n') { "" } else { "\n" };
        fs::write(&gitignore_path, format!("{content}{separator}{entry}\n"))
            .map_err(|e| CliError::general(format!("failed to update .gitignore: {e}")))?;
    } else {
        fs::write(&gitignore_path, format!("{entry}\n"))
            .map_err(|e| CliError::general(format!("failed to create .gitignore: {e}")))?;
    }

    Ok(())
}
