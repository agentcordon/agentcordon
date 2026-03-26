use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const STATE_DIR: &str = ".agentcordon";
const STATE_FILE: &str = "state.json";

/// Workspace state persisted in `.agentcordon/state.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorkspaceState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_pk_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

impl WorkspaceState {
    /// Load state from `.agentcordon/state.json` in the current directory.
    pub fn load() -> Self {
        let path = state_path();
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save state to `.agentcordon/state.json`, creating the directory if needed.
    pub fn save(&self) -> Result<(), String> {
        let dir = state_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create {}: {}", dir.display(), e))?;
        let path = dir.join(STATE_FILE);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize state: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("failed to write {}: {}", path.display(), e))
    }

    /// Resolve server URL: flag > env > state > default.
    pub fn resolve_server_url(&self, flag: &Option<String>) -> String {
        if let Some(url) = flag {
            return url.trim_end_matches('/').to_string();
        }
        if let Ok(url) = std::env::var("AGENTCORDON_SERVER_URL") {
            if !url.is_empty() {
                return url.trim_end_matches('/').to_string();
            }
        }
        if let Some(ref url) = self.server_url {
            if !url.is_empty() {
                return url.trim_end_matches('/').to_string();
            }
        }
        "http://localhost:3140".to_string()
    }

    /// Check if the JWT is still valid (not expired, with 30s buffer).
    pub fn jwt_valid(&self) -> bool {
        let jwt = match &self.jwt {
            Some(j) if !j.is_empty() => j,
            _ => return false,
        };
        let _ = jwt; // just checking non-empty
        let expires_at = match &self.jwt_expires_at {
            Some(e) => match e.parse::<i64>() {
                Ok(v) => v,
                Err(_) => return false,
            },
            None => return false,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now < (expires_at - 30)
    }
}

fn state_dir() -> PathBuf {
    Path::new(STATE_DIR).to_path_buf()
}

fn state_path() -> PathBuf {
    state_dir().join(STATE_FILE)
}

/// Path to the workspace key directory.
pub fn workspace_dir() -> PathBuf {
    Path::new(STATE_DIR).to_path_buf()
}

/// Check if workspace keys exist.
pub fn has_workspace_key() -> bool {
    let dir = workspace_dir();
    dir.join("workspace.key").exists() && dir.join("workspace.pub").exists()
}
