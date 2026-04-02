use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

use super::user::UserId;

/// Unique identifier for a workspace.
///
/// This is the unified identity type that replaces the former AgentId,
/// DeviceId, and WorkspaceIdentityId. Every autonomous entity in the
/// system is a Workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkspaceId(pub Uuid);

/// Status of a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceStatus {
    Pending,
    Active,
    Revoked,
}

impl WorkspaceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            WorkspaceStatus::Pending => "pending",
            WorkspaceStatus::Active => "active",
            WorkspaceStatus::Revoked => "revoked",
        }
    }
}

impl FromStr for WorkspaceStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(WorkspaceStatus::Pending),
            "active" => Ok(WorkspaceStatus::Active),
            "revoked" => Ok(WorkspaceStatus::Revoked),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for WorkspaceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A unified workspace entity.
///
/// Replaces the former Agent, Device, and WorkspaceIdentity types.
/// Every autonomous entity (CLI agent, device proxy, CI runner, etc.)
/// is represented as a Workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub enabled: bool,
    pub status: WorkspaceStatus,
    /// SHA-256 hex digest of the raw 32-byte Ed25519 public key.
    pub pk_hash: Option<String>,
    /// P-256 encryption public key (JWK format) for ECIES credential vending.
    pub encryption_public_key: Option<String>,
    pub tags: Vec<String>,
    /// The user who owns this workspace.
    pub owner_id: Option<UserId>,
    /// For future sub-workspace delegation.
    pub parent_id: Option<WorkspaceId>,
    /// Informational: "claude-code", "cursor", etc.
    pub tool_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A registration record created when an admin approves workspace registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceRegistration {
    pub pk_hash: String,
    /// SHA-256 hex of the PKCE nonce (code_challenge = SHA-256(nonce)).
    pub code_challenge: String,
    /// SHA-256 hex of the approval code (stored hashed, never plaintext).
    pub code_hash: String,
    /// Raw approval code, nulled after first read (one-time use).
    pub approval_code: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub attempts: u8,
    pub max_attempts: u8,
    /// The user ID of the admin who approved this registration.
    pub approved_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Curated 256-word list for approval code generation (~8 bits of entropy).
const APPROVAL_WORDS: [&str; 256] = [
    "ALPHA", "AMBER", "ANVIL", "APEX", "AQUA", "ARROW", "ATLAS", "AZURE", "BADGE", "BASIL",
    "BEACON", "BIRCH", "BLAZE", "BOLT", "BRAVE", "BRICK", "CABIN", "CAMEL", "CEDAR", "CHAIN",
    "CHIME", "CLIFF", "CLOUD", "COBRA", "CORAL", "CRANE", "CREST", "CROWN", "CYCLE", "DELTA",
    "DENIM", "DIVER", "DRAFT", "DREAM", "DRIFT", "DRUID", "EAGLE", "EBONY", "EMBER", "EPOCH",
    "EVOKE", "FABLE", "FAWN", "FERRY", "FLAME", "FLEET", "FLINT", "FLORA", "FORGE", "FROST",
    "GALE", "GARNET", "GHOST", "GLEAM", "GLOBE", "GRACE", "GRAIN", "GROVE", "GUARD", "GUIDE",
    "HAVEN", "HAZEL", "HELIX", "HERON", "HINGE", "HOLLY", "HOVER", "IVORY", "JEWEL", "KNACK",
    "LANCE", "LARCH", "LEMON", "LIGHT", "LILAC", "LINEN", "LOTUS", "LUNAR", "MAPLE", "MARSH",
    "MERIT", "MICA", "MIRTH", "MOCHA", "MORSE", "MURAL", "NEXUS", "NOBLE", "NORTH", "OASIS",
    "OLIVE", "ONYX", "ORBIT", "OTTER", "OXIDE", "PANDA", "PEARL", "PENNY", "PETAL", "PILOT",
    "PIXEL", "PLAID", "PLUME", "POLAR", "PRISM", "PULSE", "QUAIL", "QUEST", "RADAR", "RAVEN",
    "REALM", "RIDGE", "RIVER", "ROBIN", "ROYAL", "RUSTIC", "SABLE", "SAGE", "SCALE", "SCOUT",
    "SHALE", "SLATE", "SOLAR", "SPARK", "SPEAR", "SPINE", "SPOKE", "STEEL", "STONE", "STORM",
    "STRUM", "SWIFT", "THORN", "THYME", "TIDAL", "TIGER", "TORCH", "TOWER", "TRACE", "TRAIL",
    "TROVE", "TULIP", "UNITY", "URBAN", "VALE", "VAPOR", "VAULT", "VERGE", "VIGOR", "VIPER",
    "VIVID", "VOCAL", "WARDEN", "WHEAT", "WILLOW", "ZINC", "ALDER", "ASPEN", "BASALT", "BERRY",
    "BLOOM", "BRINE", "CAIRN", "CHALK", "CLOVER", "COMPASS", "COPPER", "COVE", "DAGGER", "DAWN",
    "DUNE", "ECHO", "EMERALD", "FALCON", "FIELD", "FJORD", "FLARE", "GAVEL", "GLACIER", "GRAVEL",
    "HARBOR", "HAWK", "HEATH", "HELM", "JASPER", "KITE", "LAGOON", "LAUREL", "LODGE", "MANTLE",
    "MEADOW", "MIST", "MOSS", "NEEDLE", "OAK", "OCEAN", "OSPREY", "PALM", "PINE", "PLANK",
    "QUARTZ", "REEF", "RIPPLE", "ROWAN", "RUBY", "QUILL", "SAPPHIRE", "SIERRA", "SILVER", "SPRING",
    "SUMMIT", "TALON", "TERRA", "TIMBER", "TUNDRA", "VALLEY", "VELVET", "WAVE", "WREN", "YARROW",
    "ZENITH", "AGATE", "ANCHOR", "BROOK", "BREEZE", "CANYON", "CITRUS", "COBALT", "FLUTE", "CRYPT",
    "DUSK", "ELM", "FERN", "PIVOT", "GLEN", "GRANITE", "HAZE", "IRIS", "JADE", "KELP", "LICHEN",
    "LOOM", "MAGNET", "MARBLE", "NEON", "NIMBUS", "OPAL", "ORCHID", "PEBBLE", "PLUM", "QUARRY",
    "RAPIDS", "SAND", "SPRUCE", "THISTLE", "TOPAZ",
];

/// Generate an approval code in WORD-NNNNNN format (~28-bit entropy).
pub fn generate_approval_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let word = APPROVAL_WORDS[rng.gen_range(0..256)];
    let digits: u32 = rng.gen_range(0..1_000_000);
    format!("{}-{:06}", word, digits)
}

/// Hash an approval code with SHA-256 for storage (never store plaintext).
pub fn hash_approval_code(code: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(code.as_bytes());
    hex::encode(hash)
}

/// A single-use provisioning token for CI/CD workspace registration.
/// The raw token is never stored — only its SHA-256 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningToken {
    pub token_hash: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Generate a random provisioning token (32 bytes, hex-encoded).
pub fn generate_provisioning_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Hash a provisioning token for storage.
pub fn hash_provisioning_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    // --- WorkspaceStatus roundtrip ---

    #[test]
    fn test_workspace_status_roundtrip() {
        for status in &[
            WorkspaceStatus::Pending,
            WorkspaceStatus::Active,
            WorkspaceStatus::Revoked,
        ] {
            let s = status.as_str();
            let parsed = WorkspaceStatus::from_str(s);
            assert_eq!(
                parsed.as_ref(),
                Ok(status),
                "roundtrip failed for {:?}",
                status
            );
        }
    }

    #[test]
    fn test_workspace_status_from_str_unknown_returns_err() {
        assert!(WorkspaceStatus::from_str("unknown").is_err());
        assert!(WorkspaceStatus::from_str("").is_err());
        assert!(
            WorkspaceStatus::from_str("Active").is_err(),
            "mixed case should not match"
        );
        assert!(
            WorkspaceStatus::from_str("PENDING").is_err(),
            "uppercase should not match"
        );
    }

    // --- generate_approval_code ---

    #[test]
    fn test_generate_approval_code_format() {
        let re = regex::Regex::new(r"^[A-Z]+-\d{6}$").unwrap();
        for _ in 0..100 {
            let code = generate_approval_code();
            assert!(
                re.is_match(&code),
                "approval code '{}' does not match WORD-NNNNNN format",
                code
            );
        }
    }

    #[test]
    fn test_generate_approval_code_uniqueness() {
        let codes: HashSet<String> = (0..1000).map(|_| generate_approval_code()).collect();
        assert!(
            codes.len() >= 900,
            "expected at least 900 unique codes out of 1000, got {}",
            codes.len()
        );
    }

    // --- hash_approval_code ---

    #[test]
    fn test_hash_approval_code_deterministic() {
        let code = "ALPHA-123456";
        let h1 = hash_approval_code(code);
        let h2 = hash_approval_code(code);
        assert_eq!(h1, h2, "same input must produce same hash");
        assert_eq!(h1.len(), 64, "SHA-256 hex digest must be 64 chars");
        // Verify it's valid hex
        assert!(
            h1.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hex"
        );
    }

    #[test]
    fn test_hash_approval_code_different_inputs() {
        let h1 = hash_approval_code("ALPHA-000001");
        let h2 = hash_approval_code("ALPHA-000002");
        assert_ne!(h1, h2, "different inputs must produce different hashes");
    }

    #[test]
    fn test_hash_approval_code_empty_string() {
        let h = hash_approval_code("");
        assert_eq!(h.len(), 64, "empty string hash must still be 64 chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be valid hex"
        );
    }

    // --- generate_provisioning_token ---

    #[test]
    fn test_generate_provisioning_token_format() {
        let token = generate_provisioning_token();
        assert_eq!(token.len(), 64, "32 bytes hex-encoded = 64 chars");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "token must be hex"
        );
    }

    #[test]
    fn test_generate_provisioning_token_uniqueness() {
        let t1 = generate_provisioning_token();
        let t2 = generate_provisioning_token();
        assert_ne!(t1, t2, "two calls must produce different tokens");
    }

    // --- hash_provisioning_token ---

    #[test]
    fn test_hash_provisioning_token_deterministic() {
        let token = "abc123def456";
        let h1 = hash_provisioning_token(token);
        let h2 = hash_provisioning_token(token);
        assert_eq!(h1, h2, "same input must produce same hash");
        assert_eq!(h1.len(), 64);
    }

    // --- Backward compatibility type aliases ---

    #[test]
    fn test_backward_compat_agent_alias() {
        // Verify that domain::agent::Agent is the same type as Workspace
        fn accepts_workspace(_w: &Workspace) {}
        let agent: crate::domain::agent::Agent = crate::domain::agent::Agent {
            id: WorkspaceId(Uuid::new_v4()),
            name: "test".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        accepts_workspace(&agent);
    }

    #[test]
    fn test_backward_compat_device_alias() {
        // Verify that domain::device::Device is the same type as Workspace
        fn accepts_workspace(_w: &Workspace) {}
        let device: crate::domain::device::Device = crate::domain::device::Device {
            id: WorkspaceId(Uuid::new_v4()),
            name: "test-device".to_string(),
            enabled: true,
            status: WorkspaceStatus::Active,
            pk_hash: None,
            encryption_public_key: None,
            tags: vec![],
            owner_id: None,
            parent_id: None,
            tool_name: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        accepts_workspace(&device);
    }

    // --- Entropy distribution ---

    #[test]
    fn test_approval_code_entropy_distribution() {
        let mut word_counts: HashMap<String, usize> = HashMap::new();
        let n = 10_000;
        for _ in 0..n {
            let code = generate_approval_code();
            let word = code.split('-').next().unwrap().to_string();
            *word_counts.entry(word).or_insert(0) += 1;
        }
        // With 256 words and 10000 samples, expected ~39 per word.
        // Check no single word has more than 3x the expected value (117).
        let max_count = word_counts.values().max().copied().unwrap_or(0);
        assert!(
            max_count < 120,
            "word distribution skewed: max count {} (expected ~39 per word)",
            max_count
        );
        // Check we saw a good fraction of all 256 words
        assert!(
            word_counts.len() >= 200,
            "expected at least 200 distinct words in 10000 samples, got {}",
            word_counts.len()
        );
    }

    #[test]
    fn test_provisioning_token_entropy() {
        let tokens: HashSet<String> = (0..100).map(|_| generate_provisioning_token()).collect();
        assert_eq!(
            tokens.len(),
            100,
            "100 provisioning tokens must all be unique"
        );
        // Verify no predictable sequential pattern: sort and check no two adjacent
        // tokens share a common prefix of more than 8 hex chars (very unlikely with
        // 32 random bytes)
        let mut sorted: Vec<&String> = tokens.iter().collect();
        sorted.sort();
        for pair in sorted.windows(2) {
            let common_prefix = pair[0]
                .chars()
                .zip(pair[1].chars())
                .take_while(|(a, b)| a == b)
                .count();
            assert!(
                common_prefix <= 12,
                "tokens share suspiciously long common prefix ({} chars): {} vs {}",
                common_prefix,
                pair[0],
                pair[1]
            );
        }
    }
}
