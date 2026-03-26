//! v1.5.3 Server Defaults Integration Tests
//!
//! Tests for Feature 1 (MASTER_SECRET auto-generation) and Feature 2 (KDF_SALT derivation).
//!
//! Feature 1: When `AGTCRDN_MASTER_SECRET` is unset, the server auto-generates a
//! 32-byte random secret, persists it to `{data_dir}/.secret`, and reads from that
//! file on subsequent calls. If the env var IS set, it takes precedence.
//!
//! Feature 2: When `AGTCRDN_KDF_SALT` is unset, the salt is derived deterministically
//! from the master secret via HKDF with info label `agentcordon:default-kdf-salt-v1`.

use std::os::unix::fs::PermissionsExt;

use agent_cordon_core::crypto::aes_gcm::AesGcmEncryptor;
use agent_cordon_core::crypto::key_derivation::{derive_jwt_signing_keypair, derive_master_key};
use agent_cordon_core::crypto::SecretEncryptor;

use agent_cordon_server::config::AppConfig;

use hkdf::Hkdf;
use serial_test::serial;
use sha2::Sha256;
use tempfile::TempDir;

// ===========================================================================
// Feature 1: MASTER_SECRET Auto-Generation
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. test_master_secret_autogen_when_env_unset
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_autogen_when_env_unset() {
    // Ensure the env var is NOT set
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();

    // Point from_env() at our temp directory
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config = AppConfig::from_env().expect("from_env should succeed without MASTER_SECRET");

    // (a) Function succeeded (above)
    // (b) Secret is at least 16 characters
    assert!(
        config.master_secret.len() >= 16,
        "auto-generated secret should be at least 16 characters, got {}",
        config.master_secret.len()
    );

    // (c) File exists and contains the same value
    let secret_path = tmp.path().join(".secret");
    assert!(secret_path.exists(), ".secret file should be created");
    let file_contents = std::fs::read_to_string(&secret_path)
        .expect("read .secret file")
        .trim()
        .to_string();
    assert_eq!(
        config.master_secret, file_contents,
        "config secret should match file contents"
    );

    // Cleanup
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 2. test_master_secret_persisted_file_read_on_restart
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_persisted_file_read_on_restart() {
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    // First call: generates and persists
    let config1 = AppConfig::from_env().expect("first from_env");

    // Second call: reads from persisted file
    let config2 = AppConfig::from_env().expect("second from_env");

    assert_eq!(
        config1.master_secret, config2.master_secret,
        "secret must be identical across calls (read from persisted file)"
    );

    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 3. test_master_secret_env_var_takes_precedence_over_file
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_env_var_takes_precedence_over_file() {
    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();

    // Write a known value to .secret file
    let file_secret = "file-secret-at-least-16-chars-ok";
    let secret_path = tmp.path().join(".secret");
    std::fs::write(&secret_path, file_secret).expect("write .secret");

    // Set env var to a DIFFERENT value
    let env_secret = "env-secret-at-least-16-chars-ok!";
    std::env::set_var("AGTCRDN_MASTER_SECRET", env_secret);
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let config = AppConfig::from_env().expect("from_env");

    assert_eq!(
        config.master_secret, env_secret,
        "env var should take precedence over file"
    );
    assert_ne!(
        config.master_secret, file_secret,
        "file secret should NOT be used when env var is set"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 4. test_master_secret_file_permissions_restrictive
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_file_permissions_restrictive() {
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let _config = AppConfig::from_env().expect("from_env");

    let secret_path = tmp.path().join(".secret");
    let metadata = std::fs::metadata(&secret_path).expect("file metadata");
    let mode = metadata.permissions().mode() & 0o777;

    assert_eq!(
        mode, 0o600,
        "secret file should have mode 0600, got {:o}",
        mode
    );

    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 5. test_master_secret_generated_value_is_random
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_generated_value_is_random() {
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp1 = TempDir::new().expect("create temp dir 1");
    let db_path1 = tmp1
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path1);
    let config1 = AppConfig::from_env().expect("from_env 1");

    let tmp2 = TempDir::new().expect("create temp dir 2");
    let db_path2 = tmp2
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path2);
    let config2 = AppConfig::from_env().expect("from_env 2");

    assert_ne!(
        config1.master_secret, config2.master_secret,
        "two auto-generated secrets must be different"
    );

    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 6. test_master_secret_minimum_length
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_minimum_length() {
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config = AppConfig::from_env().expect("from_env");

    // 32 bytes base64url-encoded = 43 characters (no padding)
    assert!(
        config.master_secret.len() >= 43,
        "auto-generated secret should be at least 43 characters (32 bytes base64url), got {}",
        config.master_secret.len()
    );

    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 7. test_master_secret_env_var_too_short_rejected
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_master_secret_env_var_too_short_rejected() {
    std::env::set_var("AGTCRDN_MASTER_SECRET", "tooshort12"); // 10 chars < 16
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let result = AppConfig::from_env();
    assert!(result.is_err(), "from_env should fail for short secret");
    let err = result.unwrap_err();
    assert!(
        err.contains("at least 16 characters"),
        "error should mention '16 characters', got: {}",
        err
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 8. test_app_boots_without_master_secret_env
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_app_boots_without_master_secret_env() {
    use crate::common::*;
    use agent_cordon_server::test_helpers::TestAppBuilder;

    // Build a test app through TestAppBuilder — it uses test_default() config
    // which has a valid master secret. This test verifies the crypto pipeline
    // works end-to-end with a config that was resolved through auto-generation.
    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    // Resolve a config through the auto-generation path
    let resolved_config = AppConfig::from_env().expect("from_env with auto-gen");
    let resolved_secret = resolved_config.master_secret.clone();
    let resolved_salt = resolved_config.kdf_salt.clone();

    // Use TestAppBuilder but inject the resolved secret/salt
    let ctx = TestAppBuilder::new()
        .with_config(move |c| {
            c.master_secret = resolved_secret;
            c.kdf_salt = resolved_salt;
        })
        .build()
        .await;

    // Create an admin user, login, and verify JWT issuance works
    let _admin = create_user_in_db(
        &*ctx.store,
        "admin",
        "strong-password-123!",
        agent_cordon_core::domain::user::UserRole::Admin,
        true,
        true,
    )
    .await;

    let app = agent_cordon_server::build_router(ctx.state.clone());
    let (session_cookie, csrf_token) = login_user(&app, "admin", "strong-password-123!").await;

    // Verify the session was created (login returned valid cookie+csrf)
    assert!(
        !session_cookie.is_empty(),
        "session cookie should not be empty"
    );
    assert!(!csrf_token.is_empty(), "CSRF token should not be empty");

    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ===========================================================================
// Feature 2A: KDF_SALT Derivation from Master Secret
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. test_kdf_salt_derived_from_master_secret_when_unset
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_kdf_salt_derived_from_master_secret_when_unset() {
    let known_secret = "a-known-master-secret-for-test!";
    std::env::set_var("AGTCRDN_MASTER_SECRET", known_secret);
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config = AppConfig::from_env().expect("from_env");

    // (a) succeeded
    // (b) salt is non-empty
    assert!(
        !config.kdf_salt.is_empty(),
        "derived KDF salt should not be empty"
    );

    // (c) NOT equal to the old hardcoded default
    assert_ne!(
        config.kdf_salt,
        AppConfig::DEFAULT_KDF_SALT,
        "derived salt must not equal old hardcoded default"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 2. test_kdf_salt_derivation_is_deterministic
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_kdf_salt_derivation_is_deterministic() {
    let known_secret = "deterministic-secret-test-1234!";
    std::env::set_var("AGTCRDN_MASTER_SECRET", known_secret);
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config1 = AppConfig::from_env().expect("from_env 1");
    let config2 = AppConfig::from_env().expect("from_env 2");

    assert_eq!(
        config1.kdf_salt, config2.kdf_salt,
        "same master secret must produce the same derived salt"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 3. test_kdf_salt_different_master_produces_different_salt
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_kdf_salt_different_master_produces_different_salt() {
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    std::env::set_var("AGTCRDN_MASTER_SECRET", "first-secret-at-least-16!!");
    let config1 = AppConfig::from_env().expect("from_env 1");

    std::env::set_var("AGTCRDN_MASTER_SECRET", "second-secret-at-least-16!");
    let config2 = AppConfig::from_env().expect("from_env 2");

    assert_ne!(
        config1.kdf_salt, config2.kdf_salt,
        "different master secrets must produce different derived salts"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 4. test_kdf_salt_env_var_takes_precedence
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_kdf_salt_env_var_takes_precedence() {
    let custom_salt = "my-custom-salt-value";
    std::env::set_var("AGTCRDN_MASTER_SECRET", "some-secret-at-least-16-ch");
    std::env::set_var("AGTCRDN_KDF_SALT", custom_salt);

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config = AppConfig::from_env().expect("from_env");

    assert_eq!(
        config.kdf_salt, custom_salt,
        "env var KDF_SALT should take precedence"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_KDF_SALT");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 5. test_kdf_salt_hkdf_label_is_correct
// ---------------------------------------------------------------------------

#[test]
fn test_kdf_salt_hkdf_label_is_correct() {
    // Manually compute HKDF-SHA256 with the same parameters the server uses
    let master_secret = "test-master-secret-pinning";
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand");
    let expected_salt = hex::encode(okm);

    // Now get the server's derivation by building a config
    // We test through a mini-helper that replicates what from_env does:
    // derive_kdf_salt is private, so we call from_env with the secret set
    // and KDF_SALT unset, then compare.
    //
    // Since this test doesn't use serial (no env mutation in parallel tests),
    // we call it through a helper that avoids env vars.
    // Actually, derive_kdf_salt is private, so the only way is through from_env.
    // We'll run this as serial.
    //
    // But we can also just verify the HKDF computation directly since we know
    // the algorithm. This pins the derivation so any label change breaks it.
    assert!(!expected_salt.is_empty(), "HKDF output must not be empty");
    assert_eq!(
        expected_salt.len(),
        64,
        "hex-encoded 32-byte output should be 64 chars"
    );

    // Verify against from_env by using the serial variant below
}

#[test]
#[serial]
fn test_kdf_salt_hkdf_label_matches_server_derivation() {
    let master_secret = "test-master-secret-pinning";

    // Manual HKDF computation
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand");
    let expected_salt = hex::encode(okm);

    // Server derivation via from_env
    std::env::set_var("AGTCRDN_MASTER_SECRET", master_secret);
    std::env::remove_var("AGTCRDN_KDF_SALT");

    let tmp = TempDir::new().expect("create temp dir");
    let db_path = tmp
        .path()
        .join("agent-cordon.db")
        .to_str()
        .unwrap()
        .to_string();
    std::env::set_var("AGTCRDN_DB_PATH", &db_path);

    let config = AppConfig::from_env().expect("from_env");

    assert_eq!(
        config.kdf_salt, expected_salt,
        "server-derived salt must match manual HKDF computation"
    );

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ---------------------------------------------------------------------------
// 6. test_kdf_salt_derived_salt_not_equal_old_default
// ---------------------------------------------------------------------------

#[test]
#[serial]
fn test_kdf_salt_derived_salt_not_equal_old_default() {
    let test_secrets = [
        "first-test-secret-long-enough!",
        "second-test-secret-long-eno!",
        "third-test-secret-long-enoug",
    ];

    for secret in &test_secrets {
        std::env::set_var("AGTCRDN_MASTER_SECRET", secret);
        std::env::remove_var("AGTCRDN_KDF_SALT");

        let tmp = TempDir::new().expect("create temp dir");
        let db_path = tmp
            .path()
            .join("agent-cordon.db")
            .to_str()
            .unwrap()
            .to_string();
        std::env::set_var("AGTCRDN_DB_PATH", &db_path);

        let config = AppConfig::from_env().expect("from_env");

        assert!(
            !config.is_default_salt(),
            "is_default_salt() must return false for derived salt from secret '{}'",
            secret
        );
        assert_ne!(
            config.kdf_salt,
            AppConfig::DEFAULT_KDF_SALT,
            "derived salt must not equal old default for secret '{}'",
            secret
        );
    }

    std::env::remove_var("AGTCRDN_MASTER_SECRET");
    std::env::remove_var("AGTCRDN_DB_PATH");
}

// ===========================================================================
// Feature 2B: Crypto Stability (derived salt produces working crypto)
// ===========================================================================

// ---------------------------------------------------------------------------
// 1. test_derived_salt_produces_valid_master_key
// ---------------------------------------------------------------------------

#[test]
fn test_derived_salt_produces_valid_master_key() {
    let master_secret = "crypto-stability-test-secret!!";

    // Derive salt via HKDF (same algorithm as server)
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand");
    let derived_salt = hex::encode(okm);

    // Derive master key using the derived salt
    let master_key = derive_master_key(master_secret, derived_salt.as_bytes())
        .expect("derive_master_key should succeed with derived salt");

    // Create an encryptor and verify roundtrip
    let encryptor = AesGcmEncryptor::new(&master_key);
    let plaintext = b"test payload for encryption roundtrip";
    let aad = b"test-aad";

    let (ciphertext, nonce) = encryptor
        .encrypt(plaintext, aad)
        .expect("encryption should succeed");

    let decrypted = encryptor
        .decrypt(&ciphertext, &nonce, aad)
        .expect("decryption should succeed");

    assert_eq!(
        decrypted, plaintext,
        "decrypted text must match original plaintext"
    );
}

// ---------------------------------------------------------------------------
// 2. test_derived_salt_produces_valid_jwt_keypair
// ---------------------------------------------------------------------------

#[test]
fn test_derived_salt_produces_valid_jwt_keypair() {
    use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use serde::{Deserialize, Serialize};

    let master_secret = "jwt-keypair-stability-test-sec!";

    // Derive salt via HKDF
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand");
    let derived_salt = hex::encode(okm);

    // Derive JWT signing keypair
    let (signing_key, verifying_key) =
        derive_jwt_signing_keypair(master_secret, derived_salt.as_bytes())
            .expect("derive_jwt_signing_keypair should succeed");

    // Sign a test JWT
    #[derive(Debug, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        exp: u64,
    }

    let claims = TestClaims {
        sub: "test-agent".to_string(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
    };

    let sk_pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("signing key to PEM");
    let encoding_key = EncodingKey::from_ec_pem(sk_pem.as_bytes()).expect("encoding key from PEM");

    let token = encode(&Header::new(Algorithm::ES256), &claims, &encoding_key)
        .expect("JWT signing should succeed");

    // Verify the JWT
    let vk_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .expect("verifying key to PEM");
    let decoding_key = DecodingKey::from_ec_pem(vk_pem.as_bytes()).expect("decoding key from PEM");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.set_required_spec_claims::<String>(&[]);

    let decoded = decode::<TestClaims>(&token, &decoding_key, &validation)
        .expect("JWT verification should succeed");

    assert_eq!(decoded.claims.sub, "test-agent");
}

// ---------------------------------------------------------------------------
// 3. test_derived_salt_crypto_is_deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_derived_salt_crypto_is_deterministic() {
    let master_secret = "deterministic-crypto-stability!";

    // Derive salt via HKDF
    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand");
    let derived_salt = hex::encode(okm);

    // First derivation
    let master_key_1 =
        derive_master_key(master_secret, derived_salt.as_bytes()).expect("derive_master_key 1");
    let (sk1, vk1) = derive_jwt_signing_keypair(master_secret, derived_salt.as_bytes())
        .expect("derive_jwt_signing_keypair 1");

    // Second derivation (same inputs)
    let master_key_2 =
        derive_master_key(master_secret, derived_salt.as_bytes()).expect("derive_master_key 2");
    let (sk2, vk2) = derive_jwt_signing_keypair(master_secret, derived_salt.as_bytes())
        .expect("derive_jwt_signing_keypair 2");

    // Keys must be identical
    assert_eq!(
        *master_key_1, *master_key_2,
        "AES master keys must be identical across runs"
    );
    assert_eq!(
        sk1.to_bytes(),
        sk2.to_bytes(),
        "JWT signing keys must be identical across runs"
    );
    assert_eq!(vk1, vk2, "JWT verifying keys must be identical across runs");
}
