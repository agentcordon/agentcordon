use super::*;

/// Generate a P-256 key pair for testing. Returns (private_key_bytes, public_key_bytes).
fn generate_test_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);
    let public = secret.public_key();
    let priv_bytes = secret.to_bytes().to_vec();
    let pub_bytes = public.to_encoded_point(false).as_bytes().to_vec();
    (priv_bytes, pub_bytes)
}

#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"hello, ECIES credential encryption!";

    let envelope = encryptor
        .encrypt_for_device(&pub_key, plaintext, b"")
        .await
        .expect("encryption should succeed");

    let decrypted = encryptor
        .decrypt_envelope(&priv_key, &envelope)
        .await
        .expect("decryption should succeed");

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_encrypt_decrypt_with_aad() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"secret credential material";
    let aad = build_aad("device_123", "cred_456", "vnd_789", "1710000000");

    let envelope = encryptor
        .encrypt_for_device(&pub_key, plaintext, &aad)
        .await
        .expect("encryption should succeed");

    assert_eq!(envelope.aad, aad);

    let decrypted = encryptor
        .decrypt_envelope(&priv_key, &envelope)
        .await
        .expect("decryption with correct AAD should succeed");

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_decrypt_wrong_key_fails() {
    let (_priv_key_a, pub_key_a) = generate_test_keypair();
    let (priv_key_b, _pub_key_b) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"secret data";

    let envelope = encryptor
        .encrypt_for_device(&pub_key_a, plaintext, b"")
        .await
        .expect("encryption should succeed");

    let result = encryptor.decrypt_envelope(&priv_key_b, &envelope).await;
    assert!(result.is_err(), "decryption with wrong key must fail");
}

#[tokio::test]
async fn test_decrypt_tampered_ciphertext_fails() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"secret data for tamper test";

    let mut envelope = encryptor
        .encrypt_for_device(&pub_key, plaintext, b"")
        .await
        .expect("encryption should succeed");

    // Tamper with a ciphertext byte
    if let Some(byte) = envelope.ciphertext.first_mut() {
        *byte ^= 0xff;
    }

    let result = encryptor.decrypt_envelope(&priv_key, &envelope).await;
    assert!(
        result.is_err(),
        "decryption of tampered ciphertext must fail"
    );
}

#[tokio::test]
async fn test_decrypt_wrong_aad_fails() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"secret data for AAD test";
    let aad = build_aad("device_123", "cred_456", "vnd_789", "1710000000");

    let mut envelope = encryptor
        .encrypt_for_device(&pub_key, plaintext, &aad)
        .await
        .expect("encryption should succeed");

    // Replace AAD with different value
    let wrong_aad = build_aad("device_999", "cred_000", "vnd_111", "9999999999");
    envelope.aad = wrong_aad;

    let result = encryptor.decrypt_envelope(&priv_key, &envelope).await;
    assert!(result.is_err(), "decryption with wrong AAD must fail");
}

#[tokio::test]
async fn test_envelope_version_is_0x01() {
    let (_priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    let envelope = encryptor
        .encrypt_for_device(&pub_key, b"test", b"")
        .await
        .expect("encryption should succeed");

    assert_eq!(envelope.version, 0x01, "envelope version must be 0x01");
}

#[tokio::test]
async fn test_ephemeral_key_is_65_bytes() {
    let (_priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    let envelope = encryptor
        .encrypt_for_device(&pub_key, b"test", b"")
        .await
        .expect("encryption should succeed");

    assert_eq!(
        envelope.ephemeral_public_key.len(),
        65,
        "ephemeral public key must be 65 bytes (uncompressed P-256)"
    );
    assert_eq!(
        envelope.ephemeral_public_key[0], 0x04,
        "uncompressed point must start with 0x04"
    );
}

#[tokio::test]
async fn test_nonce_is_12_bytes() {
    let (_priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    let envelope = encryptor
        .encrypt_for_device(&pub_key, b"test", b"")
        .await
        .expect("encryption should succeed");

    assert_eq!(
        envelope.nonce.len(),
        12,
        "AES-256-GCM nonce must be 12 bytes"
    );
}

#[tokio::test]
async fn test_different_encryptions_produce_different_ciphertext() {
    let (_priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();
    let plaintext = b"same plaintext for both";

    let envelope1 = encryptor
        .encrypt_for_device(&pub_key, plaintext, b"")
        .await
        .expect("first encryption should succeed");

    let envelope2 = encryptor
        .encrypt_for_device(&pub_key, plaintext, b"")
        .await
        .expect("second encryption should succeed");

    // Both ephemeral keys and ciphertexts must differ (random nonce + random ephemeral key)
    assert_ne!(
        envelope1.ephemeral_public_key, envelope2.ephemeral_public_key,
        "ephemeral keys must differ between encryptions"
    );
    assert_ne!(
        envelope1.ciphertext, envelope2.ciphertext,
        "ciphertexts must differ between encryptions"
    );
    assert_ne!(
        envelope1.nonce, envelope2.nonce,
        "nonces should differ between encryptions (random)"
    );
}

#[tokio::test]
async fn test_empty_plaintext() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    let envelope = encryptor
        .encrypt_for_device(&pub_key, b"", b"")
        .await
        .expect("encrypting empty plaintext should succeed");

    let decrypted = encryptor
        .decrypt_envelope(&priv_key, &envelope)
        .await
        .expect("decrypting empty plaintext should succeed");

    assert!(
        decrypted.is_empty(),
        "decrypted empty plaintext must be empty"
    );
}

#[tokio::test]
async fn test_large_plaintext() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    // 1 MB payload
    let plaintext = vec![0xABu8; 1_048_576];

    let envelope = encryptor
        .encrypt_for_device(&pub_key, &plaintext, b"")
        .await
        .expect("encrypting 1MB payload should succeed");

    let decrypted = encryptor
        .decrypt_envelope(&priv_key, &envelope)
        .await
        .expect("decrypting 1MB payload should succeed");

    assert_eq!(
        decrypted, plaintext,
        "large payload must roundtrip correctly"
    );
}

#[tokio::test]
async fn test_invalid_public_key_rejected() {
    let encryptor = EciesEncryptor::new();

    // Garbage bytes
    let result = encryptor
        .encrypt_for_device(&[0xDE, 0xAD, 0xBE, 0xEF], b"test", b"")
        .await;
    assert!(result.is_err(), "garbage public key must be rejected");

    // Correct length but not on curve (all zeros except prefix)
    let mut bad_key = vec![0x04];
    bad_key.extend_from_slice(&[0u8; 64]);
    let result = encryptor.encrypt_for_device(&bad_key, b"test", b"").await;
    assert!(result.is_err(), "invalid point must be rejected");
}

#[tokio::test]
async fn test_hkdf_label_is_correct() {
    // Verify the HKDF info label used for ECIES is exactly as specified.
    assert_eq!(
        ECIES_HKDF_INFO, b"agentcordon:ecies-credential-v1",
        "HKDF info label must be 'agentcordon:ecies-credential-v1'"
    );

    // Additionally, verify that the ECIES construction uses this label correctly
    // by performing a manual ECDH + HKDF and comparing with the encryption output.
    let device_secret = SecretKey::random(&mut rand::rngs::OsRng);
    let device_pub = device_secret.public_key();
    let device_pub_bytes = device_pub.to_encoded_point(false).as_bytes().to_vec();
    let device_priv_bytes = device_secret.to_bytes().to_vec();

    let encryptor = EciesEncryptor::new();
    let plaintext = b"test for label verification";

    let envelope = encryptor
        .encrypt_for_device(&device_pub_bytes, plaintext, b"")
        .await
        .expect("encryption should succeed");

    // Parse the ephemeral public key from the envelope and manually compute
    // the shared secret + KDF to verify the label is used.
    let ephemeral_pub = PublicKey::from_sec1_bytes(&envelope.ephemeral_public_key)
        .expect("ephemeral key should be valid");

    // Manual ECDH: device_priv * ephemeral_pub
    let fb_arr: [u8; 32] = device_priv_bytes[..32]
        .try_into()
        .expect("device priv bytes should be 32 bytes");
    let device_sk =
        SecretKey::from_bytes(&p256::FieldBytes::from(fb_arr)).expect("device key should be valid");
    let shared_secret = ecdh_shared_secret(&device_sk, &ephemeral_pub);

    // Manual HKDF with the expected label
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut manual_key = [0u8; 32];
    hk.expand(b"agentcordon:ecies-credential-v1", &mut manual_key)
        .expect("HKDF should succeed");

    // If the label were wrong, decryption would fail. Verify by decrypting manually.
    let cipher = Aes256Gcm::new_from_slice(&manual_key).expect("key should be valid");
    let nonce_arr: [u8; 12] = envelope.nonce[..12]
        .try_into()
        .expect("nonce should be 12 bytes");
    let nonce = Nonce::from(nonce_arr);
    let payload = Payload {
        msg: &envelope.ciphertext,
        aad: &envelope.aad,
    };
    let decrypted = cipher
        .decrypt(&nonce, payload)
        .expect("manual decryption with correct label-derived key should succeed");

    assert_eq!(
        decrypted, plaintext,
        "manually derived key must decrypt correctly"
    );
}

#[tokio::test]
async fn test_unknown_envelope_version_rejected() {
    let (priv_key, pub_key) = generate_test_keypair();
    let encryptor = EciesEncryptor::new();

    let mut envelope = encryptor
        .encrypt_for_device(&pub_key, b"test", b"")
        .await
        .expect("encryption should succeed");

    // Set unknown version
    envelope.version = 0xFF;

    let result = encryptor.decrypt_envelope(&priv_key, &envelope).await;
    assert!(result.is_err(), "unknown envelope version must be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("unsupported envelope version"),
        "error should mention unsupported version, got: {}",
        err_msg
    );
}

#[test]
fn test_build_aad() {
    let aad = build_aad("dev_1", "cred_2", "vnd_3", "12345");
    assert_eq!(aad, b"dev_1||cred_2||vnd_3||12345");
}
