/// Derive a KDF salt from a master secret using HKDF-SHA256.
///
/// This provides a secure default when `AGTCRDN_KDF_SALT` is not explicitly set,
/// avoiding the insecure hardcoded default. The output is a hex-encoded 32-byte
/// value suitable for use as a KDF salt.
pub fn derive_kdf_salt(master_secret: &str) -> String {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, master_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"agentcordon:default-kdf-salt-v1", &mut okm)
        .expect("HKDF expand for KDF salt derivation");
    hex::encode(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_kdf_salt_deterministic() {
        let salt1 = derive_kdf_salt("test-secret");
        let salt2 = derive_kdf_salt("test-secret");
        assert_eq!(salt1, salt2);
    }

    #[test]
    fn derive_kdf_salt_different_inputs() {
        let salt1 = derive_kdf_salt("secret-a");
        let salt2 = derive_kdf_salt("secret-b");
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn derive_kdf_salt_hex_format() {
        let salt = derive_kdf_salt("test");
        assert_eq!(salt.len(), 64); // 32 bytes = 64 hex chars
        assert!(salt.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
