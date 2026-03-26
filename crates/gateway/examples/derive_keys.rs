use agent_cordon_core::crypto::key_derivation::derive_p256_keypair;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;

use agent_cordon_core::crypto::kdf::derive_kdf_salt;

fn main() {
    let master_secret = "dev-container-secret-not-for-production";
    let kdf_salt = derive_kdf_salt(master_secret);

    let (signing_sk, _) = derive_p256_keypair(
        master_secret,
        kdf_salt.as_bytes(),
        b"agentcordon:combined-device-signing-v1",
    )
    .unwrap();

    let (enc_sk, _) = derive_p256_keypair(
        master_secret,
        kdf_salt.as_bytes(),
        b"agentcordon:combined-device-encryption-v1",
    )
    .unwrap();

    let signing_key = p256::SecretKey::from_bytes(&signing_sk.to_bytes()).unwrap();
    let enc_key = p256::SecretKey::from_bytes(&enc_sk.to_bytes()).unwrap();

    let sp = signing_key.public_key().to_encoded_point(false);
    let ep = enc_key.public_key().to_encoded_point(false);

    let sx = URL_SAFE_NO_PAD.encode(&sp.as_bytes()[1..33]);
    let sy = URL_SAFE_NO_PAD.encode(&sp.as_bytes()[33..65]);
    let ex = URL_SAFE_NO_PAD.encode(&ep.as_bytes()[1..33]);
    let ey = URL_SAFE_NO_PAD.encode(&ep.as_bytes()[33..65]);

    // Output as JSON suitable for device enrollment
    println!(
        r#"{{"signing_key":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","use":"sig"}},"encryption_key":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","use":"enc"}}}}"#,
        sx, sy, ex, ey
    );
}
