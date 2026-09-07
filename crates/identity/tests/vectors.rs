//! Frozen test vectors for the identity crate.
//!
//! The seed is RFC 8032 section 7.1 test vector 1. Every other literal in
//! this file was computed once with the implementation and then frozen: a
//! change that alters the bytes the CLI signs, the bytes the broker
//! verifies, the on-disk key format, or the identity hash fails here
//! before it can ship as a silent wire break.

use agentcordon_identity::{
    canonicalise_path_and_query, identity_string, pk_hash_from_hex, pk_hash_of, register_payload,
    sign_register_at, sign_request_with, signing_payload, verify_register, verify_request,
    WorkspaceKey, MAX_CLOCK_SKEW_SECS,
};

const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const PK_HASH: &str = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
const IDENTITY: &str = "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";

/// One request-signing vector: inputs, the exact payload bytes, and the
/// signature the CLI must emit for them.
///
/// Frozen a second time when the nonce joined the payload
/// (`METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY`): every signature below was
/// recomputed with that change and no other.
struct RequestVector {
    method: &'static str,
    /// Already canonical (what `sign_request_with` receives).
    path: &'static str,
    timestamp: i64,
    /// 16 random bytes as lowercase hex; fixed here.
    nonce: &'static str,
    body: &'static [u8],
    payload: &'static [u8],
    signature_hex: &'static str,
}

const REQUEST_VECTORS: &[RequestVector] = &[
    RequestVector {
        method: "GET",
        path: "/status",
        timestamp: 1_700_000_000,
        nonce: "000102030405060708090a0b0c0d0e0f",
        body: b"",
        payload: b"GET\n/status\n1700000000\n000102030405060708090a0b0c0d0e0f\n",
        signature_hex: "11c69ec479255e28da8d3443eeb7ae423027e0e5396a2ae851695ce506f4fa4661cc294dd6bf095dd7b4d1920c476543636606c0a35ff6698cfcdb3a9918e902",
    },
    RequestVector {
        method: "POST",
        path: "/proxy?x=1&y=%20",
        timestamp: 1_700_000_001,
        nonce: "ffeeddccbbaa99887766554433221100",
        body: br#"{"credential":"github","method":"GET"}"#,
        payload: b"POST\n/proxy?x=1&y=%20\n1700000001\nffeeddccbbaa99887766554433221100\n{\"credential\":\"github\",\"method\":\"GET\"}",
        signature_hex: "6ed774196a3ec300402c560275622ca1382d3722c7eef2ffb01fc413d76abc7cc52f4eca3465ddc0b194bda193bcd15acc578eb85cfd5c1fad361eb409a39f08",
    },
    RequestVector {
        method: "POST",
        path: "/mcp/servers",
        timestamp: 1_700_000_002,
        nonce: "0123456789abcdef0123456789abcdef",
        body: b"",
        payload: b"POST\n/mcp/servers\n1700000002\n0123456789abcdef0123456789abcdef\n",
        signature_hex: "4bc582b00e3fd596ee3693c670c9627b140e8df814e3644780233303d16a083987cd4e02305169889e75731a390a4ff06b454fe286651da2ae68a80e8aac9505",
    },
    RequestVector {
        method: "GET",
        path: "/",
        timestamp: 0,
        nonce: "00000000000000000000000000000000",
        body: b"\xff\x00binary",
        payload: b"GET\n/\n0\n00000000000000000000000000000000\n\xff\x00binary",
        signature_hex: "10e215ae232d4f2dbd483c1f988962caae973261962280f652f51ca3502bd5d3c471c21c7f81386fdff48f01663eae9720928596b0c2a0198f940c786b911b02",
    },
];

fn key() -> WorkspaceKey {
    let seed: [u8; 32] = hex::decode(SEED_HEX).unwrap().try_into().unwrap();
    WorkspaceKey::from_seed(&seed)
}

#[test]
fn seed_derives_frozen_public_key_hash_and_identity() {
    let key = key();
    assert_eq!(key.seed_hex(), SEED_HEX);
    assert_eq!(key.public_key_hex(), PUBLIC_KEY_HEX);
    assert_eq!(key.pk_hash(), PK_HASH);
    assert_eq!(key.identity(), IDENTITY);

    // The free functions the broker uses agree with the key's own view.
    assert_eq!(pk_hash_of(&key.public_key_bytes()), PK_HASH);
    assert_eq!(pk_hash_from_hex(PUBLIC_KEY_HEX).unwrap(), PK_HASH);
    assert_eq!(identity_string(PK_HASH), IDENTITY);
}

#[test]
fn request_vectors_payload_and_signature_are_frozen() {
    let key = key();
    for (i, v) in REQUEST_VECTORS.iter().enumerate() {
        let ts = v.timestamp.to_string();
        assert_eq!(
            signing_payload(v.method, v.path, &ts, v.nonce, v.body),
            v.payload,
            "vector {i}: payload bytes"
        );
        let headers = sign_request_with(&key, v.method, v.path, v.body, v.timestamp, v.nonce);
        assert_eq!(headers.public_key, PUBLIC_KEY_HEX, "vector {i}: public key");
        assert_eq!(headers.timestamp, ts, "vector {i}: timestamp");
        assert_eq!(headers.nonce, v.nonce, "vector {i}: nonce");
        assert_eq!(headers.signature, v.signature_hex, "vector {i}: signature");
    }
}

#[test]
fn request_vectors_verify_within_skew_and_fail_outside() {
    for (i, v) in REQUEST_VECTORS.iter().enumerate() {
        let ts = v.timestamp.to_string();
        verify_request(
            PUBLIC_KEY_HEX,
            &ts,
            v.nonce,
            v.signature_hex,
            v.method,
            v.path,
            v.body,
            v.timestamp + MAX_CLOCK_SKEW_SECS,
        )
        .unwrap_or_else(|e| panic!("vector {i} should verify at max skew: {e}"));
        assert!(
            verify_request(
                PUBLIC_KEY_HEX,
                &ts,
                v.nonce,
                v.signature_hex,
                v.method,
                v.path,
                v.body,
                v.timestamp + MAX_CLOCK_SKEW_SECS + 1,
            )
            .is_err(),
            "vector {i} must fail one second past max skew"
        );
        // The nonce is inside the signed bytes: swapping it for another
        // well-formed nonce breaks the signature.
        assert!(
            verify_request(
                PUBLIC_KEY_HEX,
                &ts,
                "0f0e0d0c0b0a09080706050403020100",
                v.signature_hex,
                v.method,
                v.path,
                v.body,
                v.timestamp,
            )
            .is_err(),
            "vector {i} must fail with a different nonce"
        );
    }
}

const REGISTER_NAME: &str = "vector-workspace";
const REGISTER_SCOPES: &[&str] = &["credentials:discover", "credentials:vend"];
const REGISTER_TIMESTAMP: i64 = 1_700_000_010;
const REGISTER_NONCE: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
/// Frozen a second time when the timestamp and nonce joined the payload
/// (`NAME\nPUBLIC_KEY_HEX\nSCOPES\nTIMESTAMP\nNONCE`).
const REGISTER_PAYLOAD: &str = "vector-workspace\n\
    d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n\
    credentials:discover credentials:vend\n\
    1700000010\n\
    a1b2c3d4e5f60718293a4b5c6d7e8f90";
const REGISTER_SIGNATURE_HEX: &str = "d389778684da5ddd53bcc6282c91cf0362b670aa4437d364d32f9f20dabfaa0c2238e5a95f1d000d15cca2d6d91515290156d4b38ab7bde3c23e85cec213480f";

#[test]
fn register_vector_is_frozen() {
    let key = key();
    let scopes: Vec<String> = REGISTER_SCOPES.iter().map(|s| s.to_string()).collect();
    let ts = REGISTER_TIMESTAMP.to_string();
    assert_eq!(
        register_payload(REGISTER_NAME, PUBLIC_KEY_HEX, &scopes, &ts, REGISTER_NONCE),
        REGISTER_PAYLOAD
    );
    let signed = sign_register_at(
        &key,
        REGISTER_NAME,
        &scopes,
        REGISTER_TIMESTAMP,
        REGISTER_NONCE,
    );
    assert_eq!(signed.workspace_name, REGISTER_NAME);
    assert_eq!(signed.public_key, PUBLIC_KEY_HEX);
    assert_eq!(signed.scopes, scopes);
    assert_eq!(signed.timestamp, ts);
    assert_eq!(signed.nonce, REGISTER_NONCE);
    assert_eq!(signed.signature, REGISTER_SIGNATURE_HEX);

    let pk_hash = verify_register(
        &signed.public_key,
        &signed.workspace_name,
        &signed.scopes,
        &signed.timestamp,
        &signed.nonce,
        &signed.signature,
        REGISTER_TIMESTAMP + MAX_CLOCK_SKEW_SECS,
    )
    .expect("register vector verifies at max skew");
    assert_eq!(pk_hash, PK_HASH);

    assert!(
        verify_register(
            &signed.public_key,
            &signed.workspace_name,
            &signed.scopes,
            &signed.timestamp,
            &signed.nonce,
            &signed.signature,
            REGISTER_TIMESTAMP + MAX_CLOCK_SKEW_SECS + 1,
        )
        .is_err(),
        "register vector must fail one second past max skew"
    );
}

#[test]
fn canonicalisation_vectors() {
    let cases: &[(&str, Option<&str>, &str)] = &[
        ("/foo/bar", None, "/foo/bar"),
        ("/foo/bar/", None, "/foo/bar"),
        ("/foo/bar", Some("a=1&b=2"), "/foo/bar?a=1&b=2"),
        ("/foo/bar/", Some("a=1&b=2"), "/foo/bar?a=1&b=2"),
        ("/", None, "/"),
        ("/", Some("a=1"), "/?a=1"),
        ("/", Some(""), "/"),
        ("/foo/bar/", Some(""), "/foo/bar"),
        // Only one trailing slash is stripped; percent-encoding and
        // parameter order are untouched.
        ("/foo//", None, "/foo/"),
        ("/a%20b/", Some("z=1&a=%2F"), "/a%20b?z=1&a=%2F"),
    ];
    for (path, query, want) in cases {
        assert_eq!(
            canonicalise_path_and_query(path, *query),
            *want,
            "path={path:?} query={query:?}"
        );
    }
}
