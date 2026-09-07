//! SSRF guard for outbound proxy and MCP targets.
//!
//! There is one public entry point, [`validate_proxy_target_resolved`]. It
//! parses the URL, rejects unsupported schemes and localhost names before any
//! DNS lookup, resolves the host, and refuses the target if *any* resolved
//! address falls in a private or reserved range. The range check itself is
//! [`is_private_or_reserved`], one function over [`IpAddr`] that unwraps
//! IPv4-mapped, NAT64, 6to4, and IPv4-compatible IPv6 forms and applies the
//! IPv4 rules to the embedded address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Async SSRF validation with DNS resolution.
///
/// Rejects, in order:
/// - Non-HTTP(S) schemes and URLs with a missing or empty host.
/// - `localhost` and any name ending in `.localhost` (before resolution).
/// - IP literals in a private or reserved range (see [`is_private_or_reserved`]).
/// - Domains for which resolution fails, times out (5s), returns nothing, or
///   returns any address in a private or reserved range. Every resolved
///   address is checked, so a record set mixing public and private answers
///   is refused.
///
/// Returns `Ok(())` if the URL is safe, or `Err(reason)` if it should be blocked.
pub async fn validate_proxy_target_resolved(url: &str) -> Result<(), String> {
    let parsed = parse_target(url)?;

    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => reject_if_reserved(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => reject_if_reserved(IpAddr::V6(v6)),
        Some(url::Host::Domain(domain)) => {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let lookup_target = format!("{domain}:{port}");

            let resolved = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host(&lookup_target),
            )
            .await
            .map_err(|_| "DNS resolution timed out".to_string())?
            .map_err(|e| format!("DNS resolution failed: {e}"))?;

            let addrs: Vec<IpAddr> = resolved.map(|a| a.ip()).collect();
            if addrs.is_empty() {
                return Err("DNS resolution returned no addresses".to_string());
            }

            // Block if ANY resolved address is private or reserved.
            if let Some(bad) = addrs.iter().find(|ip| is_private_or_reserved(**ip)) {
                return Err(format!(
                    "domain resolves to private/reserved address: {bad}"
                ));
            }
            Ok(())
        }
        None => Err("URL has no host".to_string()),
    }
}

/// Parse and apply the checks that need no network: scheme, host presence,
/// and localhost names. Shared by the resolving variant; not a public API,
/// because on its own it lets an attacker-controlled domain through.
fn parse_target(url: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("unsupported scheme: {scheme}")),
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    if host.is_empty() {
        return Err("URL has empty host".to_string());
    }

    if is_localhost_name(host) {
        return Err("localhost is not allowed".to_string());
    }

    Ok(parsed)
}

/// `localhost`, any label under `.localhost` (RFC 6761), with or without a
/// trailing dot, case-insensitively.
fn is_localhost_name(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host.len() > ".localhost".len()
            && host[host.len() - ".localhost".len()..].eq_ignore_ascii_case(".localhost")
}

fn reject_if_reserved(ip: IpAddr) -> Result<(), String> {
    if is_private_or_reserved(ip) {
        Err("target address is in a private or reserved range".to_string())
    } else {
        Ok(())
    }
}

/// Whether an address is in a private, loopback, link-local, multicast,
/// documentation, benchmarking, or otherwise reserved range that an outbound
/// proxy must never reach.
///
/// IPv4 (RFC 6890 and friends): 0.0.0.0/8, 10/8, 100.64/10, 127/8,
/// 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16,
/// 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4 (which includes
/// 255.255.255.255).
///
/// IPv6: unspecified, loopback, unique-local fc00::/7, link-local fe80::/10,
/// site-local fec0::/10, multicast ff00::/8, and the deprecated
/// IPv4-compatible ::/96. IPv4-mapped ::ffff:0:0/96, NAT64 64:ff9b::/96, and
/// 6to4 2002::/16 addresses are unwrapped and the embedded IPv4 address is
/// checked with the IPv4 rules.
pub fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_v4(v4),
        IpAddr::V6(v6) => is_reserved_v6(v6),
    }
}

fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    a == 0                                       // 0.0.0.0/8 "this network"
        || a == 10                               // 10/8
        || (a == 100 && (b & 0xc0) == 64)        // 100.64/10 CGNAT
        || a == 127                              // 127/8 loopback
        || (a == 169 && b == 254)                // 169.254/16 link-local (incl. metadata)
        || (a == 172 && (b & 0xf0) == 16)        // 172.16/12
        || (a == 192 && b == 0 && c == 0)        // 192.0.0/24 IETF protocol assignments
        || (a == 192 && b == 0 && c == 2)        // 192.0.2/24 TEST-NET-1
        || (a == 192 && b == 88 && c == 99)      // 192.88.99/24 6to4 relay anycast
        || (a == 192 && b == 168)                // 192.168/16
        || (a == 198 && (b & 0xfe) == 18)        // 198.18/15 benchmarking
        || (a == 198 && b == 51 && c == 100)     // 198.51.100/24 TEST-NET-2
        || (a == 203 && b == 0 && c == 113)      // 203.0.113/24 TEST-NET-3
        || (a & 0xf0) == 224                     // 224/4 multicast
        || (a & 0xf0) == 240 // 240/4 reserved, incl. 255.255.255.255 broadcast
}

fn is_reserved_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    // ::/96 IPv4-compatible (deprecated) — covers :: and ::1 too. Rejected
    // as a whole rather than by embedded address.
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        return true;
    }
    if let Some(v4) = embedded_v4(v6) {
        return is_reserved_v4(v4);
    }
    (s[0] & 0xfe00) == 0xfc00                    // fc00::/7 unique-local
        || (s[0] & 0xffc0) == 0xfe80             // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0             // fec0::/10 site-local (deprecated)
        || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

/// The IPv4 address embedded in a transition-form IPv6 address, if any:
/// IPv4-mapped `::ffff:a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`, or 6to4
/// `2002:aabb:ccdd::/48`.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let low = |i: usize| Ipv4Addr::from(((s[i] as u32) << 16) | s[i + 1] as u32);
    let ipv4_mapped = s[..6] == [0, 0, 0, 0, 0, 0xffff]; // ::ffff:0:0/96
    let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]; // 64:ff9b::/96 well-known prefix
    if ipv4_mapped || nat64 {
        Some(low(6))
    } else if s[0] == 0x2002 {
        Some(low(1)) // 2002::/16 6to4
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row per reserved range: an address inside it and the nearest
    /// address outside it (or a nearby public one when the range abuts
    /// another reserved range).
    const RANGE_TABLE: &[(&str, &str, &str)] = &[
        // (range, inside, just outside)
        ("0.0.0.0/8 this-network", "0.255.255.255", "1.0.0.0"),
        ("10/8 private", "10.0.0.1", "11.0.0.0"),
        ("100.64/10 cgnat", "100.64.0.0", "100.63.255.255"),
        ("100.64/10 cgnat upper", "100.127.255.255", "100.128.0.0"),
        ("127/8 loopback", "127.0.0.1", "128.0.0.1"),
        ("169.254/16 link-local", "169.254.169.254", "169.255.0.0"),
        ("172.16/12 private", "172.16.0.1", "172.15.255.255"),
        ("172.16/12 private upper", "172.31.255.255", "172.32.0.0"),
        ("192.0.0/24 ietf protocol", "192.0.0.1", "192.0.1.1"),
        ("192.0.2/24 test-net-1", "192.0.2.1", "192.0.3.1"),
        ("192.88.99/24 6to4 relay", "192.88.99.1", "192.88.100.1"),
        ("192.168/16 private", "192.168.1.1", "192.169.0.1"),
        ("198.18/15 benchmark", "198.18.0.1", "198.17.255.255"),
        ("198.18/15 benchmark upper", "198.19.255.255", "198.20.0.0"),
        ("198.51.100/24 test-net-2", "198.51.100.1", "198.51.101.1"),
        ("203.0.113/24 test-net-3", "203.0.113.1", "203.0.114.1"),
        ("224/4 multicast", "224.0.0.1", "223.255.255.255"),
        ("240/4 reserved", "240.0.0.1", "239.255.255.255"),
        ("255.255.255.255 broadcast", "255.255.255.255", "8.8.8.8"),
        // IPv6
        ("::/128 unspecified", "::", "2001:db8::1"),
        ("::1/128 loopback", "::1", "2001:db8::1"),
        (
            "::ffff:0:0/96 mapped loopback",
            "::ffff:127.0.0.1",
            "::ffff:8.8.8.8",
        ),
        (
            "::ffff:0:0/96 mapped private",
            "::ffff:10.0.0.1",
            "::ffff:1.1.1.1",
        ),
        (
            "::ffff:0:0/96 mapped link-local",
            "::ffff:169.254.169.254",
            "::ffff:9.9.9.9",
        ),
        (
            "64:ff9b::/96 nat64 loopback",
            "64:ff9b::7f00:1",
            "64:ff9b::808:808",
        ),
        (
            "64:ff9b::/96 nat64 private",
            "64:ff9b::a00:1",
            "64:ff9b::101:101",
        ),
        (
            "64:ff9b::/96 nat64 metadata",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::909:909",
        ),
        ("2002::/16 6to4 loopback", "2002:7f00:1::", "2002:808:808::"),
        (
            "2002::/16 6to4 private",
            "2002:c0a8:101::",
            "2002:101:101::",
        ),
        ("fc00::/7 unique-local", "fc00::1", "fbff::1"),
        ("fc00::/7 unique-local upper", "fdff::1", "fe00::1"),
        ("fe80::/10 link-local", "fe80::1", "fe7f::1"),
        ("fe80::/10 link-local upper", "febf::1", "fec0::1"),
        ("fec0::/10 site-local", "fec0::1", "fe00::1"),
        ("fec0::/10 site-local upper", "feff::1", "ff00::1"),
        ("ff00::/8 multicast", "ff02::1", "feff::1"),
        (
            "ff00::/8 multicast upper",
            "ffff::1",
            "2001:4860:4860::8888",
        ),
        ("::/96 ipv4-compatible", "::7f00:1", "0:0:0:0:1::"),
        (
            "::/96 ipv4-compatible public v4",
            "::808:808",
            "2001:db8::808:808",
        ),
    ];

    #[test]
    fn reserved_range_table() {
        for (range, inside, _outside) in RANGE_TABLE {
            let inside_ip: IpAddr = inside.parse().unwrap();
            assert!(
                is_private_or_reserved(inside_ip),
                "{range}: {inside} should be reserved"
            );
        }
        // The "outside" column is only meaningful when it is itself not in
        // some other reserved range; those rows are marked by being in the
        // public list below.
        for (range, _inside, outside) in RANGE_TABLE {
            let outside_ip: IpAddr = outside.parse().unwrap();
            if PUBLIC_NEIGHBOURS.contains(outside) {
                assert!(
                    !is_private_or_reserved(outside_ip),
                    "{range}: {outside} should be public"
                );
            } else {
                // Adjacent to another reserved range: must still be reserved.
                assert!(
                    is_private_or_reserved(outside_ip),
                    "{range}: {outside} is adjacent to another reserved range and must stay reserved"
                );
            }
        }
    }

    /// Outside-addresses from the table that are genuinely public.
    const PUBLIC_NEIGHBOURS: &[&str] = &[
        "1.0.0.0",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "128.0.0.1",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.1",
        "192.0.3.1",
        "192.88.100.1",
        "192.169.0.1",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.101.1",
        "203.0.114.1",
        "223.255.255.255",
        "8.8.8.8",
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "::ffff:1.1.1.1",
        "::ffff:9.9.9.9",
        "64:ff9b::808:808",
        "64:ff9b::101:101",
        "64:ff9b::909:909",
        "2002:808:808::",
        "2002:101:101::",
        "fbff::1",
        "fe00::1",
        "fe7f::1",
        "2001:4860:4860::8888",
        "2001:db8::808:808",
        "0:0:0:0:1::",
    ];

    #[test]
    fn public_neighbours_are_all_table_rows() {
        for p in PUBLIC_NEIGHBOURS {
            assert!(
                RANGE_TABLE.iter().any(|(_, _, o)| o == p),
                "{p} is listed as public but is not a table row"
            );
        }
    }

    #[test]
    fn public_edges() {
        // 239.255.255.255 is multicast, so the 240/4 "outside" row above is
        // reserved by a neighbouring range; assert the true public edge here.
        assert!(!is_private_or_reserved("223.255.255.255".parse().unwrap()));
        assert!(!is_private_or_reserved("1.1.1.1".parse().unwrap()));
        // 6to4 with a public embedded address is public.
        assert!(!is_private_or_reserved("2002:101:101::".parse().unwrap()));
    }

    // ---- URL-level checks through the resolving variant ------------------

    #[tokio::test]
    async fn allows_public_ip_literals() {
        assert!(validate_proxy_target_resolved("https://8.8.8.8/dns-query")
            .await
            .is_ok());
        assert!(
            validate_proxy_target_resolved("http://[2001:4860:4860::8888]/")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_localhost_names_before_resolution() {
        for url in [
            "http://localhost:8080/api",
            "http://LOCALHOST/api",
            "http://foo.localhost/",
            "http://a.b.LocalHost:9/x",
            "http://localhost./",
        ] {
            let err = validate_proxy_target_resolved(url).await.unwrap_err();
            assert!(err.contains("localhost"), "{url}: {err}");
        }
    }

    #[tokio::test]
    async fn rejects_reserved_ip_literals() {
        for url in [
            "http://127.0.0.1:3000/",
            "http://[::1]:8080/",
            "http://169.254.169.254/latest/meta-data/",
            "http://0.0.0.0/",
            "http://192.0.0.8/",
            "http://198.18.0.1/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::7f00:1]/",
            "http://[2002:7f00:1::]/",
            "http://[fec0::1]/",
            "http://[ff02::1]/",
            "http://[::7f00:1]/",
        ] {
            assert!(
                validate_proxy_target_resolved(url).await.is_err(),
                "{url} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_http_schemes_and_missing_host() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/file",
            "gopher://evil.com/",
            "http://",
        ] {
            assert!(
                validate_proxy_target_resolved(url).await.is_err(),
                "{url} should be rejected"
            );
        }
    }
}
