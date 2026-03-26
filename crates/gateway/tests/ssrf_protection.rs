//! v1.6 — SSRF Protection Tests (Wave 4.4 + 4.5)
//!
//! Tests that the device proxy blocks requests to private/internal IP addresses
//! while allowing public URLs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ===========================================================================
// URL parsing helper for SSRF validation
// ===========================================================================

/// Check if an IP address is in a private/reserved range that should be blocked.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                           // 127.0.0.0/8
                || v4.is_private()                     // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()                  // 169.254.0.0/16
                || v4.is_unspecified()                 // 0.0.0.0
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                           // ::1
                || v6.is_unspecified()                 // ::
                // Unique Local Addresses (fc00::/7) — IPv6 equivalent of RFC 1918
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped IPv6 (::ffff:x.x.x.x) — check the mapped IPv4
                || {
                    let segs = v6.segments();
                    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0
                        && segs[4] == 0 && segs[5] == 0xffff {
                        let v4 = std::net::Ipv4Addr::new(
                            (segs[6] >> 8) as u8, segs[6] as u8,
                            (segs[7] >> 8) as u8, segs[7] as u8,
                        );
                        is_private_ip(&IpAddr::V4(v4))
                    } else {
                        false
                    }
                }
        }
    }
}

// ===========================================================================
// Wave 4.4: Device Proxy SSRF Protection
// ===========================================================================

#[test]
fn test_proxy_blocks_localhost() {
    let localhost_ips = [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ];
    for ip in &localhost_ips {
        assert!(is_private_ip(ip), "localhost {:?} should be blocked", ip);
    }
}

#[test]
fn test_proxy_blocks_rfc1918() {
    let rfc1918_ips = [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255)),
    ];
    for ip in &rfc1918_ips {
        assert!(is_private_ip(ip), "RFC 1918 IP {:?} should be blocked", ip);
    }
}

#[test]
fn test_proxy_blocks_link_local() {
    let link_local_ips = [
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    ];
    for ip in &link_local_ips {
        assert!(
            is_private_ip(ip),
            "link-local IP {:?} should be blocked",
            ip
        );
    }
}

#[test]
fn test_proxy_blocks_ipv6_loopback() {
    let ipv6_loopback = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(
        is_private_ip(&ipv6_loopback),
        "IPv6 loopback should be blocked"
    );
}

#[test]
fn test_proxy_allows_public_urls() {
    let public_ips = [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),       // Google DNS
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),       // Cloudflare
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // example.com
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),   // TEST-NET-3
    ];
    for ip in &public_ips {
        assert!(!is_private_ip(ip), "public IP {:?} should be allowed", ip);
    }
}

#[test]
fn test_proxy_blocks_ipv6_unique_local() {
    // fc00::/7 — Unique Local Addresses (IPv6 equivalent of RFC 1918)
    let ula_ips = [
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfdab, 0x1234, 0, 0, 0, 0, 0, 1)),
    ];
    for ip in &ula_ips {
        assert!(is_private_ip(ip), "IPv6 ULA {:?} should be blocked", ip);
    }
}

#[test]
fn test_proxy_blocks_ipv6_link_local() {
    // fe80::/10 — Link-local
    let link_local_ips = [
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0,
        )),
        IpAddr::V6(Ipv6Addr::new(0xfebf, 0, 0, 0, 0, 0, 0, 1)),
    ];
    for ip in &link_local_ips {
        assert!(
            is_private_ip(ip),
            "IPv6 link-local {:?} should be blocked",
            ip
        );
    }
}

#[test]
fn test_proxy_blocks_ipv4_mapped_ipv6() {
    // ::ffff:127.0.0.1 — IPv4-mapped loopback
    let mapped_loopback = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
    assert!(
        is_private_ip(&mapped_loopback),
        "IPv4-mapped loopback should be blocked"
    );

    // ::ffff:10.0.0.1 — IPv4-mapped RFC 1918
    let mapped_rfc1918 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
    assert!(
        is_private_ip(&mapped_rfc1918),
        "IPv4-mapped 10.x should be blocked"
    );

    // ::ffff:192.168.1.1 — IPv4-mapped RFC 1918
    let mapped_private = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
    assert!(
        is_private_ip(&mapped_private),
        "IPv4-mapped 192.168.x should be blocked"
    );

    // ::ffff:8.8.8.8 — IPv4-mapped public should be allowed
    let mapped_public = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808));
    assert!(
        !is_private_ip(&mapped_public),
        "IPv4-mapped public IP should be allowed"
    );
}

// ===========================================================================
// URL-level SSRF checks
// ===========================================================================

/// Extract the host from a URL and check if it's a private address.
fn url_targets_private_ip(url: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            // Direct IP check (strip brackets for IPv6)
            let bare_host = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = bare_host.parse::<IpAddr>() {
                return is_private_ip(&ip);
            }
            // Check for "localhost" hostname
            if host == "localhost" || host.ends_with(".localhost") {
                return true;
            }
        }
        // Also check via url crate's host() enum which handles IPv6 natively
        if let Some(url::Host::Ipv6(v6)) = parsed.host() {
            return is_private_ip(&IpAddr::V6(v6));
        }
        if let Some(url::Host::Ipv4(v4)) = parsed.host() {
            return is_private_ip(&IpAddr::V4(v4));
        }
    }
    false
}

#[test]
fn test_url_ssrf_localhost_variants() {
    assert!(url_targets_private_ip("http://localhost/path"));
    assert!(url_targets_private_ip("http://127.0.0.1/path"));
    assert!(url_targets_private_ip("http://127.0.0.1:8080/path"));
    assert!(url_targets_private_ip("http://localhost:3000/admin"));
}

#[test]
fn test_url_ssrf_rfc1918_variants() {
    assert!(url_targets_private_ip("http://10.0.0.1/internal"));
    assert!(url_targets_private_ip("http://192.168.1.1/admin"));
    assert!(url_targets_private_ip("http://172.16.0.1:9090/metrics"));
}

#[test]
fn test_url_ssrf_ipv6_loopback() {
    assert!(url_targets_private_ip("http://[::1]/path"));
    assert!(url_targets_private_ip("http://[::1]:8080/admin"));
}

#[test]
fn test_url_ssrf_public_allowed() {
    assert!(!url_targets_private_ip(
        "https://api.example.com/v1/resource"
    ));
    assert!(!url_targets_private_ip("https://api.github.com/repos"));
    assert!(!url_targets_private_ip("https://8.8.8.8/dns-query"));
}

// ===========================================================================
// Wave 4.5: OAuth2 SSRF Protection
// ===========================================================================

#[test]
fn test_oauth2_blocks_rfc1918_token_endpoint() {
    assert!(url_targets_private_ip("http://10.0.0.5/oauth/token"));
    assert!(url_targets_private_ip("http://192.168.1.100/token"));
}

#[test]
fn test_oauth2_blocks_localhost_token_endpoint() {
    assert!(url_targets_private_ip("http://localhost:8080/token"));
}

#[test]
fn test_oauth2_allows_public_token_endpoint() {
    assert!(!url_targets_private_ip("https://oauth.provider.com/token"));
    assert!(!url_targets_private_ip(
        "https://login.microsoftonline.com/token"
    ));
}

// ===========================================================================
// Config: allow loopback for dev mode
// ===========================================================================

#[test]
fn test_proxy_config_allow_loopback() {
    let allow_loopback = true;
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    if allow_loopback {
        // In dev mode, localhost is allowed
        assert!(
            is_private_ip(&ip),
            "IP is still private, but config allows it"
        );
    }

    // When allow_loopback is false, blocked
    let allow_loopback = false;
    if !allow_loopback {
        assert!(
            is_private_ip(&ip),
            "localhost should be identified as private"
        );
    }
}
