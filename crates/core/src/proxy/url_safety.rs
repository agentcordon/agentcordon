use std::net::IpAddr;
use std::time::Duration;

/// Validate that a URL is safe to proxy to (not an internal/private network target).
///
/// Blocks:
/// - Non-HTTP(S) schemes
/// - Loopback addresses (127.0.0.0/8, ::1)
/// - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - Cloud metadata endpoints (169.254.169.254)
/// - `localhost` hostname
/// - Missing or empty host
///
/// Returns `Ok(())` if the URL is safe, or `Err(reason)` if it should be blocked.
pub fn validate_proxy_target(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    // Only allow http and https schemes
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

    // Block localhost by name
    if host.eq_ignore_ascii_case("localhost") {
        return Err("localhost is not allowed".to_string());
    }

    // Check via url crate's host() which properly handles IPv4, IPv6, and domains
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            if is_private_or_reserved(IpAddr::V4(v4)) {
                return Err("target address is in a private or reserved range".to_string());
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            if is_private_or_reserved(IpAddr::V6(v6)) {
                return Err("target address is in a private or reserved range".to_string());
            }
        }
        Some(url::Host::Domain(_)) => {
            // Domain name — sync check can only block obvious cases (localhost).
            // Use `validate_proxy_target_resolved` for full DNS-based SSRF protection.
        }
        None => {
            return Err("URL has no host".to_string());
        }
    }

    Ok(())
}

/// Async SSRF validation with DNS resolution.
///
/// Performs all the same checks as `validate_proxy_target`, then additionally
/// resolves the hostname to IP addresses and validates each resolved IP is not
/// in a private/reserved range. This prevents DNS rebinding attacks where an
/// attacker-controlled domain resolves to an internal IP (e.g., 127.0.0.1).
///
/// DNS resolution has a 5-second timeout to avoid blocking the request path.
pub async fn validate_proxy_target_resolved(url: &str) -> Result<(), String> {
    // Run all sync checks first (scheme, literal IP, localhost, etc.)
    validate_proxy_target(url)?;

    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    // Only domain hosts need DNS resolution; IP literals were already checked.
    if let Some(url::Host::Domain(domain)) = parsed.host() {
        let port = parsed.port_or_known_default().unwrap_or(443);
        let lookup_target = format!("{}:{}", domain, port);

        // Resolve DNS with a timeout to prevent slow DNS from blocking requests.
        let resolved = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host(&lookup_target),
        )
        .await
        .map_err(|_| "DNS resolution timed out".to_string())?
        .map_err(|e| format!("DNS resolution failed: {e}"))?;

        let addrs: Vec<_> = resolved.collect();
        if addrs.is_empty() {
            return Err("DNS resolution returned no addresses".to_string());
        }

        // Check every resolved IP — block if ANY resolves to a private range.
        for addr in &addrs {
            if is_private_or_reserved(addr.ip()) {
                return Err(format!(
                    "domain resolves to private/reserved address: {}",
                    addr.ip()
                ));
            }
        }
    }

    Ok(())
}

fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                           // 127.0.0.0/8
                || v4.is_private()                     // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()                  // 169.254.0.0/16 (includes metadata)
                || v4.is_broadcast()                   // 255.255.255.255
                || v4.is_unspecified()                  // 0.0.0.0
                || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127
            // CGNAT 100.64/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                           // ::1
                || v6.is_unspecified()                  // ::
                || is_ipv6_link_local(v6)              // fe80::/10
                || is_ipv6_unique_local(v6)            // fc00::/7
                || is_ipv4_mapped_private(v6) // ::ffff:127.0.0.1 etc.
        }
    }
}

fn is_ipv6_link_local(v6: std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_unique_local(v6: std::net::Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

fn is_ipv4_mapped_private(v6: std::net::Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_public_https() {
        assert!(validate_proxy_target("https://api.github.com/repos/foo").is_ok());
    }

    #[test]
    fn allows_public_http() {
        assert!(validate_proxy_target("http://api.example.com/data").is_ok());
    }

    #[test]
    fn blocks_localhost() {
        assert!(validate_proxy_target("http://localhost:8080/api").is_err());
        assert!(validate_proxy_target("http://LOCALHOST/api").is_err());
    }

    #[test]
    fn blocks_loopback_ipv4() {
        assert!(validate_proxy_target("http://127.0.0.1:3000/").is_err());
        assert!(validate_proxy_target("http://127.0.0.2/").is_err());
    }

    #[test]
    fn blocks_loopback_ipv6() {
        assert!(validate_proxy_target("http://[::1]:8080/").is_err());
    }

    #[test]
    fn blocks_private_10() {
        assert!(validate_proxy_target("http://10.0.0.1/api").is_err());
        assert!(validate_proxy_target("http://10.255.255.255/").is_err());
    }

    #[test]
    fn blocks_private_172() {
        assert!(validate_proxy_target("http://172.16.0.1/api").is_err());
        assert!(validate_proxy_target("http://172.31.255.255/").is_err());
    }

    #[test]
    fn blocks_private_192() {
        assert!(validate_proxy_target("http://192.168.1.1/api").is_err());
    }

    #[test]
    fn blocks_link_local() {
        assert!(validate_proxy_target("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_proxy_target("http://169.254.1.1/").is_err());
    }

    #[test]
    fn blocks_unspecified() {
        assert!(validate_proxy_target("http://0.0.0.0/").is_err());
    }

    #[test]
    fn blocks_non_http_schemes() {
        assert!(validate_proxy_target("file:///etc/passwd").is_err());
        assert!(validate_proxy_target("ftp://example.com/file").is_err());
        assert!(validate_proxy_target("gopher://evil.com/").is_err());
    }

    #[test]
    fn blocks_missing_host() {
        assert!(validate_proxy_target("http://").is_err());
    }

    #[test]
    fn allows_public_ip() {
        assert!(validate_proxy_target("https://8.8.8.8/dns-query").is_ok());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_private() {
        assert!(validate_proxy_target("http://[::ffff:127.0.0.1]/").is_err());
        assert!(validate_proxy_target("http://[::ffff:10.0.0.1]/").is_err());
    }

    #[test]
    fn blocks_cgnat_range() {
        assert!(validate_proxy_target("http://100.64.0.1/api").is_err());
        assert!(validate_proxy_target("http://100.127.255.255/api").is_err());
    }

    #[test]
    fn allows_non_cgnat_100() {
        assert!(validate_proxy_target("http://100.63.255.255/api").is_ok());
        assert!(validate_proxy_target("http://100.128.0.0/api").is_ok());
    }
}
