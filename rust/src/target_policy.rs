//! Target authorization policy: default-deny for public hosts.
//!
//! Mirrors `src/torshammer/target.py` so the standalone `torshammer-rust`
//! binary enforces the same safety guard as the Python wrapper, rather than
//! relying on callers to always route through the Python `torshammer` entry
//! point. The check is hostname-based (see `docs/security.md` for the
//! DNS-rebinding TOCTOU limitation, which applies identically here).

use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Load an allowlist file: one hostname per line; blank lines and `#`
/// comments are ignored; entries are matched case-insensitively.
pub fn load_allowlist(path: &str) -> Result<HashSet<String>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("cannot read allowlist file {path}: {err}"))?;
    Ok(content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_ascii_lowercase())
        .collect())
}

/// True when `host` resolves to a loopback/private/link-local/multicast or
/// otherwise non-routable address, or is a `localhost` alias. Bare public
/// hostnames (anything that is not such an IP literal) are treated as public.
pub fn is_private_or_local(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => is_private_v4(&ip),
        Ok(IpAddr::V6(ip)) => is_private_v6(&ip),
        Err(_) => false,
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || ip.is_broadcast()
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    // fc00::/7 (unique-local) and fe80::/10 (link-local) have no stable
    // stdlib predicates, so classify the leading segment by hand.
    let first = ip.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    if unique_local || link_local {
        return true;
    }
    // v4-compatible / v4-mapped forms inherit their v4 classification.
    if let Some(v4) = ip.to_ipv4() {
        return is_private_v4(&v4);
    }
    false
}

/// Enforce the default-deny policy. Returns `Ok(())` when the host may be
/// targeted, or an error message explaining why the run was refused.
pub fn check(host: &str, allow_public: bool, allowlist: &HashSet<String>) -> Result<(), String> {
    let normalized = host.trim().to_ascii_lowercase();
    if allowlist.contains(&normalized) || allow_public || is_private_or_local(&normalized) {
        return Ok(());
    }
    Err(
        "refusing to target a public host by default; confirm you are authorized with \
         --allow-public-targets, or list the host in --allowlist-file"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_and_aliases_are_local() {
        assert!(is_private_or_local("localhost"));
        assert!(is_private_or_local("foo.localhost"));
        assert!(is_private_or_local("127.0.0.1"));
        assert!(is_private_or_local("::1"));
    }

    #[test]
    fn private_ranges_are_local() {
        assert!(is_private_or_local("10.0.0.5"));
        assert!(is_private_or_local("192.168.1.1"));
        assert!(is_private_or_local("172.16.0.1"));
        assert!(is_private_or_local("169.254.1.1")); // link-local
        assert!(is_private_or_local("fc00::1")); // unique-local v6
        assert!(is_private_or_local("fe80::1")); // link-local v6
    }

    #[test]
    fn public_targets_are_not_local() {
        assert!(!is_private_or_local("8.8.8.8"));
        assert!(!is_private_or_local("1.1.1.1"));
        assert!(!is_private_or_local("93.184.216.34"));
        assert!(!is_private_or_local("example.com"));
    }

    #[test]
    fn empty_host_is_treated_as_local() {
        // Mirrors target.py's `not host` branch; unreachable in practice
        // because url::parse rejects an empty authority before the check runs.
        assert!(is_private_or_local(""));
    }

    #[test]
    fn check_refuses_public_host_without_opt_in() {
        let empty = HashSet::new();
        assert!(check("8.8.8.8", false, &empty).is_err());
        assert!(check("example.com", false, &empty).is_err());
    }

    #[test]
    fn check_allows_public_with_flag_or_allowlist() {
        assert!(check("example.com", true, &HashSet::new()).is_ok());
        let mut allowlist = HashSet::new();
        allowlist.insert("target.example".to_string());
        assert!(check("TARGET.Example", false, &allowlist).is_ok());
    }

    #[test]
    fn check_allows_local_by_default() {
        assert!(check("127.0.0.1", false, &HashSet::new()).is_ok());
        assert!(check("localhost", false, &HashSet::new()).is_ok());
    }
}
