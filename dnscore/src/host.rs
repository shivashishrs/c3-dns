//! The `Host` header allowlist of the web UI (DNS-rebinding defence).
//!
//! A rebinding page runs in the browser under the attacker's own name (`evil.example`) that
//! was made to resolve to the device, so its requests carry `Host: evil.example`. The device
//! answers only requests addressed to one of its own names (`adblock.local`, the configured
//! `local_name`) or to one of its own addresses, optionally with a port. Everything else is
//! refused before authentication.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest `Host` value considered (bytes): a 253-byte name, a port and some slack.
pub const MAX_HOST: usize = 300;

fn port_ok(p: &str) -> bool {
    !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && matches!(p.parse::<u32>(), Ok(1..=65535))
}

fn unmap(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

fn addr_ok(a: IpAddr, addrs: &[IpAddr]) -> bool {
    let a = unmap(a);
    addrs.iter().any(|x| unmap(*x) == a)
}

fn strip_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// True if `host` (the request's `Host` header) names this device: one of `names` (compared
/// without case and without one trailing dot) or one of `addrs` (IPv6 in brackets), each
/// optionally followed by `:port`. A missing, empty, oversized or malformed value is refused.
pub fn host_allowed(host: Option<&str>, names: &[&str], addrs: &[IpAddr]) -> bool {
    let Some(h) = host else { return false };
    if h.is_empty() || h.len() > MAX_HOST {
        return false;
    }
    if let Some(rest) = h.strip_prefix('[') {
        let Some((lit, after)) = rest.split_once(']') else { return false };
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(port_ok)) {
            return false;
        }
        return match lit.parse::<Ipv6Addr>() {
            Ok(a) => addr_ok(IpAddr::V6(a), addrs),
            Err(_) => false,
        };
    }
    let name = match h.split_once(':') {
        Some((n, p)) if port_ok(p) => n,
        Some(_) => return false,
        None => h,
    };
    let name = strip_dot(name);
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return false;
    }
    if let Ok(a) = name.parse::<Ipv4Addr>() {
        return addr_ok(IpAddr::V4(a), addrs);
    }
    names.iter().map(|n| strip_dot(n)).any(|n| !n.is_empty() && n.eq_ignore_ascii_case(name))
}
