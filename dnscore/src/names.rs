//! The device's own addresses for its built-in name (`Settings.local_name`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// At most this many addresses are answered for the own name (a router may hand out several
/// prefixes; SLAAC plus privacy addresses can add more).
pub const MAX_OWN_ADDRS: usize = 8;

fn usable_v4(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_broadcast())
}

/// Global unicast (2000::/3) or unique local (fc00::/7). Never link-local (fe80::/10): a
/// link-local answer is useless without a zone and would break clients on another link.
fn usable_v6(a: Ipv6Addr) -> bool {
    let s0 = a.segments()[0];
    (s0 & 0xe000) == 0x2000 || (s0 & 0xfe00) == 0xfc00
}

/// The addresses to answer for the own name: the IPv4 address first, then global and ULA
/// IPv6 addresses in the given order, without duplicates, at most `MAX_OWN_ADDRS`.
pub fn own_addrs(v4: Option<Ipv4Addr>, v6: &[Ipv6Addr]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::with_capacity(MAX_OWN_ADDRS);
    let cands = v4.filter(|a| usable_v4(*a)).map(IpAddr::V4).into_iter().chain(
        v6.iter().copied().filter(|a| usable_v6(*a)).map(IpAddr::V6),
    );
    for a in cands {
        if out.len() >= MAX_OWN_ADDRS {
            break;
        }
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}
