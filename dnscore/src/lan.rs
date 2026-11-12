//! LAN-only source policy: only local addresses may query; never loopback or public.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Default)]
pub struct LanPolicy {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6: Vec<(Ipv6Addr, u8)>,
}

fn v4_in(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return false; // a /0 would admit the whole internet
    }
    let p = prefix.min(32) as u32;
    let mask = u32::MAX << (32 - p);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return false;
    }
    let p = prefix.min(128) as u32;
    let mask = u128::MAX << (128 - p);
    u128::from(ip) & mask == u128::from(net) & mask
}

impl LanPolicy {
    pub fn is_lan(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.v4_ok(a),
            IpAddr::V6(a) => {
                if let Some(m) = a.to_ipv4_mapped() {
                    return self.v4_ok(m);
                }
                self.v6_ok(a)
            }
        }
    }

    fn v4_ok(&self, a: Ipv4Addr) -> bool {
        if a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
            return false;
        }
        matches!(self.v4, Some((net, p)) if v4_in(a, net, p))
    }

    fn v6_ok(&self, a: Ipv6Addr) -> bool {
        if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
            return false;
        }
        let first = a.segments()[0];
        if first & 0xffc0 == 0xfe80 || first & 0xfe00 == 0xfc00 {
            return true;
        }
        self.v6.iter().any(|&(net, p)| v6_in(a, net, p))
    }
}
