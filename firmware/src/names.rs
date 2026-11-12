//! The device's own names: `Settings.local_name` (default `adblock.home`) as a built-in local
//! record pointing at the device's own IPv4 and global/ULA IPv6 addresses (answered with the
//! local TTL, 60 s), and `adblock.local` over mDNS (set up in `main`).
//!
//! `refresh` runs on every network poll (2 s): it picks up DHCP renewals, SLAAC addresses
//! appearing or going, and a changed `local_name`, and only touches the engine on a change.

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscore::names::own_addrs;
use dnscore::normalize;
use log::info;

use crate::dns::Shared;

pub fn refresh(shared: &Shared, v4: Option<Ipv4Addr>, v6: &[Ipv6Addr]) {
    let ips = own_addrs(v4, v6);
    let mut st = shared.lock();
    let Some(name) = normalize(&st.settings.local_name) else {
        return; // validated when stored; never expected
    };
    let same = match st.engine.own() {
        Some((n, a)) => n == name && a == ips.as_slice(),
        None => ips.is_empty(),
    };
    if same {
        return;
    }
    if ips.is_empty() {
        st.engine.clear_own();
        drop(st);
        info!("names: {name}: no usable address; record withdrawn");
        return;
    }
    let shown: Vec<String> = ips.iter().map(|a| a.to_string()).collect();
    let r = st.engine.set_own(&name, ips);
    drop(st);
    match r {
        Ok(()) => info!("names: {name} -> {}", shown.join(", ")),
        Err(e) => info!("names: {name}: not set ({e:?})"),
    }
}
