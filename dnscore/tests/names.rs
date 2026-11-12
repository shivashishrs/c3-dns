use dnscore::names::{own_addrs, MAX_OWN_ADDRS};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

#[test]
fn keeps_v4_global_and_ula_drops_link_local_and_specials() {
    let got = own_addrs(
        Some(Ipv4Addr::new(192, 0, 2, 3)),
        &[
            v6("fe80::eaf6:aff:fe4f:1adc"),
            v6("2001:db8:1:2:eaf6:aff:fe4f:1adc"),
            v6("fd00:1::5"),
            v6("::1"),
            v6("::"),
            v6("ff02::1"),
            v6("::ffff:192.0.2.3"),
        ],
    );
    assert_eq!(
        got,
        vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
            IpAddr::V6(v6("2001:db8:1:2:eaf6:aff:fe4f:1adc")),
            IpAddr::V6(v6("fd00:1::5")),
        ]
    );
}

#[test]
fn no_usable_v4_and_duplicates_are_dropped() {
    for bad in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::LOCALHOST, Ipv4Addr::new(169, 254, 3, 4)] {
        assert!(own_addrs(Some(bad), &[]).is_empty(), "{bad}");
    }
    assert!(own_addrs(None, &[v6("fe80::1")]).is_empty());
    let a = v6("2001:db8::7");
    assert_eq!(own_addrs(None, &[a, a]), vec![IpAddr::V6(a)]);
}

#[test]
fn bounded() {
    let many: Vec<Ipv6Addr> = (0..40u16).map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)).collect();
    let got = own_addrs(Some(Ipv4Addr::new(10, 0, 0, 2)), &many);
    assert_eq!(got.len(), MAX_OWN_ADDRS);
    assert_eq!(got[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
}
