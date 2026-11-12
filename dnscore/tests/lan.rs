use dnscore::lan::LanPolicy;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}
fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
}
fn policy() -> LanPolicy {
    LanPolicy { v4: Some((Ipv4Addr::new(192, 0, 2, 11), 24)), v6: vec![] }
}

#[test]
fn lan_accepts_own_subnet_ula_and_link_local() {
    let p = policy();
    assert!(p.is_lan(v4(192, 0, 2, 50)));
    assert!(p.is_lan(v6("fd12:3456::1")));
    assert!(p.is_lan(v6("fc00::1")));
    assert!(p.is_lan(v6("fe80::1")));
    assert!(p.is_lan(v6("febf::1")));
    assert!(!p.is_lan(v6("fec0::1")));
}

#[test]
fn lan_rejects_public_v4_and_v6_and_loopback() {
    let p = policy();
    assert!(!p.is_lan(v4(8, 8, 8, 8)));
    assert!(!p.is_lan(v4(192, 168, 2, 1)));
    assert!(!p.is_lan(v4(127, 0, 0, 1)));
    assert!(!p.is_lan(v4(0, 0, 0, 0)));
    assert!(!p.is_lan(v6("2001:4860:4860::8888")));
    assert!(!p.is_lan(v6("::1")));
    assert!(!p.is_lan(v6("::")));
    let none = LanPolicy { v4: None, v6: vec![] };
    assert!(!none.is_lan(v4(192, 0, 2, 50)));
}

#[test]
fn lan_accepts_a_listed_v6_prefix_only() {
    let p = LanPolicy { v4: None, v6: vec![("2001:db8:1::".parse().unwrap(), 64)] };
    assert!(p.is_lan(v6("2001:db8:1::42")));
    assert!(!p.is_lan(v6("2001:db8:2::42")));
}

#[test]
fn lan_judges_ipv4_mapped_v6_by_embedded_v4() {
    let p = policy();
    assert!(p.is_lan(v6("::ffff:192.0.2.50")));
    assert!(!p.is_lan(v6("::ffff:8.8.8.8")));
    assert!(!p.is_lan(v6("::ffff:127.0.0.1")));
    // a listed v6 prefix covering ::ffff:0:0/96 must not let public v4 through
    let wide = LanPolicy { v4: None, v6: vec![("::".parse().unwrap(), 0)] };
    assert!(!wide.is_lan(v6("::ffff:8.8.8.8")));
    assert!(!wide.is_lan(v6("2001:4860::1")));
}

#[test]
fn lan_zero_prefix_never_matches_and_big_prefix_is_safe() {
    let p = LanPolicy { v4: Some((Ipv4Addr::new(10, 0, 0, 1), 0)), v6: vec![] };
    assert!(!p.is_lan(v4(8, 8, 8, 8)));
    let q = LanPolicy { v4: Some((Ipv4Addr::new(10, 0, 0, 1), 200)), v6: vec![] };
    assert!(q.is_lan(v4(10, 0, 0, 1)));
    assert!(!q.is_lan(v4(10, 0, 0, 2)));
}

#[test]
fn prefix_extremes_do_not_panic_and_behave() {
    let net4 = Ipv4Addr::new(192, 0, 2, 11);
    let p = |bits: u8| LanPolicy { v4: Some((net4, bits)), v6: vec![] };
    assert!(!p(0).is_lan(v4(192, 0, 2, 50)), "/0 admits nothing");
    assert!(p(32).is_lan(v4(192, 0, 2, 11)));
    assert!(!p(32).is_lan(v4(192, 0, 2, 12)));
    for bits in [33u8, 64, 255] {
        assert!(p(bits).is_lan(v4(192, 0, 2, 11)), "/{bits} acts as /32");
        assert!(!p(bits).is_lan(v4(192, 0, 2, 12)), "/{bits} acts as /32");
    }
    let net6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let q = |bits: u8| LanPolicy { v4: None, v6: vec![(net6, bits)] };
    assert!(!q(0).is_lan(v6("2001:db8::1")), "/0 admits nothing");
    assert!(q(128).is_lan(v6("2001:db8::1")));
    assert!(!q(128).is_lan(v6("2001:db8::2")));
    for bits in [129u8, 200, 255] {
        assert!(q(bits).is_lan(v6("2001:db8::1")), "/{bits} acts as /128");
        assert!(!q(bits).is_lan(v6("2001:db8::2")), "/{bits} acts as /128");
    }
}
