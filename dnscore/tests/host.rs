use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscore::host::{host_allowed, MAX_HOST};

const NAMES: [&str; 2] = ["adblock.local", "adblock.home"];

fn addrs() -> Vec<IpAddr> {
    vec![
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        IpAddr::V6("2001:db8::1adc".parse::<Ipv6Addr>().unwrap()),
        IpAddr::V6("fe80::eaf6:aff:fe4f:1adc".parse::<Ipv6Addr>().unwrap()),
    ]
}

fn ok(h: &str) -> bool {
    host_allowed(Some(h), &NAMES, &addrs())
}

#[test]
fn own_names_and_addresses_are_accepted() {
    assert!(ok("adblock.local"));
    assert!(ok("adblock.home"));
    assert!(ok("192.0.2.3"));
    assert!(ok("[2001:db8::1adc]"));
    assert!(ok("[fe80::eaf6:aff:fe4f:1adc]"));
}

#[test]
fn ports_are_optional_but_must_be_numbers() {
    assert!(ok("adblock.local:80"));
    assert!(ok("192.0.2.3:8080"));
    assert!(ok("[2001:db8::1adc]:80"));
    assert!(ok("adblock.home:65535"));
    for bad in ["adblock.local:", "adblock.local:0", "adblock.local:65536", "adblock.local:8o", "adblock.local:+80",
        "adblock.local:123456", "192.0.2.3:80:80", "[2001:db8::1adc]:", "[2001:db8::1adc]x", "[2001:db8::1adc]:8x"]
    {
        assert!(!ok(bad), "{bad}");
    }
}

#[test]
fn case_and_one_trailing_dot_do_not_matter() {
    assert!(ok("ADBLOCK.Local"));
    assert!(ok("adblock.local."));
    assert!(ok("AdBlock.Home.:80"));
    assert!(!ok("adblock.local.."));
    assert!(!ok("."));
    assert!(ok("[2001:DB8::1ADC]"), "IPv6 hex digits in any case");
}

#[test]
fn other_names_and_addresses_are_refused() {
    for bad in [
        "evil.example",
        "adblock.local.evil.example",
        "evil.example:80",
        "localhost",
        "adblock",
        "192.0.2.4",
        "198.51.100.3",
        "[2001:db8::1add]",
        "127.0.0.1",
        "[::1]",
        "0.0.0.0",
    ] {
        assert!(!ok(bad), "{bad}");
    }
}

#[test]
fn malformed_ipv6_forms_are_refused() {
    for bad in [
        "2001:db8::1adc",             // unbracketed
        "[2001:db8::1adc",            // unclosed
        "2001:db8::1adc]",            // no opening bracket
        "[fe80::eaf6:aff:fe4f:1adc%25en0]", // zone identifiers are not accepted
        "[192.0.2.3]",                // an IPv4 address in brackets
        "[]",
        "[adblock.local]",
    ] {
        assert!(!ok(bad), "{bad}");
    }
}

#[test]
fn ipv4_mapped_forms_match_the_ipv4_address() {
    assert!(ok("[::ffff:192.0.2.3]"));
    assert!(!ok("[::ffff:192.0.2.4]"));
    // an IPv4-mapped entry in the device's list matches the plain IPv4 form too
    let mapped = [IpAddr::V6("::ffff:198.51.100.7".parse::<Ipv6Addr>().unwrap())];
    assert!(host_allowed(Some("198.51.100.7"), &[], &mapped));
}

#[test]
fn missing_empty_huge_or_odd_hosts_are_refused() {
    assert!(!host_allowed(None, &NAMES, &addrs()));
    assert!(!ok(""));
    assert!(!ok(" adblock.local"));
    assert!(!ok("adblock.local "));
    assert!(!ok("adblock .local"));
    assert!(!ok("user@adblock.local"));
    assert!(!ok("adblock.local/x"));
    let huge = format!("{}.adblock.local", "a".repeat(MAX_HOST));
    assert!(!ok(&huge));
    let huge = "a".repeat(100_000);
    assert!(!ok(&huge));
    // an exact name of the maximum length is fine when it is one of ours
    let long = format!("{}.home", "a".repeat(MAX_HOST - 5));
    assert!(host_allowed(Some(&long), &[long.as_str()], &[]));
}

#[test]
fn configured_names_are_compared_without_their_trailing_dot_or_case() {
    assert!(host_allowed(Some("nas.lan"), &["NAS.lan."], &[]));
    assert!(!host_allowed(Some("nas.lan"), &[], &[]));
    assert!(!host_allowed(Some("anything"), &[""], &[]), "an empty configured name matches nothing");
}
