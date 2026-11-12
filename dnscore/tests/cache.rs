use dnscore::cache::{cacheable, Cache, CacheKey, Lookup, MAX_ENTRY_BYTES};
use dnscore::*;

fn enc_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

fn a_response(name: &str, ttl: u32) -> Vec<u8> {
    let mut p = Vec::new();
    for x in [0x1234u16, 0x8180, 1, 1, 0, 0] {
        p.extend_from_slice(&x.to_be_bytes());
    }
    p.extend(enc_name(name));
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&[0xC0, 0x0C]);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&ttl.to_be_bytes());
    p.extend_from_slice(&4u16.to_be_bytes());
    p.extend_from_slice(&[1, 2, 3, 4]);
    p
}

fn key(n: &str) -> CacheKey {
    CacheKey { name: n.to_string(), qtype: QTYPE_A }
}

const SIX_H: u32 = 6 * 3600;

#[test]
fn cache_returns_fresh_then_stale_then_miss() {
    let mut c = Cache::new(8, SIX_H);
    c.put(key("a.com"), a_response("a.com", 60), 60, 1000);
    assert!(matches!(c.get(&key("a.com"), 1030), Lookup::Fresh(_)));
    assert!(matches!(c.get(&key("a.com"), 1120), Lookup::Stale(_)));
    assert!(matches!(c.get(&key("a.com"), 1000 + 7 * 3600), Lookup::Miss));
    assert!(matches!(c.get(&key("other.com"), 1000), Lookup::Miss));
}

#[test]
fn fresh_hit_has_aged_ttls() {
    let mut c = Cache::new(8, SIX_H);
    c.put(key("a.com"), a_response("a.com", 60), 60, 1000);
    match c.get(&key("a.com"), 1030) {
        Lookup::Fresh(p) => assert_eq!(parse_response(&p).unwrap().min_ttl, 30),
        _ => panic!("expected fresh"),
    }
}

#[test]
fn cache_evicts_oldest_at_capacity_and_never_exceeds_cap() {
    let mut c = Cache::new(3, SIX_H);
    for i in 0..10 {
        let n = format!("h{i}.com");
        c.put(key(&n), a_response(&n, 60), 60, 1000);
        assert!(c.len() <= 3);
    }
    assert_eq!(c.len(), 3);
    assert!(matches!(c.get(&key("h0.com"), 1001), Lookup::Miss));
    assert!(matches!(c.get(&key("h9.com"), 1001), Lookup::Fresh(_)));
    // re-putting an existing key does not grow the cache
    c.put(key("h9.com"), a_response("h9.com", 60), 60, 1002);
    assert_eq!(c.len(), 3);
}

#[test]
fn cache_zero_capacity_and_huge_times_do_not_panic() {
    let mut c = Cache::new(0, SIX_H);
    c.put(key("a.com"), a_response("a.com", 60), 60, 0);
    assert_eq!(c.len(), 0);
    let mut c = Cache::new(2, u32::MAX);
    c.put(key("a.com"), a_response("a.com", 60), u32::MAX, u64::MAX - 1);
    let _ = c.get(&key("a.com"), 0);
    let _ = c.get(&key("a.com"), u64::MAX);
}

#[test]
fn stale_and_miss_boundaries_are_exact() {
    let mut c = Cache::new(8, 100);
    c.put(key("a.com"), a_response("a.com", 60), 60, 1000);
    // expires = 1060
    assert!(matches!(c.get(&key("a.com"), 1059), Lookup::Fresh(_)));
    assert!(matches!(c.get(&key("a.com"), 1060), Lookup::Stale(_)));
    assert!(matches!(c.get(&key("a.com"), 1160), Lookup::Stale(_)));
    assert!(matches!(c.get(&key("a.com"), 1161), Lookup::Miss));
    assert_eq!(c.len(), 0);
}

// ---- Task 6: byte budget and entry size bound ----

fn big_response(name: &str, ttl: u32, extra: usize) -> Vec<u8> {
    let mut p = a_response(name, ttl);
    p.extend(std::iter::repeat_n(0u8, extra)); // trailing bytes count toward size
    p
}

#[test]
fn entries_over_512_bytes_are_never_cached() {
    let mut c = Cache::new(8, SIX_H);
    let r = big_response("a.com", 60, 600);
    assert!(r.len() > MAX_ENTRY_BYTES);
    c.put(key("a.com"), r, 60, 1000);
    assert_eq!(c.len(), 0);
    let ok = big_response("b.com", 60, MAX_ENTRY_BYTES - a_response("b.com", 60).len());
    assert_eq!(ok.len(), MAX_ENTRY_BYTES);
    c.put(key("b.com"), ok, 60, 1000);
    assert_eq!(c.len(), 1);
}

#[test]
fn byte_budget_evicts_oldest_and_is_never_exceeded() {
    let budget = 2000;
    let mut c = Cache::with_budget(100, SIX_H, budget);
    for i in 0..50 {
        let n = format!("h{i}.com");
        c.put(key(&n), big_response(&n, 60, 300), 60, 1000);
        assert!(c.bytes() <= budget, "bytes {} > {budget}", c.bytes());
    }
    assert!(c.len() >= 2 && c.len() < 50);
    assert!(matches!(c.get(&key("h49.com"), 1001), Lookup::Fresh(_)));
    assert!(matches!(c.get(&key("h0.com"), 1001), Lookup::Miss));
}

#[test]
fn replacing_an_entry_keeps_the_byte_count_right() {
    let mut c = Cache::with_budget(10, SIX_H, 10_000);
    c.put(key("a.com"), big_response("a.com", 60, 300), 60, 1000);
    let one = c.bytes();
    c.put(key("a.com"), a_response("a.com", 60), 60, 1001);
    assert!(c.bytes() < one);
    c.put(key("a.com"), big_response("a.com", 60, 300), 60, 1002);
    assert_eq!(c.bytes(), one);
    // a Miss past max_stale removes the entry and its bytes
    let _ = c.get(&key("a.com"), 1002 + 60 + SIX_H as u64 + 1);
    assert_eq!(c.bytes(), 0);
    assert_eq!(c.len(), 0);
}

// ---- cacheable decision ----

fn resp(rcode: u8, truncated: bool, min_ttl: u32) -> Response {
    Response { rcode, truncated, min_ttl, cnames: vec![] }
}

#[test]
fn cacheable_refuses_paused_truncated_oversized_errors_and_zero_ttl() {
    assert!(cacheable(&resp(0, false, 60), 100, false));
    assert!(cacheable(&resp(3, false, 60), 100, false), "NXDOMAIN is cacheable");
    assert!(!cacheable(&resp(0, false, 60), 100, true), "nothing fetched while paused");
    assert!(!cacheable(&resp(0, true, 60), 100, false), "truncated");
    assert!(!cacheable(&resp(0, false, 60), MAX_ENTRY_BYTES + 1, false), "oversized");
    assert!(cacheable(&resp(0, false, 60), MAX_ENTRY_BYTES, false));
    assert!(!cacheable(&resp(2, false, 60), 100, false), "SERVFAIL");
    assert!(!cacheable(&resp(5, false, 60), 100, false), "REFUSED");
    assert!(!cacheable(&resp(0, false, 0), 100, false), "zero TTL");
}
