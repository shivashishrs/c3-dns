use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscore::webauth::{
    base64_decode, parse_basic, BasicError, Gate, Lockout, SessionCache, GLOBAL_VERIFY_PER_MIN, LOCKOUT_CLIENTS,
    LOCKOUT_MS, MAX_AUTH_HEADER, MAX_FAILURES, SESSION_IDLE_MS, SESSION_SLOTS,
};
use dnscore::ClientKey;

fn b64(s: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in s.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        o.push(A[(n >> 18 & 63) as usize] as char);
        o.push(A[(n >> 12 & 63) as usize] as char);
        o.push(if c.len() > 1 { A[(n >> 6 & 63) as usize] as char } else { '=' });
        o.push(if c.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    o
}

fn client(n: u8) -> ClientKey {
    ClientKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
}

#[test]
fn base64_decodes_rfc4648_vectors() {
    for (plain, enc) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64_decode(enc.as_bytes()).as_deref(), Some(plain.as_bytes()), "{enc}");
    }
    // every byte value survives
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(base64_decode(b64(&all).as_bytes()), Some(all));
}

#[test]
fn base64_rejects_malformed_input() {
    for bad in ["Zg", "Zg=", "Z===", "Zm9v=", "Zm9", "Zg==Zg==", "Zm$v", "Zm9v\n", "Zm 9v", "=Zm9", "Zh=="] {
        assert_eq!(base64_decode(bad.as_bytes()), None, "{bad:?}");
    }
}

#[test]
fn parses_basic_credentials() {
    let h = format!("Basic {}", b64(b"admin:correct horse: battery"));
    let c = parse_basic(&h).ok().unwrap();
    assert_eq!(c.user, "admin");
    // only the first colon separates: passwords may contain colons
    assert_eq!(c.password.as_str(), "correct horse: battery");
    // the scheme is case-insensitive, surrounding blanks are ignored
    let h = format!("  bAsIc   {}  ", b64(b"admin:pw"));
    assert_eq!(parse_basic(&h).ok().unwrap().password.as_str(), "pw");
    // UTF-8 passwords
    let h = format!("Basic {}", b64("admin:pässwörd…".as_bytes()));
    assert_eq!(parse_basic(&h).ok().unwrap().password.as_str(), "pässwörd…");
    // empty password parses (verification refuses it later)
    let h = format!("Basic {}", b64(b"admin:"));
    assert_eq!(parse_basic(&h).ok().unwrap().password.as_str(), "");
}

#[test]
fn rejects_malformed_basic_headers() {
    let err = |h: &str| parse_basic(h).err();
    assert_eq!(err(""), Some(BasicError::NotBasic));
    assert_eq!(err("Bearer abc"), Some(BasicError::NotBasic));
    assert_eq!(err("Basic"), Some(BasicError::NotBasic));
    assert_eq!(err("Basicxyz"), Some(BasicError::NotBasic));
    assert_eq!(err("Basic !!!!"), Some(BasicError::BadBase64));
    assert_eq!(err("Basic Zg"), Some(BasicError::BadBase64));
    assert_eq!(err(&format!("Basic {}", b64(b"adminpassword"))), Some(BasicError::NoColon));
    assert_eq!(err(&format!("Basic {}", b64(b"admin:\xff\xfe"))), Some(BasicError::BadUtf8));
    assert_eq!(err(&format!("Basic {}", b64(b"admin:a\x00b"))), Some(BasicError::BadUtf8));
    let huge = format!("Basic {}", "A".repeat(MAX_AUTH_HEADER));
    assert_eq!(err(&huge), Some(BasicError::TooLong));
    assert_eq!(err(&"x".repeat(1_000_000)), Some(BasicError::TooLong));
    // the longest legal password (128 four-byte characters) still fits the header limit
    let pw = "😀".repeat(128);
    let h = format!("Basic {}", b64(format!("admin:{pw}").as_bytes()));
    assert!(h.len() <= MAX_AUTH_HEADER);
    assert_eq!(parse_basic(&h).ok().unwrap().password.as_str(), pw);
}

#[test]
fn session_cache_remembers_verified_headers_until_idle() {
    let mut c = SessionCache::default();
    let d = [7u8; 32];
    assert!(!c.check(&d, 0));
    c.insert(d, 0);
    assert!(c.check(&d, 1000));
    // each hit refreshes the idle timer
    assert!(c.check(&d, SESSION_IDLE_MS));
    assert!(c.check(&d, 2 * SESSION_IDLE_MS));
    // idle too long: gone
    assert!(!c.check(&d, 3 * SESSION_IDLE_MS + 1));
    assert_eq!(c.len(), 0);
    // a different digest never matches
    c.insert(d, 0);
    let mut other = d;
    other[31] ^= 1;
    assert!(!c.check(&other, 1));
}

#[test]
fn session_cache_is_bounded_and_evicts_the_least_recently_used() {
    let mut c = SessionCache::default();
    for i in 0..SESSION_SLOTS as u8 {
        c.insert([i; 32], u64::from(i));
    }
    assert_eq!(c.len(), SESSION_SLOTS);
    assert!(c.check(&[0; 32], 100)); // slot 0 is now the most recent
    c.insert([99; 32], 101); // evicts slot 1 (least recently used)
    assert_eq!(c.len(), SESSION_SLOTS);
    assert!(!c.check(&[1; 32], 102));
    assert!(c.check(&[0; 32], 102));
    assert!(c.check(&[99; 32], 102));
    // inserting a known digest refreshes it instead of using another slot
    c.insert([99; 32], 103);
    assert_eq!(c.len(), SESSION_SLOTS);
    c.clear();
    assert_eq!(c.len(), 0);
    assert!(!c.check(&[0; 32], 104));
}

#[test]
fn lockout_after_max_failures_for_a_minute() {
    let mut l = Lockout::default();
    let a = client(7);
    let mut now = 1_000;
    for i in 0..MAX_FAILURES {
        assert_eq!(l.before_verify(a, now), Gate::Ok, "attempt {i}");
        let locked = l.failed(a, now);
        assert_eq!(locked, i + 1 == MAX_FAILURES);
        now += 100;
    }
    // the sixth attempt is refused without a password check
    match l.before_verify(a, now) {
        Gate::Locked { retry_after_secs } => assert!((59..=60).contains(&retry_after_secs)),
        g => panic!("expected Locked, got {g:?}"),
    }
    assert!(l.locked(a, now).is_some());
    // another client is unaffected
    assert_eq!(l.before_verify(client(8), now), Gate::Ok);
    // after the lockout the client may try again, with a fresh count
    now += LOCKOUT_MS;
    assert_eq!(l.locked(a, now), None);
    assert_eq!(l.before_verify(a, now), Gate::Ok);
    assert!(!l.failed(a, now));
}

#[test]
fn success_resets_the_failure_count() {
    let mut l = Lockout::default();
    let a = client(7);
    for _ in 0..MAX_FAILURES - 1 {
        l.failed(a, 0);
    }
    l.succeeded(a);
    for _ in 0..MAX_FAILURES - 1 {
        assert!(!l.failed(a, 1));
    }
    assert!(l.failed(a, 1));
}

#[test]
fn global_verification_budget_bounds_hashing_per_minute() {
    let mut l = Lockout::default();
    let mut n = 0u32;
    // many different clients (address rotation) each try once
    for i in 0..200u16 {
        let c = ClientKey::from_ip(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i)));
        match l.before_verify(c, 5_000) {
            Gate::Ok => {
                n += 1;
                l.failed(c, 5_000);
            }
            Gate::Busy { retry_after_secs } => assert!((1..=60).contains(&retry_after_secs)),
            g => panic!("unexpected {g:?}"),
        }
    }
    assert_eq!(n, GLOBAL_VERIFY_PER_MIN);
    // the next minute opens a new window
    assert_eq!(l.before_verify(client(1), 5_000 + 60_000), Gate::Ok);
}

#[test]
fn lockout_table_is_bounded() {
    let mut l = Lockout::default();
    for i in 0..10_000u32 {
        let c = ClientKey::from_ip(IpAddr::V6(Ipv6Addr::from(u128::from(i) | 0xfd00 << 112)));
        l.failed(c, u64::from(i));
        assert!(l.len() <= LOCKOUT_CLIENTS);
    }
}
