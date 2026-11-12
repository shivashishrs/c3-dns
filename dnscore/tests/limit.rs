use dnscore::limit::RateLimiter;
use dnscore::ClientKey;
use std::net::Ipv4Addr;

fn c(n: u32) -> ClientKey {
    ClientKey::V4(Ipv4Addr::from(n))
}

#[test]
fn limiter_allows_burst_then_throttles_then_refills() {
    let mut l = RateLimiter::new(5, 2, 16);
    for _ in 0..5 {
        assert!(l.allow(c(1), 0));
    }
    assert!(!l.allow(c(1), 0));
    assert!(l.allow(c(1), 1000));
    assert!(l.allow(c(1), 1000));
    assert!(!l.allow(c(1), 1000));
    // another client is independent
    assert!(l.allow(c(2), 0));
}

#[test]
fn limiter_bounds_its_own_client_table() {
    let mut l = RateLimiter::new(5, 2, 64);
    for i in 0..10_000u32 {
        l.allow(c(i), i as u64);
        assert!(l.len() <= 64);
    }
    assert_eq!(l.len(), 64);
}

#[test]
fn limiter_survives_huge_gaps_and_backwards_clock() {
    let mut l = RateLimiter::new(5, 2, 4);
    assert!(l.allow(c(1), 10));
    assert!(l.allow(c(1), u64::MAX));
    for _ in 0..10 {
        l.allow(c(1), u64::MAX);
    }
    assert!(!l.allow(c(1), u64::MAX));
    // clock goes backwards: no panic, no free tokens
    assert!(!l.allow(c(1), 5));
    let mut z = RateLimiter::new(0, 0, 0);
    let _ = z.allow(c(1), 0);
    let mut big = RateLimiter::new(u32::MAX, u32::MAX, 2);
    assert!(big.allow(c(1), 0));
    assert!(big.allow(c(1), u64::MAX));
}

#[test]
fn v6_clients_in_one_slash_64_get_separate_buckets() {
    let a = ClientKey::from_ip("2001:db8:1:2::a".parse().unwrap());
    let b = ClientKey::from_ip("2001:db8:1:2::b".parse().unwrap());
    let mut l = RateLimiter::new(2, 1, 64);
    assert!(l.allow(a, 0));
    assert!(l.allow(a, 0));
    assert!(!l.allow(a, 0), "a has used its burst");
    assert!(l.allow(b, 0), "b has its own bucket");
    assert!(l.allow(b, 0));
}

// ---- reduced burst for new clients and the global bucket (review finding: rotating source
// addresses must not each get a full burst, and the total must be bounded) ----

use dnscore::limit::{
    global_rate_valid, Admission, TokenBucket, Verdict, GLOBAL_BURST, GLOBAL_PER_SEC, MAX_GLOBAL_BURST,
    NEW_CLIENT_BURST,
};
use std::net::Ipv6Addr;

fn v6(n: u32) -> ClientKey {
    ClientKey::from_ip(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, (n >> 16) as u16, n as u16).into())
}

fn burst_of(l: &mut RateLimiter, k: ClientKey, now: u64) -> u32 {
    let mut n = 0;
    while l.allow(k, now) {
        n += 1;
        assert!(n <= 100_000);
    }
    n
}

#[test]
fn new_clients_get_the_full_burst_until_the_table_is_full_then_the_small_one() {
    let mut l = RateLimiter::new(50, 20, 64);
    for i in 0..64 {
        assert_eq!(burst_of(&mut l, v6(i), 0), 50, "client {i} while the table has room");
    }
    for i in 64..1064 {
        assert_eq!(burst_of(&mut l, v6(i), 0), NEW_CLIENT_BURST, "client {i} into a full table");
    }
    assert_eq!(l.len(), 64);
}

#[test]
fn small_new_client_burst_never_exceeds_the_configured_burst() {
    let mut l = RateLimiter::new(3, 1, 1);
    assert_eq!(burst_of(&mut l, c(1), 0), 3);
    assert_eq!(burst_of(&mut l, c(2), 0), 3, "min(NEW_CLIENT_BURST, burst)");
}

#[test]
fn token_bucket_burst_refill_and_backwards_clock() {
    let mut b = TokenBucket::new(4, 2);
    for _ in 0..4 {
        assert!(b.allow(1000));
    }
    assert!(!b.allow(1000));
    assert!(b.allow(1500), "1 token after 500 ms at 2/s");
    assert!(!b.allow(1500));
    assert!(!b.allow(10), "clock backwards gives nothing");
    assert_eq!(b.available(1_000_000), 4, "refill stops at the burst");
    let mut big = TokenBucket::new(u32::MAX, u32::MAX);
    assert!(big.allow(0));
    assert!(big.allow(u64::MAX));
}

#[test]
fn a_thousand_rotating_addresses_cannot_exceed_the_global_bucket() {
    let mut a = Admission::new(50, 20, 64);
    let mut admitted = 0u32;
    let mut verdicts = (0u32, 0u32);
    // All at once: 1,000 fresh addresses, each trying 60 queries.
    for i in 0..1000 {
        for _ in 0..60 {
            match a.check(v6(i), 0) {
                Verdict::Allow => admitted += 1,
                Verdict::ClientLimited => verdicts.0 += 1,
                Verdict::GlobalLimited => verdicts.1 += 1,
            }
        }
    }
    assert_eq!(admitted, GLOBAL_BURST, "the global burst bounds everything at one instant");
    assert!(verdicts.1 > 0 && verdicts.0 > 0);
}

#[test]
fn rotating_addresses_over_time_are_held_to_the_global_rate() {
    let mut a = Admission::new(50, 20, 64);
    let mut admitted = 0u64;
    // 20 s, a new address every ms, each sending 5 queries: 100,000 queries offered.
    for ms in 0..20_000u64 {
        for _ in 0..5 {
            if a.check(v6(ms as u32), ms) == Verdict::Allow {
                admitted += 1;
            }
        }
    }
    let max = GLOBAL_BURST as u64 + GLOBAL_PER_SEC as u64 * 20;
    assert!(admitted <= max, "admitted {admitted} > {max}");
    assert!(admitted >= max - 2, "the global bucket is used up, not starved: {admitted}");
}

#[test]
fn a_single_flooding_client_does_not_use_up_the_global_bucket() {
    let mut a = Admission::new(50, 20, 64);
    let flood = c(1);
    let other = c(2);
    let mut other_ok = 0;
    for ms in 0..10_000u64 {
        // 2,000 q/s from one address: its own bucket refuses most before the global one.
        for _ in 0..2 {
            a.check(flood, ms);
        }
        if ms % 100 == 0 && a.check(other, ms) == Verdict::Allow {
            other_ok += 1;
        }
    }
    assert_eq!(other_ok, 100, "the normal client (10 q/s) is never refused");
}

#[test]
fn household_load_is_never_refused() {
    // Three clients, 30 q/s together for 60 s, plus a 100-query burst (34/33/33) every 10 s.
    let mut a = Admission::new(50, 20, 64);
    let clients = [c(10), c(11), ClientKey::from_ip("2001:db8::5".parse().unwrap())];
    let mut refused = 0;
    for ms in 0..60_000u64 {
        if ms % 100 == 0 {
            let k = clients[(ms / 100 % 3) as usize];
            // 10 per second per client = 30 q/s overall
            if a.check(k, ms) != Verdict::Allow {
                refused += 1;
            }
        }
        if ms % 10_000 == 5_000 {
            for (i, k) in clients.iter().enumerate() {
                for _ in 0..(if i == 0 { 34 } else { 33 }) {
                    if a.check(*k, ms) != Verdict::Allow {
                        refused += 1;
                    }
                }
            }
        }
    }
    assert_eq!(refused, 0);
}

#[test]
fn global_override_is_bounded() {
    let mut a = Admission::new(50, 20, 64);
    assert_eq!(a.global_rate(), (GLOBAL_BURST, GLOBAL_PER_SEC));
    assert!(!a.set_global(0, 10));
    assert!(!a.set_global(10, 0));
    assert!(!a.set_global(MAX_GLOBAL_BURST + 1, 10));
    assert!(!global_rate_valid(10, u32::MAX));
    assert_eq!(a.global_rate(), (GLOBAL_BURST, GLOBAL_PER_SEC));
    assert!(a.set_global(5, 1));
    assert_eq!(a.global_rate(), (5, 1));
    let mut ok = 0;
    for i in 0..100 {
        if a.check(c(i), 0) == Verdict::Allow {
            ok += 1;
        }
    }
    assert_eq!(ok, 5);
}
