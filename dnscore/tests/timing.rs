use dnscore::timing::{next_rotation_at, read_timeout_for, rotation_due, CaseFallback};
use std::time::Duration;

const IDLE: Duration = Duration::from_secs(3);
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn read_timeout_expired_when_less_than_one_ms_left() {
    assert_eq!(read_timeout_for(Duration::ZERO, IDLE), None);
    assert_eq!(read_timeout_for(Duration::from_micros(1), IDLE), None);
    assert_eq!(read_timeout_for(Duration::from_micros(999), IDLE), None, "sub-ms would become 0 = forever");
}

#[test]
fn read_timeout_is_whole_ms_and_never_zero() {
    assert_eq!(read_timeout_for(ms(1), IDLE), Some(ms(1)), "1 ms edge");
    assert_eq!(read_timeout_for(Duration::from_micros(1500), IDLE), Some(ms(1)));
    assert_eq!(read_timeout_for(ms(2500), IDLE), Some(ms(2500)));
    assert_eq!(read_timeout_for(IDLE, IDLE), Some(IDLE), "exactly idle");
    assert_eq!(read_timeout_for(ms(10_000), IDLE), Some(IDLE), "left > idle -> idle");
    assert_eq!(read_timeout_for(ms(10), Duration::ZERO), Some(ms(1)), "a zero cap still never yields 0");
    for us in [1_000u64, 1_001, 5_999, 2_999_999, 3_000_001] {
        let t = read_timeout_for(Duration::from_micros(us), IDLE).unwrap();
        assert!(t >= ms(1) && t.subsec_nanos().is_multiple_of(1_000_000), "{us} us -> {t:?}");
    }
}

#[test]
fn rotation_due_by_time_or_count() {
    let next = next_rotation_at(0, true, 60_000, 5_000);
    assert_eq!(next, 60_000);
    assert!(!rotation_due(59_999, next, 0, 2000));
    assert!(rotation_due(60_000, next, 0, 2000));
    assert!(rotation_due(10, next, 2000, 2000), "2000 sends");
}

#[test]
fn failed_rotation_retries_after_the_retry_interval_not_every_scan() {
    let now = 1_000_000;
    let next = next_rotation_at(now, false, 60_000, 5_000);
    for t in [now, now + 50, now + 4_999] {
        assert!(!rotation_due(t, next, 0, 2000), "retry too soon at {t}");
    }
    assert!(rotation_due(now + 5_000, next, 0, 2000));
    assert_eq!(next_rotation_at(u64::MAX - 1, false, 60_000, 5_000), u64::MAX, "no overflow");
}

#[test]
fn case_fallback_disables_after_three_consecutive_and_match_resets_streak() {
    let mut f: CaseFallback<u8> = CaseFallback::new(3, 600_000, 8);
    assert!(f.enabled(1, 0));
    assert!(!f.on_mismatch(1, 0));
    assert!(!f.on_mismatch(1, 0));
    f.on_match(1, 0);
    assert!(!f.on_mismatch(1, 0));
    assert!(!f.on_mismatch(1, 0));
    assert!(f.enabled(1, 0), "streak was broken by a match");
    assert!(f.on_mismatch(1, 0), "third consecutive: newly disabled");
    assert!(!f.enabled(1, 0));
    assert!(!f.on_mismatch(1, 0), "already disabled: not reported again");
    assert!(f.enabled(2, 0), "other upstreams unaffected");
}

#[test]
fn case_fallback_resets_every_period() {
    let mut f: CaseFallback<u8> = CaseFallback::new(3, 600_000, 8);
    for _ in 0..3 {
        f.on_mismatch(1, 1_000);
    }
    assert!(!f.enabled(1, 1_000));
    assert!(!f.enabled(1, 600_999));
    assert!(f.enabled(1, 601_000), "re-enabled after 10 minutes");
    assert!(!f.on_mismatch(1, 601_000), "the streak starts over too");
}

#[test]
fn case_fallback_is_bounded() {
    let mut f: CaseFallback<u32> = CaseFallback::new(3, 600_000, 8);
    for a in 0..1000u32 {
        f.on_mismatch(a, 0);
    }
    assert!(f.len() <= 8);
}
