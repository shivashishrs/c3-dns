use dnscore::stats::DailySummary;
use dnscore::store::{decode, encode, Persisted, Saver, Settings, Warning};
use dnscore::{ClientKey, RuleKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn sample() -> Persisted {
    Persisted {
        rules: vec![
            (RuleKind::Block, "ads.example.com".to_string()),
            (RuleKind::Allow, "ok.example.org".to_string()),
            (RuleKind::Block, "*.tracker.net".to_string()),
        ],
        records: vec![
            ("nas.home".to_string(), vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))]),
            (
                "pc.home".to_string(),
                vec![
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)),
                    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),
                ],
            ),
        ],
        bans: vec![
            ClientKey::V4(Ipv4Addr::new(192, 0, 2, 99)),
            ClientKey::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 77)),
        ],
        settings: Settings {
            upstreams: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            rate_burst: 7,
            rate_per_sec: 3,
            stale_secs: 100,
            local_name: "box.lan".to_string(),
            log_cap: 123,
            cache_cap: 45,
        },
        summaries: vec![DailySummary {
            day: 20000,
            allowed: 10,
            blocked: 4,
            top_queried: vec![("a.com".to_string(), 5), ("b.com".to_string(), 2)],
            top_blocked: vec![("ads.example.com".to_string(), 4)],
        }],
    }
}

fn same(a: &Persisted, b: &Persisted) -> bool {
    a.rules == b.rules
        && a.records == b.records
        && a.bans == b.bans
        && a.settings == b.settings
        && a.summaries == b.summaries
}

#[test]
fn roundtrip_preserves_everything() {
    let p = sample();
    let (q, w) = decode(&encode(&p));
    assert_eq!(w, None);
    assert!(same(&p, &q));
}

#[test]
fn defaults_are_as_specified() {
    let s = Settings::default();
    assert_eq!(s.upstreams.len(), 4);
    assert_eq!(s.upstreams[0], "9.9.9.9".parse::<IpAddr>().unwrap());
    assert_eq!(s.upstreams[1], "1.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(s.upstreams[2], "2620:fe::fe".parse::<IpAddr>().unwrap());
    assert_eq!(s.upstreams[3], "2606:4700:4700::1111".parse::<IpAddr>().unwrap());
    assert_eq!((s.rate_burst, s.rate_per_sec, s.stale_secs), (50, 20, 21600));
    assert_eq!((s.local_name.as_str(), s.log_cap, s.cache_cap), ("adblock.home", 500, 300));
}

#[test]
fn decode_of_empty_is_defaults_with_empty_warning() {
    let (p, w) = decode(&[]);
    assert_eq!(w, Some(Warning::Empty));
    assert!(p.rules.is_empty() && p.records.is_empty() && p.bans.is_empty());
    assert_eq!(p.settings, Settings::default());
}

// Every single bit of a real blob, deterministically. A flip in the version
// byte yields UnknownVersion (checked before the CRC); all others are Corrupt.
#[test]
fn decode_of_flipped_bit_is_defaults_with_corrupt_warning() {
    let good = encode(&sample());
    for bit in 0..good.len() * 8 {
        let mut b = good.clone();
        b[bit / 8] ^= 1 << (bit % 8);
        let (p, w) = decode(&b);
        assert!(w.is_some(), "flip of bit {bit} undetected");
        if bit / 8 == 4 {
            assert_eq!(w, Some(Warning::UnknownVersion));
        } else {
            assert_eq!(w, Some(Warning::Corrupt), "bit {bit}");
        }
        assert!(p.rules.is_empty());
        assert_eq!(p.settings, Settings::default());
    }
}

#[test]
fn decode_of_future_version_is_defaults_with_unknown_version() {
    let mut b = encode(&sample());
    // Version byte sits right after the 4-byte magic.
    b[4] = 200;
    let (p, w) = decode(&b);
    assert_eq!(w, Some(Warning::UnknownVersion));
    assert!(p.rules.is_empty());
    assert_eq!(p.settings, Settings::default());
}

#[test]
fn decode_never_panics_on_random_bytes() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let good = encode(&sample());
    for i in 0..100_000 {
        let len = (rng.next() % 200) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if i % 2 == 0 && len >= 5 {
            b[..4].copy_from_slice(&good[..4]);
            b[4] = good[4];
        }
        let _ = decode(&b);
    }
}

#[test]
fn decode_rejects_huge_length_without_allocating() {
    let good = encode(&sample());
    let mut b = good.clone();
    // Corrupt the declared payload length to something enormous.
    for x in &mut b[5..9] {
        *x = 0xff;
    }
    let (_, w) = decode(&b);
    assert_eq!(w, Some(Warning::Corrupt));
}

#[test]
fn saver_saves_nothing_when_not_dirty() {
    let mut s = Saver::new(60, 10);
    assert!(!s.should_save(false, 1_000));
    assert!(!s.should_save(false, 100_000));
}

#[test]
fn saver_never_saves_more_often_than_the_interval() {
    let mut s = Saver::new(60, 1000);
    assert!(s.should_save(true, 1_000));
    assert!(!s.should_save(true, 1_059));
    assert!(s.should_save(true, 1_060));
    assert!(!s.should_save(true, 1_100));
}

#[test]
fn saver_stops_at_the_daily_budget_and_resets_next_day() {
    let mut s = Saver::new(10, 3);
    let day = 5 * 86_400;
    assert!(s.should_save(true, day));
    assert!(s.should_save(true, day + 10));
    assert!(s.should_save(true, day + 20));
    assert!(!s.should_save(true, day + 30));
    assert!(!s.should_save(true, day + 86_399));
    assert!(s.should_save(true, day + 86_400));
}

// ---- blobs with a valid header and CRC ----

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn wrap(payload: &[u8]) -> Vec<u8> {
    let mut o = b"C3DS".to_vec();
    o.push(1);
    o.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    o.extend_from_slice(payload);
    let c = crc32(&o);
    o.extend_from_slice(&c.to_le_bytes());
    o
}

fn assert_corrupt(payload: &[u8]) {
    let (p, w) = decode(&wrap(payload));
    assert_eq!(w, Some(Warning::Corrupt));
    assert!(p.rules.is_empty() && p.records.is_empty() && p.bans.is_empty());
    assert_eq!(p.settings, Settings::default());
}

#[test]
fn wrapped_helper_matches_encode() {
    let good = encode(&sample());
    assert_eq!(wrap(&good[9..good.len() - 4]), good);
}

#[test]
fn decode_never_panics_on_valid_header_random_payloads() {
    let mut rng = Rng(0x0bad_cafe_1234_5678);
    let good = encode(&sample());
    let body = &good[9..good.len() - 4];
    for i in 0..100_000 {
        let payload: Vec<u8> = if i % 2 == 0 {
            let len = (rng.next() % 120) as usize;
            (0..len).map(|_| rng.next() as u8).collect()
        } else {
            // Mutate a real payload so deeper parsing is reached.
            let mut b = body.to_vec();
            for _ in 0..1 + rng.next() % 3 {
                let k = (rng.next() % b.len() as u64) as usize;
                b[k] = rng.next() as u8;
            }
            if rng.next().is_multiple_of(4) {
                b.truncate((rng.next() % b.len() as u64) as usize);
            }
            b
        };
        let (p, w) = decode(&wrap(&payload));
        match w {
            None => {}
            Some(w) => {
                assert_eq!(w, Warning::Corrupt);
                assert!(p.rules.is_empty());
                assert_eq!(p.settings, Settings::default());
            }
        }
    }
}

#[test]
fn oversized_nested_counts_are_corrupt() {
    // rules count 500, no body
    assert_corrupt(&500u16.to_le_bytes());
    // rules count over the limit
    assert_corrupt(&501u16.to_le_bytes());
    // rules count 0xFFFF
    assert_corrupt(&[0xff, 0xff]);
    // string length 0xFFFF-ish: one rule, kind block, length byte 0xFF, no body
    assert_corrupt(&[1, 0, 1, 0xff]);
    // records count huge
    assert_corrupt(&[0, 0, 0xff, 0xff]);
    // summaries count huge: take a valid payload, replace tail
    let good = encode(&Persisted::default());
    let mut pl = good[9..good.len() - 4].to_vec();
    let n = pl.len();
    pl[n - 1] = 0xff; // summaries count (last byte when there are none)
    assert_corrupt(&pl);
    // u16 string length in the wide sense: 0xFFFF as two bytes
    assert_corrupt(&[1, 0, 1, 0xff, 0xff]);
}

// Builds a blob with an out-of-range setting by encoding a valid one and
// patching the field bytes in place, then re-wrapping with a valid CRC.
fn patched(find: &[u8], repl: &[u8]) {
    let good = encode(&sample());
    let body = good[9..good.len() - 4].to_vec();
    let at = body.windows(find.len()).position(|w| w == find).expect("field");
    let mut b = body;
    b[at..at + repl.len()].copy_from_slice(repl);
    assert_corrupt(&b);
}

#[test]
fn invalid_settings_are_corrupt() {
    // sample(): upstreams=[8.8.8.8] burst 7, per_sec 3, stale 100, "box.lan", log 123, cache 45
    let burst = [7u8, 0, 0, 0, 3, 0, 0, 0, 100, 0, 0, 0];
    patched(&burst, &[0, 0, 0, 0]);
    patched(&burst, &[7, 0, 0, 0, 0, 0, 0, 0]);
    patched(&burst, &[7, 0, 0, 0, 3, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f]);
    let caps = [7u8, b'b', b'o', b'x', b'.', b'l', b'a', b'n', 123, 0, 0, 0, 45, 0, 0, 0];
    patched(&caps, &[7, b'b', b'o', b'x', b'.', b'l', b'a', b'n', 0xd1, 0x07, 0, 0, 45, 0, 0, 0]);
    patched(&caps, &[7, b'b', b'o', b'x', b'.', b'l', b'a', b'n', 123, 0, 0, 0, 0xe9, 0x03, 0, 0]);
    // empty upstreams: build by hand from a default-settings payload
    let s = Settings { upstreams: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], ..Default::default() };
    let good = encode(&Persisted { settings: s, ..Default::default() });
    let mut body = good[9..good.len() - 4].to_vec();
    // layout: rules(2) records(2) bans(1) upstream count(1) ...
    body[5] = 0;
    body.drain(6..11); // remove the one v4 entry (tag + 4 bytes)
    assert_corrupt(&body);
}

#[test]
fn encode_never_emits_a_blob_decode_rejects() {
    let long = "a".repeat(300);
    let mut p = sample();
    for i in 0..600 {
        p.rules.push((RuleKind::Block, format!("r{i}.example.com")));
    }
    p.rules.push((RuleKind::Block, "bad pattern!!".to_string()));
    p.rules.push((RuleKind::Block, long.clone()));
    for i in 0..150 {
        p.records.push((format!("h{i}.home"), vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]));
    }
    p.records.push(("empty.home".to_string(), vec![]));
    p.records.push(("not valid".to_string(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
    for i in 0..100u8 {
        p.bans.push(ClientKey::V4(Ipv4Addr::new(10, 1, 0, i)));
    }
    p.settings = Settings {
        upstreams: vec![],
        rate_burst: 0,
        rate_per_sec: 0,
        stale_secs: u32::MAX,
        local_name: "bad name".to_string(),
        log_cap: 1_000_000,
        cache_cap: 1_000_000,
    };
    let multi = "é".repeat(200); // 400 bytes, clipped at a char boundary
    for d in 0..10 {
        p.summaries.push(DailySummary {
            day: d,
            allowed: 1,
            blocked: 1,
            top_queried: vec![(multi.clone(), 1); 30],
            top_blocked: vec![],
        });
    }
    let (q, w) = decode(&encode(&p));
    assert_eq!(w, None);
    assert!(q.rules.len() <= 500 && q.records.len() <= 100 && q.bans.len() <= 64);
    assert!(!q.settings.upstreams.is_empty() && q.settings.rate_burst >= 1);
    assert_eq!(q.settings.log_cap, 2000);
}

#[test]
fn saver_backwards_clock_jump_does_not_stick() {
    let mut s = Saver::new(60, 1000);
    assert!(s.should_save(true, 100_000));
    assert!(s.should_save(true, 50_000));
    assert!(!s.should_save(true, 50_030));
    assert!(s.should_save(true, 50_060));
}

#[test]
fn saver_oscillating_clock_cannot_exceed_daily_budget() {
    let mut s = Saver::new(1, 4);
    let mut saved = 0;
    for i in 0..100u64 {
        // alternate between day 10 and day 9 and day 11 never reached
        let t = if i % 2 == 0 { 10 * 86_400 + i * 2 } else { 9 * 86_400 + i * 2 };
        if s.should_save(true, t) {
            saved += 1;
        }
    }
    assert_eq!(saved, 4);
}

// ---- byte budget (review finding: a save must never need more RAM than a fixed budget) ----

use dnscore::stats::{clip_summary_name, CLIP_MARK, SUMMARY_NAME_MAX, SUMMARY_TOP};
use dnscore::store::{
    clamp_settings, settings_valid, try_encode, EncodeError, BLOB_BUDGET, MAX_RATE_BURST, MAX_RATE_PER_SEC,
};

/// A 253-byte valid DNS name (four labels of 63, unique per `i`).
fn long_name(i: usize) -> String {
    let l = |c: char| c.to_string().repeat(63);
    let n = format!("{:03}{}.{}.{}.{}", i % 1000, &l('a')[3..], l('b'), l('c'), "d".repeat(61));
    assert_eq!(n.len(), 253);
    n
}

fn full_day(day: u32) -> DailySummary {
    DailySummary {
        day,
        allowed: day,
        blocked: day / 2,
        top_queried: (0..SUMMARY_TOP).map(|i| (long_name(i), 100 - i as u32)).collect(),
        top_blocked: (0..SUMMARY_TOP).map(|i| (long_name(500 + i), 50 - i as u32)).collect(),
    }
}

/// Owner data of roughly `bytes` bytes (rules of 200-byte names).
fn with_user_bytes(bytes: usize) -> Persisted {
    let mut p = sample();
    let mut i = 0;
    while p.rules.iter().map(|(_, r)| r.len() + 2).sum::<usize>() < bytes {
        p.rules.push((RuleKind::Block, format!("r{i:04}.{}.{}.{}.example.com", "x".repeat(60), "y".repeat(60), "z".repeat(48))));
        i += 1;
    }
    p
}

#[test]
fn seven_full_days_of_long_names_encode_within_budget_and_decode_cleanly() {
    let mut p = sample();
    p.summaries = (0..7).map(|d| full_day(20_000 + d)).collect();
    let e = try_encode(&p, BLOB_BUDGET).unwrap();
    assert!(e.bytes.len() <= BLOB_BUDGET, "{}", e.bytes.len());
    assert_eq!(e.dropped_summaries, 0, "7 clipped days fit the budget with room to spare");
    assert_eq!(e.bytes.capacity(), e.bytes.len(), "one exact allocation, no doubling");
    let (q, w) = decode(&e.bytes);
    assert_eq!(w, None);
    assert_eq!(q.summaries.len(), 7);
    for d in &q.summaries {
        for (n, _) in d.top_queried.iter().chain(&d.top_blocked) {
            assert!(n.len() <= SUMMARY_NAME_MAX, "{} bytes", n.len());
            assert!(n.ends_with(CLIP_MARK));
        }
    }
    assert_eq!(q.summaries[0].top_queried[0].0, clip_summary_name(&long_name(0)));
    assert!(same(&Persisted { summaries: vec![], ..p.clone() }, &Persisted { summaries: vec![], ..q }));
}

#[test]
fn over_budget_drops_the_oldest_summaries_and_keeps_all_user_data() {
    let mut p = with_user_bytes(16 * 1024);
    p.summaries = (0..7).map(|d| full_day(20_000 + d)).collect();
    let e = try_encode(&p, BLOB_BUDGET).unwrap();
    assert!(e.bytes.len() <= BLOB_BUDGET);
    assert!(e.dropped_summaries > 0 && e.dropped_summaries < 7, "dropped {}", e.dropped_summaries);
    assert_eq!(e.trimmed_top_entries, 0);
    let (q, w) = decode(&e.bytes);
    assert_eq!(w, None);
    assert_eq!(q.rules, p.rules, "every rule kept");
    assert_eq!((&q.records, &q.bans, &q.settings), (&p.records, &p.bans, &p.settings));
    let kept: Vec<u32> = q.summaries.iter().map(|d| d.day).collect();
    let want: Vec<u32> = (20_000 + e.dropped_summaries as u32..20_007).collect();
    assert_eq!(kept, want, "the newest days are the ones kept");
}

#[test]
fn when_only_part_of_the_newest_day_fits_its_top_lists_are_cut() {
    let mut p = with_user_bytes(BLOB_BUDGET - 1200);
    p.summaries = (0..7).map(|d| full_day(20_000 + d)).collect();
    let e = try_encode(&p, BLOB_BUDGET).unwrap();
    assert!(e.bytes.len() <= BLOB_BUDGET);
    assert_eq!(e.dropped_summaries, 6);
    assert!(e.trimmed_top_entries > 0);
    let (q, w) = decode(&e.bytes);
    assert_eq!(w, None);
    assert_eq!(q.rules, p.rules);
    assert_eq!(q.summaries.len(), 1);
    assert_eq!(q.summaries[0].day, 20_006);
    assert!(q.summaries[0].top_queried.len() < SUMMARY_TOP);
}

#[test]
fn owner_data_over_budget_is_refused_not_trimmed() {
    let p = with_user_bytes(BLOB_BUDGET + 100);
    match try_encode(&p, BLOB_BUDGET) {
        Err(EncodeError::OverBudget { needed }) => assert!(needed > BLOB_BUDGET),
        other => panic!("{other:?}"),
    }
    assert!(encode(&p).is_empty(), "the host helper gives an empty blob (decodes as Empty)");
}

#[test]
fn every_budget_is_respected_exactly() {
    let mut p = with_user_bytes(2000);
    p.summaries = (0..7).map(|d| full_day(20_000 + d)).collect();
    let fixed = try_encode(&Persisted { summaries: vec![], ..p.clone() }, usize::MAX).unwrap().bytes.len();
    for budget in (fixed..fixed + 11_000).step_by(37) {
        let e = try_encode(&p, budget).unwrap();
        assert!(e.bytes.len() <= budget, "budget {budget}: {}", e.bytes.len());
        assert_eq!(e.bytes.capacity(), e.bytes.len());
        assert_eq!(decode(&e.bytes).1, None, "budget {budget}");
    }
    assert!(matches!(try_encode(&p, fixed - 1), Err(EncodeError::OverBudget { .. })));
}

#[test]
fn rate_settings_have_upper_bounds() {
    let mut s = Settings::default();
    assert!(settings_valid(&s));
    s.rate_burst = MAX_RATE_BURST;
    s.rate_per_sec = MAX_RATE_PER_SEC;
    assert!(settings_valid(&s));
    s.rate_burst = MAX_RATE_BURST + 1;
    assert!(!settings_valid(&s));
    s.rate_burst = 50;
    s.rate_per_sec = 5000;
    assert!(!settings_valid(&s));
    let c = clamp_settings(&Settings { rate_burst: 5000, rate_per_sec: u32::MAX, ..Settings::default() });
    assert_eq!((c.rate_burst, c.rate_per_sec), (MAX_RATE_BURST, MAX_RATE_PER_SEC));
    assert!(settings_valid(&c));
}

#[test]
fn stored_rates_over_the_bound_are_clamped_on_save_and_load() {
    // Encode clamps.
    let mut p = sample();
    p.settings.rate_burst = 5000;
    p.settings.rate_per_sec = 5000;
    let (q, w) = decode(&encode(&p));
    assert_eq!(w, None);
    assert_eq!((q.settings.rate_burst, q.settings.rate_per_sec), (MAX_RATE_BURST, MAX_RATE_PER_SEC));
    // A v1 blob written before the bounds existed (rates 5000/s, e.g. a lifted debug rate)
    // still loads, with its rules, and the rates clamped.
    let mut b = encode(&sample());
    let at = b.windows(8).position(|w| w == [7, 0, 0, 0, 3, 0, 0, 0]).unwrap();
    b[at..at + 4].copy_from_slice(&5000u32.to_le_bytes());
    b[at + 4..at + 8].copy_from_slice(&5000u32.to_le_bytes());
    let n = b.len() - 4;
    let c = crc32(&b[..n]);
    b[n..].copy_from_slice(&c.to_le_bytes());
    let (q, w) = decode(&b);
    assert_eq!(w, None);
    assert_eq!(q.rules, sample().rules);
    assert_eq!((q.settings.rate_burst, q.settings.rate_per_sec), (MAX_RATE_BURST, MAX_RATE_PER_SEC));
    assert_eq!(b[4], 1, "format version unchanged");
}

// ---- local_name policy (Task 9) ----

use dnscore::store::{check_local_name, LocalNameError};

#[test]
fn local_name_must_be_under_a_private_suffix() {
    for ok in ["adblock.home", "nas.home", "a.b.home", "box.lan", "dns.internal", "adblock.home.arpa", "x-1.y.lan", "NAS.Home."] {
        assert!(check_local_name(ok).is_ok(), "{ok}");
    }
    assert_eq!(check_local_name("NAS.Home.").unwrap(), "nas.home");
    for (bad, e) in [
        ("google.com", LocalNameError::NotPrivate),
        ("adblock.local", LocalNameError::NotPrivate),
        ("home", LocalNameError::NotPrivate),
        ("lan", LocalNameError::NotPrivate),
        ("home.arpa", LocalNameError::NotPrivate),
        ("arpa", LocalNameError::NotPrivate),
        ("example.homes", LocalNameError::NotPrivate),
        ("a.b.c.home", LocalNameError::TooDeep),
        ("a.b.c.home.arpa", LocalNameError::TooDeep),
        ("", LocalNameError::Invalid),
        ("bad name.home", LocalNameError::Invalid),
        ("under_score.home", LocalNameError::Invalid),
        ("-dash.home", LocalNameError::Invalid),
        ("dash-.home", LocalNameError::Invalid),
        ("a..home", LocalNameError::Invalid),
        ("é.home", LocalNameError::Invalid),
    ] {
        assert_eq!(check_local_name(bad), Err(e), "{bad}");
        assert!(!e.message().is_empty());
    }
    let long = format!("{}.home", "a".repeat(64));
    assert_eq!(check_local_name(&long), Err(LocalNameError::Invalid));
}

#[test]
fn settings_validity_uses_the_local_name_policy() {
    let mut s = Settings::default();
    assert!(settings_valid(&s));
    s.local_name = "google.com".to_string();
    assert!(!settings_valid(&s));
    // clamping (what a save stores) falls back to the default name
    assert_eq!(clamp_settings(&s).local_name, "adblock.home");
}

#[test]
fn an_older_blob_with_a_public_local_name_still_loads() {
    // Saved by a build before the policy: everything else in it must survive.
    let mut p = sample();
    p.settings.local_name = "google.com".to_string();
    let bytes = encode_unclamped_name(&p);
    let (got, w) = decode(&bytes);
    assert_eq!(w, None);
    assert_eq!(got.rules, p.rules);
    assert_eq!(got.settings.local_name, "google.com");
    // the device then replaces it, with a warning for the UI
    let mut s = got.settings.clone();
    let warn = dnscore::persist::sanitize_local_name(&mut s).expect("a warning");
    assert_eq!(s.local_name, "adblock.home");
    assert!(warn.contains("google.com") && warn.contains("adblock.home"));
    let mut ok = Settings::default();
    assert_eq!(dnscore::persist::sanitize_local_name(&mut ok), None);
}

/// Encode `p` and then patch the stored local name back to `p`'s (the encoder now clamps it),
/// fixing the length and CRC: what an older firmware would have written.
fn encode_unclamped_name(p: &Persisted) -> Vec<u8> {
    let b = encode(p);
    let def = b"adblock.home";
    let name = p.settings.local_name.as_bytes();
    let at = b.windows(def.len() + 1).position(|w| w[0] as usize == def.len() && &w[1..] == def).expect("name");
    let mut out = b[..at].to_vec();
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.extend_from_slice(&b[at + 1 + def.len()..b.len() - 4]);
    let len = (out.len() - 9) as u32;
    out[5..9].copy_from_slice(&len.to_le_bytes());
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}
