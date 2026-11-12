use dnscore::persist::{
    check_record, check_rule, day_of, load_into, plausible, push_summary, snapshot, utc_string, Dirty, SaveDecision,
    SaveGate, PLAUSIBLE_MAX_UNIX, PLAUSIBLE_MIN_UNIX,
};
use dnscore::stats::DailySummary;
use dnscore::store::{decode, encode, Persisted, Settings, MAX_RECORD_IPS, MAX_STR};
use dnscore::{BlockList, ClientKey, Engine, LocalRecords, RuleError, RuleKind, Rules};
use std::net::{IpAddr, Ipv4Addr};

const T: u64 = 1_800_000_000; // 2027-01-15, plausible

fn engine(rules_cap: usize, records_cap: usize) -> Engine<Vec<u8>> {
    Engine::new(Rules::new(rules_cap), LocalRecords::new(records_cap), BlockList::new(Vec::new()))
}

fn ip(d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
}

#[test]
fn plausible_time_bounds() {
    assert_eq!(PLAUSIBLE_MIN_UNIX, 1_767_225_600);
    assert!(!plausible(0));
    assert!(!plausible(PLAUSIBLE_MIN_UNIX - 1));
    assert!(plausible(PLAUSIBLE_MIN_UNIX));
    assert!(plausible(T));
    assert!(!plausible(PLAUSIBLE_MAX_UNIX));
    assert!(!plausible(u64::MAX));
}

#[test]
fn utc_string_known_values() {
    assert_eq!(utc_string(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc_string(PLAUSIBLE_MIN_UNIX), "2026-01-01T00:00:00Z");
    assert_eq!(utc_string(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc_string(1_793_101_234), "2026-10-27T11:40:34Z");
    assert_eq!(utc_string(4_102_444_799), "2099-12-31T23:59:59Z");
}

#[test]
fn day_of_is_unix_days() {
    assert_eq!(day_of(0), 0);
    assert_eq!(day_of(86_399), 0);
    assert_eq!(day_of(86_400), 1);
    assert_eq!(day_of(PLAUSIBLE_MIN_UNIX), 20454);
}

#[test]
fn gate_refuses_without_plausible_time_even_when_forced() {
    let mut g = SaveGate::new(600, 144);
    assert_eq!(g.decide(true, None, false), SaveDecision::NoTime);
    assert_eq!(g.decide(true, None, true), SaveDecision::NoTime);
    assert_eq!(g.decide(true, Some(5), true), SaveDecision::NoTime);
    assert_eq!(g.decide(true, Some(u64::MAX / 2), false), SaveDecision::NoTime);
    // The bogus readings above did not touch the Saver: a real time still saves at once.
    assert_eq!(g.decide(true, Some(T), false), SaveDecision::Save);
}

#[test]
fn gate_read_only_refuses_everything() {
    let mut g = SaveGate::new(600, 144);
    g.set_read_only(true);
    assert!(g.read_only());
    assert_eq!(g.decide(true, Some(T), false), SaveDecision::ReadOnly);
    assert_eq!(g.decide(true, Some(T), true), SaveDecision::ReadOnly);
    assert_eq!(g.decide(false, Some(T), true), SaveDecision::ReadOnly);
}

#[test]
fn gate_respects_interval_and_clean_state_but_force_bypasses_interval() {
    let mut g = SaveGate::new(600, 144);
    assert_eq!(g.decide(false, Some(T), false), SaveDecision::Clean);
    assert_eq!(g.decide(true, Some(T), false), SaveDecision::Save);
    assert_eq!(g.decide(true, Some(T + 60), false), SaveDecision::NotDue);
    assert_eq!(g.decide(true, Some(T + 120), true), SaveDecision::Save);
    assert_eq!(g.decide(false, Some(T + 130), true), SaveDecision::Save);
    assert_eq!(g.decide(true, Some(T + 600), false), SaveDecision::Save);
}

#[test]
fn at_most_three_saves_in_thirty_minutes_of_constant_changes() {
    let mut g = SaveGate::new(600, 144);
    let saves = (0..30).filter(|m| g.decide(true, Some(T + m * 60), false) == SaveDecision::Save).count();
    assert_eq!(saves, 3);
}

#[test]
fn dirty_tracking_survives_a_change_during_the_write() {
    let mut d = Dirty::default();
    assert!(!d.is_dirty());
    d.mark();
    let gen = d.generation();
    d.mark(); // a change lands while the snapshot is being written
    d.saved(gen);
    assert!(d.is_dirty());
    let gen = d.generation();
    d.saved(gen);
    assert!(!d.is_dirty());
    // An old generation reported late never marks a newer state clean.
    d.mark();
    d.saved(gen);
    assert!(d.is_dirty());
}

fn summary(day: u32, allowed: u32, top: &[(&str, u32)]) -> DailySummary {
    DailySummary {
        day,
        allowed,
        blocked: 1,
        top_queried: top.iter().map(|(n, c)| (n.to_string(), *c)).collect(),
        top_blocked: vec![],
    }
}

#[test]
fn push_summary_keeps_seven_newest_sorted() {
    let mut v = Vec::new();
    for d in [5, 1, 2, 3, 4, 6, 7, 8, 9] {
        push_summary(&mut v, summary(d, 1, &[]));
    }
    assert_eq!(v.iter().map(|s| s.day).collect::<Vec<_>>(), vec![3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn push_summary_merges_the_same_day() {
    // A reboot mid-day: the day is summarised twice; the counts add up and tops merge.
    let mut v = vec![summary(10, 5, &[("a.com", 3), ("b.com", 1)])];
    push_summary(&mut v, summary(10, 2, &[("b.com", 4), ("c.com", 1)]));
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].allowed, 7);
    assert_eq!(v[0].blocked, 2);
    assert_eq!(
        v[0].top_queried,
        vec![("b.com".to_string(), 5), ("a.com".to_string(), 3), ("c.com".to_string(), 1)]
    );
}

#[test]
fn push_summary_merge_keeps_tops_bounded() {
    let names: Vec<String> = (0..30).map(|i| format!("n{i}.com")).collect();
    let a: Vec<(&str, u32)> = names[..15].iter().map(|n| (n.as_str(), 2)).collect();
    let b: Vec<(&str, u32)> = names[15..].iter().map(|n| (n.as_str(), 1)).collect();
    let mut v = vec![summary(3, 1, &a)];
    push_summary(&mut v, summary(3, 1, &b));
    assert_eq!(v[0].top_queried.len(), dnscore::stats::SUMMARY_TOP);
    assert!(v[0].top_queried.iter().all(|(_, c)| *c == 2));
}

#[test]
fn check_rule_accepts_valid_and_returns_canonical() {
    assert_eq!(check_rule(RuleKind::Block, " Ads.Example.com. "), Ok("ads.example.com".to_string()));
    assert_eq!(check_rule(RuleKind::Allow, "||Example.org^"), Ok("||example.org^".to_string()));
    assert_eq!(check_rule(RuleKind::Block, "*.tracker.net"), Ok("*.tracker.net".to_string()));
}

#[test]
fn check_rule_rejects_what_encode_would_drop() {
    assert_eq!(check_rule(RuleKind::Block, ""), Err(RuleError::Empty));
    assert_eq!(check_rule(RuleKind::Block, "bad name"), Err(RuleError::Invalid));
    // A 252-byte name is a valid exact rule, but as a subtree rule `||name^` is 255 bytes,
    // longer than the store keeps: rejected up front instead of silently dropped on save.
    let long = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(60));
    assert_eq!(long.len(), 252);
    assert!(check_rule(RuleKind::Block, &long).is_ok());
    assert_eq!(check_rule(RuleKind::Block, &format!("||{long}^")), Err(RuleError::Invalid));
    assert!(MAX_STR < long.len() + 3);
}

#[test]
fn check_record_validates_name_and_ips() {
    assert_eq!(check_record("NAS.home.", &[ip(2)]), Ok("nas.home".to_string()));
    assert_eq!(check_record("nas.home", &[]), Err(RuleError::Empty));
    assert_eq!(check_record("bad name", &[ip(2)]), Err(RuleError::Invalid));
    let many = vec![ip(3); MAX_RECORD_IPS + 1];
    assert_eq!(check_record("nas.home", &many), Err(RuleError::TooMany));
    assert!(check_record("nas.home", &many[..MAX_RECORD_IPS]).is_ok());
}

fn persisted() -> Persisted {
    Persisted {
        rules: vec![
            (RuleKind::Block, "ads.example.com".to_string()),
            (RuleKind::Allow, "||ok.example.org^".to_string()),
            (RuleKind::Block, "*.tracker.net".to_string()),
        ],
        records: vec![("nas.home".to_string(), vec![ip(20)]), ("pc.home".to_string(), vec![ip(21)])],
        bans: vec![ClientKey::V4(Ipv4Addr::new(192, 0, 2, 99))],
        settings: Settings { rate_burst: 9, ..Settings::default() },
        summaries: vec![summary(20000, 3, &[("a.com", 3)])],
    }
}

#[test]
fn load_then_snapshot_round_trips_through_encode() {
    let p = persisted();
    let mut e = engine(500, 100);
    assert_eq!(load_into(&p, &mut e), 0);
    let s = snapshot(&e, &p.settings, &p.summaries);
    let (back, w) = decode(&encode(&s));
    assert_eq!(w, None);
    assert_eq!(back.rules, p.rules);
    assert_eq!(back.records, p.records);
    assert_eq!(back.bans, p.bans);
    assert_eq!(back.settings, p.settings);
    assert_eq!(back.summaries, p.summaries);
}

#[test]
fn load_drops_items_over_the_current_caps_without_panicking() {
    let p = persisted();
    let mut e = engine(2, 1);
    // One rule and one record over the caps.
    assert_eq!(load_into(&p, &mut e), 2);
    assert_eq!(e.rules().len(), 2);
    assert_eq!(e.records().list().len(), 1);
    assert_eq!(e.banned().len(), 1);
}

#[test]
fn load_drops_duplicate_and_invalid_items() {
    let mut p = persisted();
    p.rules.push((RuleKind::Block, "ADS.example.com".to_string()));
    p.rules.push((RuleKind::Block, "bad name".to_string()));
    p.records.push(("x.home".to_string(), vec![]));
    p.bans.push(p.bans[0]);
    let mut e = engine(500, 100);
    assert_eq!(load_into(&p, &mut e), 4);
    assert_eq!(e.rules().len(), 3);
}

// ---- summary clipping and encoding from the live state ----

use dnscore::persist::Live;
use dnscore::stats::{clip_summary_name, Stats, StatsCaps, CLIP_MARK, SUMMARY_NAME_MAX, SUMMARY_TOP};
use dnscore::store::{try_encode, BLOB_BUDGET};

fn name_253(i: usize) -> String {
    format!("{i:03}{}.{}.{}.{}", "a".repeat(60), "b".repeat(63), "c".repeat(63), "d".repeat(61))
}

#[test]
fn clip_summary_name_is_bounded_utf8_safe_and_idempotent() {
    assert_eq!(clip_summary_name("short.example"), "short.example");
    let exact = "x".repeat(SUMMARY_NAME_MAX);
    assert_eq!(clip_summary_name(&exact), exact);
    let c = clip_summary_name(&name_253(1));
    assert!(c.len() <= SUMMARY_NAME_MAX && c.ends_with(CLIP_MARK) && c.starts_with("001aaa"));
    assert_eq!(clip_summary_name(&c), c);
    let multi = "é".repeat(100);
    let m = clip_summary_name(&multi);
    assert!(m.len() <= SUMMARY_NAME_MAX && m.ends_with(CLIP_MARK));
}

#[test]
fn push_summary_clips_names_and_merges_collisions() {
    let mut v = Vec::new();
    // Two names that differ only after the clip point collapse into one entry.
    let a = format!("{}a.example", "z".repeat(70));
    let b = format!("{}b.example", "z".repeat(70));
    let tops: Vec<(String, u32)> = (0..SUMMARY_TOP).map(|i| (name_253(i), 5)).chain([(a, 7), (b, 6)]).collect();
    push_summary(&mut v, DailySummary { day: 1, allowed: 1, blocked: 0, top_queried: tops, top_blocked: vec![] });
    let t = &v[0].top_queried;
    assert_eq!(t.len(), SUMMARY_TOP);
    assert!(t.iter().all(|(n, _)| n.len() <= SUMMARY_NAME_MAX));
    assert_eq!(t[0].1, 13, "the two colliding names were merged");
}

#[test]
fn roll_day_summaries_have_clipped_names() {
    let mut s = Stats::new(StatsCaps::default());
    s.roll_day(10);
    for i in 0..30 {
        s.record(dnscore::stats::LogEntry {
            ts: 0,
            client: ClientKey::V4(Ipv4Addr::LOCALHOST),
            name: name_253(i),
            qtype: 1,
            blocked: i % 2 == 0,
            reason: String::new(),
        });
    }
    let d = s.roll_day(11).unwrap();
    assert!(!d.top_queried.is_empty() && !d.top_blocked.is_empty());
    assert!(d.top_queried.iter().chain(&d.top_blocked).all(|(n, _)| n.len() <= SUMMARY_NAME_MAX));
}

#[test]
fn encoding_the_live_state_matches_encoding_its_snapshot() {
    let p = persisted();
    let mut e = engine(500, 100);
    assert_eq!(load_into(&p, &mut e), 0);
    let mut sums = Vec::new();
    for d in 0..7 {
        push_summary(&mut sums, summary(20_000 + d, 3, &[("a.com", 3), (&name_253(d as usize), 2)]));
    }
    let live = Live { engine: &e, settings: &p.settings, summaries: &sums };
    let from_live = try_encode(&live, BLOB_BUDGET).unwrap().bytes;
    let snap = snapshot(&e, &p.settings, &sums);
    let (back, w) = decode(&from_live);
    assert_eq!(w, None);
    // Same content (records may come out in another order from the live map).
    let (mut a, mut b) = (back.clone(), snap.clone());
    a.records.sort();
    b.records.sort();
    assert_eq!(a, b);
    assert_eq!(from_live.len(), encode(&snap).len());
}

#[test]
fn clipped_summary_names_hold_no_spare_capacity() {
    let mut v = Vec::new();
    let tops: Vec<(String, u32)> = (0..SUMMARY_TOP).map(|i| (name_253(i), 5)).collect();
    push_summary(&mut v, DailySummary { day: 1, allowed: 1, blocked: 0, top_queried: tops.clone(), top_blocked: tops });
    for (n, _) in v[0].top_queried.iter().chain(&v[0].top_blocked) {
        assert_eq!(n.capacity(), n.len());
    }
    assert_eq!(v[0].top_queried.capacity(), v[0].top_queried.len());
}
