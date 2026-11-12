use dnscore::stats::{Clients, HeavyHitters, LogEntry, QueryLog, Stats, StatsCaps};
use dnscore::ClientKey;
use std::collections::HashMap;
use std::net::Ipv4Addr;

fn ck(n: u8) -> ClientKey {
    ClientKey::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn entry(ts: u64, client: u8, name: &str, blocked: bool) -> LogEntry {
    LogEntry {
        ts,
        client: ck(client),
        name: name.to_string(),
        qtype: 1,
        blocked,
        reason: if blocked { "list".into() } else { "default".into() },
    }
}

#[test]
fn heavy_hitters_finds_the_true_top_3_in_a_skewed_stream() {
    let mut stream: Vec<String> = Vec::new();
    for r in 1..=400u32 {
        for _ in 0..(1600 / r) {
            stream.push(format!("n{r}.example"));
        }
    }
    // deterministic shuffle
    let mut s: u64 = 0x1234_5678_9abc_def0;
    for i in (1..stream.len()).rev() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = ((s >> 33) as usize) % (i + 1);
        stream.swap(i, j);
    }
    stream.truncate(10_000);
    let mut truth: HashMap<&str, u32> = HashMap::new();
    let mut hh = HeavyHitters::new(100);
    for n in &stream {
        *truth.entry(n.as_str()).or_default() += 1;
        hh.offer(n);
    }
    let mut true_sorted: Vec<(&str, u32)> = truth.iter().map(|(k, v)| (*k, *v)).collect();
    true_sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let top = hh.top(3);
    assert_eq!(top.len(), 3);
    let bound = (stream.len() / 100) as u32;
    for i in 0..3 {
        assert_eq!(top[i].0, true_sorted[i].0, "rank {i}");
        let t = true_sorted[i].1;
        assert!(top[i].1 >= t && top[i].1 - t <= bound, "count {} vs true {t}", top[i].1);
    }
}

#[test]
fn heavy_hitters_never_holds_more_than_k() {
    let mut hh = HeavyHitters::new(5);
    for i in 0..1000 {
        hh.offer(&format!("d{i}.test"));
    }
    assert_eq!(hh.top(100).len(), 5);
    let mut zero = HeavyHitters::new(0);
    zero.offer("a.test");
    assert!(zero.top(10).is_empty());
}

#[test]
fn heavy_hitters_ties_break_by_name_and_replacement_inherits_count() {
    let mut hh = HeavyHitters::new(2);
    hh.offer("b.test");
    hh.offer("a.test");
    assert_eq!(hh.top(2), vec![("a.test".to_string(), 1), ("b.test".to_string(), 1)]);
    hh.offer("c.test"); // replaces a minimum, inherits 1, +1
    assert!(hh.top(2).iter().any(|(n, c)| n == "c.test" && *c == 2));
}

#[test]
fn log_keeps_only_the_newest_cap_entries_in_order() {
    let mut log = QueryLog::new(3);
    for i in 0..5u64 {
        log.push(entry(i, 1, "x.test", false));
    }
    assert_eq!(log.len(), 3);
    let ts: Vec<u64> = log.recent(10).iter().map(|e| e.ts).collect();
    assert_eq!(ts, vec![4, 3, 2]); // newest first
    assert_eq!(log.recent(2).len(), 2);
    let mut none = QueryLog::new(0);
    none.push(entry(1, 1, "x.test", false));
    assert_eq!(none.len(), 0);
}

#[test]
fn clients_table_is_bounded_and_evicts_least_active() {
    let mut c = Clients::new(2);
    for _ in 0..5 {
        c.record(ck(1), false);
    }
    c.record(ck(2), true);
    c.record(ck(3), false); // full: evicts client 2 (least active)
    let rows = c.rows();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r.client == ck(1) && r.allowed == 5 && r.blocked == 0));
    assert!(rows.iter().any(|r| r.client == ck(3)));
    assert!(!rows.iter().any(|r| r.client == ck(2)));
}

#[test]
fn stats_separates_blocked_and_allowed_tops() {
    let mut st = Stats::new(StatsCaps::default());
    for i in 0..3 {
        st.record(entry(i, 1, "good.test", false));
    }
    st.record(entry(10, 2, "ads.test", true));
    st.record(entry(11, 2, "ads.test", true));
    assert_eq!(st.top_queried(5)[0], ("good.test".to_string(), 3));
    assert_eq!(st.top_blocked(5), vec![("ads.test".to_string(), 2)]);
    assert_eq!(st.totals(), (3, 2));
}

#[test]
fn roll_day_returns_the_summary_and_resets_counters() {
    let mut st = Stats::new(StatsCaps::default());
    assert!(st.roll_day(100).is_none());
    st.record(entry(1, 1, "good.test", false));
    st.record(entry(2, 1, "ads.test", true));
    assert!(st.roll_day(100).is_none());
    let s = st.roll_day(101).expect("summary");
    assert_eq!((s.day, s.allowed, s.blocked), (100, 1, 1));
    assert_eq!(s.top_blocked, vec![("ads.test".to_string(), 1)]);
    assert!(st.top_queried(5).is_empty());
    assert!(st.top_blocked(5).is_empty());
    let s2 = st.roll_day(102).expect("summary");
    assert_eq!((s2.day, s2.allowed, s2.blocked), (101, 0, 0));
}

#[test]
fn overlong_names_are_truncated_not_panicking() {
    let mut st = Stats::new(StatsCaps::default());
    let long = "é".repeat(400);
    st.record(entry(1, 1, &long, false));
    assert!(st.top_queried(1)[0].0.len() <= 253);
}

#[test]
fn heavy_hitters_with_k_one_keeps_a_single_counter() {
    let mut h = HeavyHitters::new(1);
    for n in ["a", "b", "a"] {
        h.offer(n);
    }
    assert_eq!(h.top(5), vec![("a".to_string(), 3)]);
}

#[test]
fn clients_tie_evicts_the_earliest_inserted_row() {
    let mut c = Clients::new(2);
    c.record(ck(1), false);
    c.record(ck(2), false);
    c.record(ck(3), false);
    let who: Vec<_> = c.rows().iter().map(|r| r.client).collect();
    assert_eq!(who, vec![ck(3), ck(2)]);
}

#[test]
#[ignore = "4 billion iterations: run with cargo test --release -- --ignored"]
fn client_counter_saturates_at_u32_max() {
    let mut c = Clients::new(1);
    for _ in 0..u64::from(u32::MAX) + 5 {
        c.record(ck(1), false);
    }
    assert_eq!(c.rows()[0].allowed, u32::MAX);
}

#[test]
fn log_reason_is_clipped_utf8_safe() {
    let mut l = QueryLog::new(4);
    let mut e = entry(1, 1, "a.test", true);
    e.reason = "é".repeat(400);
    l.push(e);
    let r = &l.recent(1)[0].reason;
    assert!(r.len() <= 253 && r.len() >= 252);
    assert!(r.chars().all(|c| c == 'é'));
}

#[test]
fn roll_day_ignores_a_day_going_backwards() {
    let mut st = Stats::new(StatsCaps::default());
    assert!(st.roll_day(100).is_none());
    st.record(entry(1, 1, "good.test", false));
    assert!(st.roll_day(99).is_none());
    assert_eq!(st.top_queried(5), vec![("good.test".to_string(), 1)]);
    let s = st.roll_day(101).expect("summary for day 100");
    assert_eq!((s.day, s.allowed), (100, 1));
}

// ---- streaming accessors (Task 9: replies are built one entry at a time) ----

fn e9(name: &str, blocked: bool) -> LogEntry {
    LogEntry {
        ts: 1,
        client: ClientKey::V4(std::net::Ipv4Addr::new(192, 0, 2, 9)),
        name: name.to_string(),
        qtype: 1,
        blocked,
        reason: "default".to_string(),
    }
}

#[test]
fn log_entries_are_addressable_by_sequence_number() {
    let mut log = QueryLog::new(3);
    assert_eq!(log.end_seq(), 0);
    assert!(log.by_seq(0).is_none());
    for i in 0..5 {
        log.push(e9(&format!("n{i}.example"), false));
    }
    // 5 pushed, the newest 3 kept: seq 2, 3, 4
    assert_eq!(log.end_seq(), 5);
    assert!(log.by_seq(1).is_none());
    assert_eq!(log.by_seq(2).unwrap().name, "n2.example");
    assert_eq!(log.by_seq(4).unwrap().name, "n4.example");
    assert!(log.by_seq(5).is_none());
    assert!(log.by_seq(u64::MAX).is_none());
    // a reader walking newest-first by seq sees no duplicates when entries arrive meanwhile
    let mut seq = log.end_seq();
    let mut seen = Vec::new();
    while seq > 0 {
        seq -= 1;
        let Some(e) = log.by_seq(seq) else { break };
        seen.push(e.name.clone());
        log.push(e9("new.example", false));
    }
    assert_eq!(seen, ["n4.example", "n3.example"]);
}

#[test]
fn top_order_and_slots_match_top() {
    let mut s = Stats::new(StatsCaps { log_cap: 8, top_k: 4, clients_max: 4 });
    for (name, n) in [("a.example", 3), ("b.example", 5), ("c.example", 1)] {
        for _ in 0..n {
            s.record(e9(name, false));
        }
    }
    s.record(e9("x.example", true));
    let order = s.top_order(false);
    let via_slots: Vec<(String, u32)> = order
        .iter()
        .map(|&i| {
            let (n, c) = s.top_slot(false, i).unwrap();
            (n.to_string(), c)
        })
        .collect();
    assert_eq!(via_slots, s.top_queried(10));
    assert_eq!(s.top_order(true).len(), 1);
    assert_eq!(s.top_slot(true, s.top_order(true)[0]).unwrap().0, "x.example");
    assert!(s.top_slot(false, 99).is_none());
}

#[test]
fn client_rows_are_addressable() {
    let mut s = Stats::new(StatsCaps { log_cap: 8, top_k: 4, clients_max: 4 });
    s.record(e9("a.example", false));
    assert_eq!(s.clients().len(), 1);
    assert_eq!(s.clients().row(0).unwrap().allowed, 1);
    assert!(s.clients().row(1).is_none());
}
