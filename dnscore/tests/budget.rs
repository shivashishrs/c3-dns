use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscore::budget::{ban_cost, check, record_cost, rule_cost, usage, BudgetError, Cost, Usage};
use dnscore::{BlockList, ClientKey, Engine, LocalRecords, RuleKind, Rules};

fn engine() -> Engine<Vec<u8>> {
    Engine::new(Rules::new(500), LocalRecords::new(100), BlockList::new(Vec::new()))
}

#[test]
fn costs_grow_with_size_and_count_the_encoded_form() {
    let a = rule_cost("a.example");
    let b = rule_cost(&format!("{}.example", "a".repeat(60)));
    // encoded: kind byte + length byte + text (store.rs format)
    assert_eq!(a.encoded, 2 + "a.example".len());
    assert!(b.ram > a.ram && b.encoded > a.encoded);
    // RAM is never estimated below the encoded size
    assert!(a.ram > a.encoded && b.ram > b.encoded);
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let r1 = record_cost("nas.home", &[v4]);
    let r2 = record_cost("nas.home", &[v4, v6]);
    // name (len byte + text) + count byte + (tag + 4) + (tag + 16)
    assert_eq!(r1.encoded, 1 + 8 + 1 + 5);
    assert_eq!(r2.encoded, 1 + 8 + 1 + 5 + 17);
    assert!(r2.ram > r1.ram);
    assert_eq!(ban_cost(ClientKey::V4(Ipv4Addr::new(10, 0, 0, 1))).encoded, 5);
    assert_eq!(ban_cost(ClientKey::V6(Ipv6Addr::LOCALHOST)).encoded, 17);
}

#[test]
fn usage_sums_rules_records_and_bans() {
    let mut e = engine();
    assert_eq!(usage(&e), Usage::default());
    e.rules_mut().add(RuleKind::Block, "||ads.example^").unwrap();
    e.rules_mut().add(RuleKind::Allow, "ok.example").unwrap();
    let ips = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))];
    e.records_mut().set("nas.home", ips.clone()).unwrap();
    e.ban(ClientKey::V4(Ipv4Addr::new(10, 0, 0, 3)));
    let u = usage(&e);
    assert_eq!((u.rules, u.records, u.bans, u.entries()), (2, 1, 1, 4));
    let want = [
        rule_cost("||ads.example^"),
        rule_cost("ok.example"),
        record_cost("nas.home", &ips),
        ban_cost(ClientKey::V4(Ipv4Addr::new(10, 0, 0, 3))),
    ];
    assert_eq!(u.encoded, want.iter().map(|c| c.encoded).sum::<usize>());
    assert_eq!(u.ram, want.iter().map(|c| c.ram).sum::<usize>());
}

#[test]
fn check_refuses_what_does_not_fit() {
    let u = Usage { ram: 900, ..Usage::default() };
    assert_eq!(check(&u, Cost { encoded: 10, ram: 100 }, 1000), Ok(()));
    let e = check(&u, Cost { encoded: 10, ram: 101 }, 1000).unwrap_err();
    assert_eq!(e, BudgetError { used: 900, budget: 1000, need: 101 });
    let m = e.message();
    assert!(m.contains("0.9 KB") && m.contains("1.0 KB"), "{m}");
    // the budget is never exceeded by filling it rule by rule
    let mut e = engine();
    let budget = 4096;
    let mut added = 0;
    for i in 0..10_000 {
        let p = format!("rule{i}.example");
        if check(&usage(&e), rule_cost(&p), budget).is_err() {
            break;
        }
        e.rules_mut().add(RuleKind::Block, &p).unwrap();
        added += 1;
    }
    assert!(added > 0 && usage(&e).ram <= budget);
}

// ---- hardening 2: over-budget data at boot, duplicates before the budget ----

use dnscore::budget::{add_rule, over_budget_warning, set_record, AddError};

#[test]
fn over_budget_warning_only_when_the_loaded_data_exceeds_the_budget() {
    let at = Usage { ram: 1024, ..Usage::default() };
    assert_eq!(over_budget_warning(&at, 1024), None, "exactly full is fine");
    assert_eq!(over_budget_warning(&Usage::default(), 1024), None);
    let over = Usage { ram: 12 * 1024 + 300, ..Usage::default() };
    let w = over_budget_warning(&over, 10 * 1024).unwrap();
    assert!(w.contains("12.3 KB") && w.contains("10.0 KB") && w.contains("remove entries"), "{w}");
}

#[test]
fn data_loaded_past_the_budget_keeps_working_but_refuses_additions() {
    // What a boot with a big stored blob looks like: the engine holds more than the budget.
    let mut e = engine();
    for i in 0..60 {
        e.rules_mut().add(RuleKind::Block, &format!("loaded{i}.example")).unwrap();
    }
    let budget = usage(&e).ram / 2;
    assert!(over_budget_warning(&usage(&e), budget).is_some());
    assert!(e.rules().contains(RuleKind::Block, "loaded59.example"), "loaded rules stay active");
    assert!(matches!(add_rule(&mut e, RuleKind::Block, "new.example", budget), Err(AddError::Budget(_))));
    // removing is always possible
    assert!(e.rules_mut().remove(RuleKind::Block, "loaded0.example"));
}

#[test]
fn a_duplicate_rule_is_exists_even_when_the_budget_is_full() {
    let mut e = engine();
    add_rule(&mut e, RuleKind::Block, "||ads.example^", 4096).unwrap();
    let full = usage(&e).ram; // the budget is now exactly used up
    assert!(matches!(add_rule(&mut e, RuleKind::Block, "||ads.example^", full), Err(AddError::Exists)));
    assert!(matches!(add_rule(&mut e, RuleKind::Block, "other.example", full), Err(AddError::Budget(_))));
    // the same pattern on the other side is a different rule
    assert!(matches!(add_rule(&mut e, RuleKind::Allow, "||ads.example^", full), Err(AddError::Budget(_))));
    assert!(matches!(add_rule(&mut e, RuleKind::Block, "bad name", 4096), Err(AddError::Rule(_))));
}

#[test]
fn an_identical_record_is_exists_and_a_replacement_only_pays_the_difference() {
    let mut e = engine();
    let a = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5))];
    let b = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 6))];
    set_record(&mut e, "nas.home", a.clone(), 4096).unwrap();
    let full = usage(&e).ram;
    assert!(matches!(set_record(&mut e, "nas.home", a.clone(), full), Err(AddError::Exists)));
    // same size, different address: fits a full budget (the old one is freed)
    set_record(&mut e, "nas.home", b.clone(), full).unwrap();
    assert_eq!(e.records().get("nas.home"), Some(b.as_slice()));
    assert!(matches!(set_record(&mut e, "tv.home", a, full), Err(AddError::Budget(_))));
}
