use dnscore::blocklist::{hash40, BlockList};
use dnscore::engine::{Action, ClientKey, Engine, LocalRecords, Reason};
use dnscore::rules::{RuleKind, Rules};
use std::net::{IpAddr, Ipv4Addr};

const C: ClientKey = ClientKey::V4(Ipv4Addr::new(192, 0, 2, 50));
const OTHER: ClientKey = ClientKey::V4(Ipv4Addr::new(192, 0, 2, 51));

fn list(names: &[&str]) -> BlockList<Vec<u8>> {
    let mut h: Vec<u64> = names.iter().map(|n| hash40(n)).collect();
    h.sort_unstable();
    BlockList::new(h.iter().flat_map(|x| x.to_le_bytes()[..5].to_vec()).collect::<Vec<u8>>())
}

fn engine(block: &[&str], allow: &[&str], list_names: &[&str]) -> Engine<Vec<u8>> {
    let mut r = Rules::new(500);
    for b in block {
        r.add(RuleKind::Block, b).unwrap();
    }
    for a in allow {
        r.add(RuleKind::Allow, a).unwrap();
    }
    Engine::new(r, LocalRecords::new(16), list(list_names))
}

fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

#[test]
fn decision_order_is_banned_paused_allow_local_block_default() {
    let mut r = Rules::new(500);
    r.add(RuleKind::Block, "||ads.test^").unwrap();
    r.add(RuleKind::Allow, "ok.ads.test").unwrap();
    r.add(RuleKind::Block, "nas.test").unwrap();
    r.add(RuleKind::Allow, "both.test").unwrap();
    let mut rec = LocalRecords::new(16);
    rec.set("nas.test", vec![ip(5)]).unwrap();
    rec.set("both.test", vec![ip(6)]).unwrap();
    let mut e = Engine::new(r, rec, list(&[]));

    // default
    let d = e.decide("plain.test", C, 0);
    assert_eq!((d.action, d.reason), (Action::Resolve, Reason::Default));
    // block
    let d = e.decide("x.ads.test", C, 0);
    assert_eq!((d.action, d.reason), (Action::Block, Reason::CustomBlock("||ads.test^".into())));
    // allow beats block
    let d = e.decide("ok.ads.test", C, 0);
    assert_eq!((d.action, d.reason), (Action::Resolve, Reason::CustomAllow("ok.ads.test".into())));
    // allow beats local
    let d = e.decide("both.test", C, 0);
    assert_eq!(d.action, Action::Resolve);
    // local beats block
    let d = e.decide("nas.test", C, 0);
    assert_eq!((d.action, d.reason), (Action::Local, Reason::LocalRecord("nas.test".into())));
    // paused beats allow/local/block
    e.pause(60, 0);
    let d = e.decide("x.ads.test", C, 1);
    assert_eq!((d.action, d.reason), (Action::Resolve, Reason::Paused));
    // banned beats paused
    assert!(e.ban(C));
    let d = e.decide("x.ads.test", C, 1);
    assert_eq!((d.action, d.reason), (Action::Drop, Reason::Banned));
    let d = e.decide("x.ads.test", OTHER, 1);
    assert_eq!(d.reason, Reason::Paused);
}

#[test]
fn pause_expires_by_itself() {
    let mut e = engine(&["ads.test"], &[], &[]);
    e.pause(300, 1_000);
    assert_eq!(e.decide("ads.test", C, 2_000).action, Action::Resolve);
    assert_eq!(e.paused_for(2_000), 299);
    assert_eq!(e.decide("ads.test", C, 300_999).action, Action::Resolve);
    assert_eq!(e.decide("ads.test", C, 301_000).action, Action::Block);
    assert_eq!(e.paused_for(301_000), 0);
    e.pause(10, 0);
    e.resume();
    assert_eq!(e.decide("ads.test", C, 1).action, Action::Block);
    assert_eq!(e.paused_for(1), 0);
}

#[test]
fn explain_ignores_pause_and_ban() {
    let mut e = engine(&["ads.test"], &[], &[]);
    e.pause(300, 0);
    e.ban(C);
    let d = e.explain("ads.test");
    assert_eq!((d.action, d.reason), (Action::Block, Reason::CustomBlock("ads.test".into())));
    assert_eq!(e.banned(), vec![C]);
    assert!(e.unban(C));
    assert!(!e.unban(C));
    assert!(e.banned().is_empty());
}

#[test]
fn uncloak_blocks_when_a_chain_member_is_blocked() {
    let e = engine(&["||tracker.test^"], &[], &[]);
    let chain = vec!["www.site.test".to_string(), "x.tracker.test".to_string()];
    let d = e.uncloak(&chain).unwrap();
    assert_eq!(d.action, Action::Block);
    assert_eq!(
        d.reason,
        Reason::Cname { via: "x.tracker.test".into(), rule: "||tracker.test^".into() }
    );
    assert!(e.uncloak(&["a.test".to_string(), "b.test".to_string()]).is_none());
    assert!(e.uncloak(&[]).is_none());
}

#[test]
fn uncloak_does_not_block_when_any_member_is_allowed() {
    let e = engine(&["||tracker.test^"], &["www.site.test"], &[]);
    let chain = vec!["www.site.test".to_string(), "x.tracker.test".to_string()];
    assert!(e.uncloak(&chain).is_none());
}

#[test]
fn local_record_answers_before_block() {
    let mut r = Rules::new(10);
    r.add(RuleKind::Block, "||home.test^").unwrap();
    let mut rec = LocalRecords::new(4);
    rec.set("Printer.home.test.", vec![ip(9)]).unwrap();
    let e = Engine::new(r, rec, list(&["home.test"]));
    let d = e.decide("printer.home.test", C, 0);
    assert_eq!(d.action, Action::Local);
}

#[test]
fn list_blocks_when_no_rule_matches() {
    let e = engine(&[], &[], &["tracker.test"]);
    let d = e.decide("a.tracker.test", C, 0);
    assert_eq!(d.reason.to_string(), "list: tracker.test");
    assert_eq!((d.action, d.reason), (Action::Block, Reason::List("tracker.test".into())));
    assert_eq!(e.decide("fine.test", C, 0).action, Action::Resolve);
}

#[test]
fn custom_allow_beats_the_list() {
    let e = engine(&[], &["a.tracker.test"], &["tracker.test"]);
    assert_eq!(e.decide("a.tracker.test", C, 0).action, Action::Resolve);
    assert_eq!(e.decide("b.tracker.test", C, 0).action, Action::Block);
}

#[test]
fn uncloak_blocks_on_a_list_hit() {
    let e = engine(&[], &[], &["tracker.test"]);
    let d = e.uncloak(&["www.site.test".to_string(), "x.tracker.test".to_string()]).unwrap();
    assert_eq!(d.action, Action::Block);
    assert_eq!(
        d.reason,
        Reason::Cname { via: "x.tracker.test".into(), rule: "tracker.test".into() }
    );
}

#[test]
fn uncloak_allow_on_final_target_beats_block_on_earlier_member() {
    let e = engine(&["tracker.example"], &["final.cdn.net"], &[]);
    let chain = vec!["tracker.example".to_string(), "final.cdn.net".to_string()];
    assert_eq!(e.uncloak(&chain), None);
    // without the allow it is blocked
    let e = engine(&["tracker.example"], &[], &[]);
    assert!(e.uncloak(&chain).is_some());
}

#[test]
fn allow_variants_beat_block_variants() {
    // wildcard allow vs exact block
    let e = engine(&["x.example.com"], &["*.example.com"], &[]);
    let d = e.explain("x.example.com");
    assert_eq!((d.action, d.reason), (Action::Resolve, Reason::CustomAllow("*.example.com".into())));
    // wildcard allow vs subtree block
    let e = engine(&["||example.com^"], &["*.example.com"], &[]);
    assert_eq!(e.explain("x.example.com").action, Action::Resolve);
    // exact allow vs glob block
    let e = engine(&["*.example.com"], &["x.example.com"], &[]);
    assert_eq!(e.explain("x.example.com").action, Action::Resolve);
    assert_eq!(e.explain("y.example.com").action, Action::Block);
}

#[test]
fn pause_edges_do_not_panic() {
    let mut e = engine(&[], &[], &[]);
    e.pause(0, 1000);
    assert_eq!(e.paused_for(1000), 0);
    assert_eq!(e.decide("a.test", C, 1000).reason, Reason::Default);
    e.pause(u32::MAX, u64::MAX - 1);
    assert_eq!(e.paused_for(0), u32::MAX);
    assert_eq!(e.paused_for(u64::MAX - 1), 1);
    assert_eq!(e.paused_for(u64::MAX), 0);
    assert_eq!(e.decide("a.test", C, u64::MAX - 1).reason, Reason::Paused);
    e.resume();
    assert_eq!(e.paused_for(0), 0);
}

// ---- Task 6: client keys ----

#[test]
fn client_key_is_v4_address_or_full_v6_address() {
    use std::net::Ipv6Addr;
    let v4: IpAddr = "192.0.2.7".parse().unwrap();
    assert_eq!(ClientKey::from_ip(v4), ClientKey::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
    assert_eq!(ClientKey::from_ip(mapped), ClientKey::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let a: Ipv6Addr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
    let b: Ipv6Addr = "2001:db8:1:2::1".parse().unwrap();
    assert_eq!(ClientKey::from_ip(IpAddr::V6(a)), ClientKey::V6(a));
    // Every on-link client shares the router's /64: same /64 must still mean different keys.
    assert_ne!(ClientKey::from_ip(IpAddr::V6(a)), ClientKey::from_ip(IpAddr::V6(b)));
}

#[test]
fn banning_one_v6_client_does_not_ban_its_slash_64_neighbour() {
    let a = ClientKey::from_ip("2001:db8:1:2::a".parse().unwrap());
    let b = ClientKey::from_ip("2001:db8:1:2::b".parse().unwrap());
    let mut e = engine(&[], &[], &[]);
    assert!(e.ban(a));
    assert_eq!(e.decide("example.com", a, 0).action, Action::Drop);
    assert_eq!(e.decide("example.com", b, 0).action, Action::Resolve);
}

// --- Task 8: the device's own name (`adblock.home`) ---

#[test]
fn own_name_answers_locally_even_when_paused_blocked_or_allowed() {
    let mut e = engine(&["adblock.home", "||home^"], &[], &["adblock.home"]);
    e.set_own("adblock.home", vec![ip(3)]).unwrap();
    assert_eq!(e.decide("adblock.home", C, 0).action, Action::Local);
    assert_eq!(e.decide("ADBLOCK.home.", C, 0).action, Action::Local);
    assert_eq!(e.explain("adblock.home").reason, Reason::LocalRecord("adblock.home".into()));
    e.pause(60, 0);
    assert_eq!(e.decide("adblock.home", C, 1).action, Action::Local);
    assert_eq!(e.local_ips("adblock.home"), Some(&[ip(3)][..]));
    // an allow rule would forward the name upstream (NXDOMAIN): the own name still wins
    let mut a = engine(&[], &["||home^"], &[]);
    a.set_own("adblock.home", vec![ip(3)]).unwrap();
    assert_eq!(a.decide("adblock.home", C, 0).action, Action::Local);
    // a sibling is untouched
    assert_eq!(a.decide("other.home", C, 0).action, Action::Resolve);
}

#[test]
fn own_name_is_not_answered_to_a_banned_client() {
    let mut e = engine(&[], &[], &[]);
    e.set_own("adblock.home", vec![ip(3)]).unwrap();
    e.ban(C);
    assert_eq!(e.decide("adblock.home", C, 0).action, Action::Drop);
    assert_eq!(e.decide("adblock.home", OTHER, 0).action, Action::Local);
}

#[test]
fn own_name_is_separate_from_owner_records_and_replaceable() {
    let mut e = engine(&[], &[], &[]);
    e.records_mut().set("nas.test", vec![ip(5)]).unwrap();
    e.set_own("adblock.home", vec![ip(3)]).unwrap();
    assert_eq!(e.records().list().len(), 1, "own name must not become an owner (persisted) record");
    // renamed: the old name stops answering
    e.set_own("dns.lan", vec![ip(4)]).unwrap();
    assert_eq!(e.decide("adblock.home", C, 0).action, Action::Resolve);
    assert_eq!(e.local_ips("dns.lan"), Some(&[ip(4)][..]));
    assert_eq!(e.own(), Some(("dns.lan", &[ip(4)][..])));
    assert_eq!(e.local_ips("nas.test"), Some(&[ip(5)][..]));
    assert!(e.set_own("bad..name", vec![ip(4)]).is_err());
    assert!(e.set_own("dns.lan", vec![]).is_err());
    e.clear_own();
    assert_eq!(e.own(), None);
    assert_eq!(e.decide("dns.lan", C, 0).action, Action::Resolve);
}
