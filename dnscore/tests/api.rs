use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dnscore::api::{
    ban_req, clamp_n, password_req, pause_req, query_param, record_req, rule_error_message, rule_req, settings_req,
    top_kind, BanOp, RecordOp, RuleOp, TopKind, PAUSE_CHOICES,
};
use dnscore::store::{Settings, MAX_RATE_BURST, MAX_RATE_PER_SEC};
use dnscore::{ClientKey, RuleError, RuleKind};

fn obj(s: &str) -> dnscore::json::Object {
    dnscore::json::parse_object(s.as_bytes()).unwrap()
}

#[test]
fn query_params_are_decoded_and_bounded() {
    let uri = "/api/lookup?d=ads.example.com&n=20&x=%7C%7Cads.example%5E&s=a+b&e=";
    assert_eq!(query_param(uri, "d").as_deref(), Some("ads.example.com"));
    assert_eq!(query_param(uri, "x").as_deref(), Some("||ads.example^"));
    assert_eq!(query_param(uri, "s").as_deref(), Some("a b"));
    assert_eq!(query_param(uri, "e").as_deref(), Some(""));
    assert_eq!(query_param(uri, "missing"), None);
    assert_eq!(query_param("/api/log", "n"), None);
    assert_eq!(query_param("/api/lookup?d=%zz", "d"), None);
    assert_eq!(query_param("/api/lookup?d=%ff", "d"), None); // not UTF-8
    assert_eq!(query_param("/api/lookup?d=%0a", "d"), None); // control character
    assert_eq!(query_param("/api/lookup?d=%4", "d"), None);
    assert_eq!(clamp_n(None, 20, 50), 20);
    assert_eq!(clamp_n(Some("7"), 20, 50), 7);
    assert_eq!(clamp_n(Some("500"), 20, 128), 128);
    assert_eq!(clamp_n(Some("0"), 20, 50), 0);
    assert_eq!(clamp_n(Some("-1"), 20, 50), 20);
    assert_eq!(clamp_n(Some("99999999999999999999"), 20, 50), 50);
    assert_eq!(clamp_n(Some("abc"), 20, 50), 20);
    assert_eq!(top_kind(Some("queried")), Ok(TopKind::Queried));
    assert_eq!(top_kind(Some("blocked")), Ok(TopKind::Blocked));
    assert_eq!(top_kind(None), Ok(TopKind::Queried));
    assert!(top_kind(Some("other")).is_err());
}

#[test]
fn rule_requests() {
    let r = rule_req(&obj(r#"{"op":"add","kind":"block","pattern":"||Ads.Example.com^"}"#)).unwrap();
    assert_eq!((r.op, r.kind, r.pattern.as_str()), (RuleOp::Add, RuleKind::Block, "||ads.example.com^"));
    let r = rule_req(&obj(r#"{"op":"remove","kind":"allow","pattern":"*.cdn.*"}"#)).unwrap();
    assert_eq!((r.op, r.kind, r.pattern.as_str()), (RuleOp::Remove, RuleKind::Allow, "*.cdn.*"));
    let r = rule_req(&obj(r#"{"op":"add","kind":"allow","pattern":"Plain.Example."}"#)).unwrap();
    assert_eq!(r.pattern, "plain.example");
    for bad in [
        r#"{"op":"add","kind":"block"}"#,
        r#"{"op":"add","kind":"deny","pattern":"a.example"}"#,
        r#"{"op":"put","kind":"block","pattern":"a.example"}"#,
        r#"{"op":"add","kind":"block","pattern":""}"#,
        r#"{"op":"add","kind":"block","pattern":"bad name"}"#,
        r#"{"op":"add","kind":"block","pattern":"a.example","extra":1}"#,
        r#"{"op":"add","kind":"block","pattern":5}"#,
        r#"{"op":"add","kind":"block","pattern":["a.example"]}"#,
    ] {
        let e = rule_req(&obj(bad)).err().unwrap_or_else(|| panic!("accepted {bad}"));
        assert!(!e.0.is_empty());
    }
    for e in [RuleError::Empty, RuleError::Invalid, RuleError::TooMany, RuleError::Duplicate] {
        assert!(!rule_error_message(e).is_empty());
    }
}

#[test]
fn record_requests() {
    let r = record_req(&obj(r#"{"op":"add","name":"NAS.home","ips":["192.0.2.5","fd00::5"]}"#)).unwrap();
    assert_eq!(r.op, RecordOp::Add);
    assert_eq!(r.name, "nas.home");
    assert_eq!(r.ips, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)), "fd00::5".parse::<IpAddr>().unwrap()]);
    let r = record_req(&obj(r#"{"op":"remove","name":"nas.home"}"#)).unwrap();
    assert_eq!((r.op, r.name.as_str(), r.ips.len()), (RecordOp::Remove, "nas.home", 0));
    for bad in [
        r#"{"op":"add","name":"nas.home"}"#,
        r#"{"op":"add","name":"nas.home","ips":[]}"#,
        r#"{"op":"add","name":"nas.home","ips":["300.1.1.1"]}"#,
        r#"{"op":"add","name":"nas.home","ips":["0.0.0.0"]}"#,
        r#"{"op":"add","name":"nas.home","ips":["224.0.0.1"]}"#,
        r#"{"op":"add","name":"nas.home","ips":["10.0.0.1","10.0.0.1"]}"#,
        r#"{"op":"add","name":"bad name","ips":["10.0.0.1"]}"#,
        r#"{"op":"add","name":"nas.home","ips":"10.0.0.1"}"#,
        r#"{"op":"remove","name":"nas.home","ips":["10.0.0.1"]}"#,
    ] {
        assert!(record_req(&obj(bad)).is_err(), "accepted {bad}");
    }
}

#[test]
fn ban_requests() {
    let r = ban_req(&obj(r#"{"op":"ban","client":"192.0.2.7"}"#)).unwrap();
    assert_eq!((r.op, r.client), (BanOp::Ban, ClientKey::V4(Ipv4Addr::new(192, 0, 2, 7))));
    // IPv4-mapped IPv6 is the IPv4 client
    let r = ban_req(&obj(r#"{"op":"unban","client":"::ffff:192.0.2.7"}"#)).unwrap();
    assert_eq!((r.op, r.client), (BanOp::Unban, ClientKey::V4(Ipv4Addr::new(192, 0, 2, 7))));
    let r = ban_req(&obj(r#"{"op":"ban","client":"2001:db8::1"}"#)).unwrap();
    assert_eq!(r.client, ClientKey::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()));
    assert!(ban_req(&obj(r#"{"op":"ban","client":"nope"}"#)).is_err());
    assert!(ban_req(&obj(r#"{"op":"kick","client":"192.0.2.7"}"#)).is_err());
}

#[test]
fn pause_requests_take_the_offered_durations_or_zero() {
    assert_eq!(PAUSE_CHOICES, [30, 300, 1800]);
    for s in [0u32, 30, 300, 1800] {
        assert_eq!(pause_req(&obj(&format!("{{\"secs\":{s}}}"))), Ok(s));
    }
    for bad in [r#"{"secs":31}"#, r#"{"secs":"30"}"#, r#"{}"#, r#"{"secs":30,"x":1}"#, r#"{"secs":99999999999}"#] {
        assert!(pause_req(&obj(bad)).is_err(), "accepted {bad}");
    }
}

#[test]
fn settings_requests_validate_and_apply() {
    let cur = Settings::default();
    let s = settings_req(&obj(r#"{"upstreams":["9.9.9.9","2620:fe::fe"]}"#), &cur, &[]).unwrap();
    assert_eq!(s.upstreams.len(), 2);
    assert_eq!(s.rate_burst, cur.rate_burst);
    let s = settings_req(&obj(r#"{"rate_burst":80,"rate_per_sec":30,"local_name":"NAS.home"}"#), &cur, &[]).unwrap();
    assert_eq!((s.rate_burst, s.rate_per_sec, s.local_name.as_str()), (80, 30, "nas.home"));
    assert_eq!(s.upstreams, cur.upstreams);
    let max = format!("{{\"rate_burst\":{MAX_RATE_BURST},\"rate_per_sec\":{MAX_RATE_PER_SEC}}}");
    assert!(settings_req(&obj(&max), &cur, &[]).is_ok());
    for bad in [
        r#"{}"#,
        r#"{"upstreams":[]}"#,
        r#"{"upstreams":["9.9.9.9","9.9.9.9"]}"#,
        r#"{"upstreams":["not an ip"]}"#,
        r#"{"upstreams":["0.0.0.0"]}"#,
        r#"{"upstreams":["127.0.0.1"]}"#,
        r#"{"upstreams":["::1"]}"#,
        r#"{"upstreams":["fe80::1"]}"#,
        r#"{"upstreams":["224.0.0.1"]}"#,
        r#"{"upstreams":["255.255.255.255"]}"#,
        r#"{"upstreams":["2620:fe::fe"]}"#, // no IPv4 upstream: DNS would stop without an IPv6 uplink
        r#"{"upstreams":["1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112","208.67.222.222","208.67.220.220","94.140.14.14"]}"#,
        r#"{"rate_burst":0}"#,
        r#"{"rate_per_sec":0}"#,
        r#"{"rate_burst":1001}"#,
        r#"{"rate_per_sec":1001}"#,
        r#"{"rate_burst":"50"}"#,
        r#"{"local_name":"google.com"}"#,
        r#"{"local_name":"a.b.c.home"}"#,
        r#"{"log_cap":5}"#,
    ] {
        // (nine upstreams are already refused by the JSON list limit)
        let r = dnscore::api::body(bad.as_bytes()).and_then(|o| settings_req(&o, &cur, &[]));
        let e = r.err().unwrap_or_else(|| panic!("accepted {bad}"));
        assert!(!e.0.is_empty());
    }
    let e = settings_req(&obj(r#"{"local_name":"google.com"}"#), &cur, &[]).err().unwrap();
    assert!(e.0.contains(".home"), "{}", e.0);
}

#[test]
fn password_requests() {
    let p = password_req(&obj(r#"{"old":"old password 1","new":"a new password"}"#)).unwrap();
    assert_eq!((p.old.as_str(), p.new.as_str()), ("old password 1", "a new password"));
    assert!(password_req(&obj(r#"{"old":"x","new":"short"}"#)).is_err());
    assert!(password_req(&obj(r#"{"new":"a new password"}"#)).is_err());
    assert!(password_req(&obj(r#"{"old":"","new":"a new password"}"#)).is_err());
    let long = format!("{{\"old\":\"x\",\"new\":\"{}\"}}", "x".repeat(129));
    assert!(password_req(&obj(&long)).is_err());
}

#[test]
fn an_upstream_that_is_this_device_is_refused() {
    let cur = Settings::default();
    let own = [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)),
        IpAddr::V6("2001:db8::1adc".parse::<Ipv6Addr>().unwrap()),
    ];
    for bad in [
        r#"{"upstreams":["192.0.2.3"]}"#,
        r#"{"upstreams":["9.9.9.9","192.0.2.3"]}"#,
        r#"{"upstreams":["9.9.9.9","2001:db8::1adc"]}"#,
        r#"{"upstreams":["9.9.9.9","::ffff:192.0.2.3"]}"#,
    ] {
        let e = settings_req(&obj(bad), &cur, &own).err().unwrap_or_else(|| panic!("accepted {bad}"));
        assert!(e.0.contains("this device"), "{bad}: {}", e.0);
    }
    assert!(settings_req(&obj(r#"{"upstreams":["192.0.2.4","2001:db8::1add"]}"#), &cur, &own).is_ok());
    // settings that do not touch the upstreams are not affected by the own addresses
    assert!(settings_req(&obj(r#"{"rate_burst":10}"#), &cur, &own).is_ok());
}
