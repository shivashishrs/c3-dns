use dnscore::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn enc_name(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for l in name.split('.').filter(|l| !l.is_empty()) {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

fn header(id: u16, flags: u16, qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut v = Vec::new();
    for x in [id, flags, qd, an, ns, ar] {
        v.extend_from_slice(&x.to_be_bytes());
    }
    v
}

fn make_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut p = header(0x1234, 0x0100, 1, 0, 0, 0);
    p.extend(enc_name(name));
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p
}

fn rr(name_ptr: u16, rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut v = name_ptr.to_be_bytes().to_vec();
    v.extend_from_slice(&rtype.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(&ttl.to_be_bytes());
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
    v
}

/// Packet with two CNAMEs then an A record.
fn cname_packet() -> Vec<u8> {
    let mut p = header(7, 0x8180, 1, 3, 0, 0);
    p.extend(enc_name("www.example.com"));
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend(rr(0xC00C, 5, 300, &enc_name("cdn.example.net")));
    p.extend(rr(0xC00C, 5, 200, &enc_name("edge.Example.org")));
    p.extend(rr(0xC00C, 1, 100, &[1, 2, 3, 4]));
    p
}

#[test]
fn parses_a_query_and_lowercases() {
    let q = parse_query(&make_query("ExAmple.COM.", QTYPE_A)).unwrap();
    assert_eq!(q.name, "example.com");
    assert_eq!(q.id, 0x1234);
    assert_eq!(q.qtype, QTYPE_A);
    assert_eq!(q.qclass, 1);
    assert_eq!(q.udp_size, 512);
    assert_eq!(q.question_end, 12 + 13 + 4);
    assert_eq!(normalize("ExAmple.COM.").as_deref(), Some("example.com"));
}

#[test]
fn rejects_label_over_63_and_name_over_253() {
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.push(64);
    p.extend_from_slice(&[b'a'; 64]);
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert!(parse_query(&p).is_err());
    assert!(normalize(&"a".repeat(64)).is_none());
    assert!(normalize(&"a".repeat(63)).is_some());

    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    for _ in 0..30 {
        p.push(9);
        p.extend_from_slice(&[b'b'; 9]);
    }
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::TooLong);
    let long = vec!["bbbbbbbbb"; 30].join(".");
    assert!(normalize(&long).is_none());
    assert!(normalize("").is_none());
    assert!(normalize("a..b").is_none());
}

#[test]
fn rejects_compression_pointer_loop() {
    // pointer to itself
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::PointerLoop);
    // A -> B -> A
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.extend_from_slice(&[0xC0, 14, 0xC0, 12, 0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::PointerLoop);
    // and in a response
    let mut p = header(1, 0x8180, 1, 0, 0, 0);
    p.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
    assert_eq!(parse_response(&p).unwrap_err(), ParseError::PointerLoop);
}

#[test]
fn rejects_truncated_header_and_question() {
    let q = make_query("example.com", QTYPE_A);
    for n in 0..q.len() {
        assert!(parse_query(&q[..n]).is_err(), "len {n}");
    }
    assert!(parse_query(&q).is_ok());
    assert_eq!(parse_query(&q[..5]).unwrap_err(), ParseError::Short);
    // a response is not a query
    assert_eq!(parse_query(&cname_packet()).unwrap_err(), ParseError::NotAQuery);
}

#[test]
fn blocked_a_is_0_0_0_0_and_aaaa_is_double_colon() {
    let pkt = make_query("ads.example.com", QTYPE_A);
    let q = parse_query(&pkt).unwrap();
    let r = build_blocked(&pkt, &q);
    let resp = parse_response(&r).unwrap();
    assert_eq!(resp.rcode, 0);
    assert_eq!(&r[r.len() - 4..], &[0, 0, 0, 0]);
    assert_eq!(&r[0..2], &pkt[0..2]);
    assert_eq!(&r[12..q.question_end], &pkt[12..q.question_end]);

    let pkt = make_query("ads.example.com", QTYPE_AAAA);
    let q = parse_query(&pkt).unwrap();
    let r = build_blocked(&pkt, &q);
    assert_eq!(parse_response(&r).unwrap().rcode, 0);
    assert_eq!(&r[r.len() - 16..], &[0u8; 16]);
    assert_eq!(r.len(), q.question_end + 2 + 2 + 2 + 4 + 2 + 16);
}

#[test]
fn blocked_other_type_is_empty_noerror() {
    let pkt = make_query("ads.example.com", 15);
    let q = parse_query(&pkt).unwrap();
    let r = build_blocked(&pkt, &q);
    assert_eq!(r.len(), q.question_end);
    assert_eq!(&r[6..8], &[0, 0]);
    assert_eq!(parse_response(&r).unwrap().rcode, 0);
    assert_eq!(&r[0..2], &pkt[0..2]);
}

#[test]
fn build_local_returns_all_addresses() {
    let v4 = [Ipv4Addr::new(192, 0, 2, 11), Ipv4Addr::new(192, 0, 2, 12)];
    let v6 = [Ipv6Addr::LOCALHOST];
    let pkt = make_query("c3.lan", QTYPE_A);
    let q = parse_query(&pkt).unwrap();
    let r = build_local(&pkt, &q, &v4, &v6, 30);
    assert_eq!(&r[6..8], &[0, 2]);
    assert_eq!(&r[r.len() - 4..], &[192, 0, 2, 12]);
    let resp = parse_response(&r).unwrap();
    assert_eq!((resp.rcode, resp.min_ttl), (0, 30));
    let pkt = make_query("c3.lan", QTYPE_AAAA);
    let q = parse_query(&pkt).unwrap();
    let r = build_local(&pkt, &q, &v4, &v6, 30);
    assert_eq!(&r[6..8], &[0, 1]);
    assert_eq!(r[r.len() - 1], 1);
    let q = parse_query(&make_query("c3.lan", 15)).unwrap();
    let r = build_local(&make_query("c3.lan", 15), &q, &v4, &v6, 30);
    assert_eq!(&r[6..8], &[0, 0]);
}

#[test]
fn refused_and_servfail_set_rcode() {
    let pkt = make_query("x.com", QTYPE_A);
    let q = parse_query(&pkt).unwrap();
    assert_eq!(parse_response(&build_refused(&pkt, &q)).unwrap().rcode, 5);
    assert_eq!(parse_response(&build_servfail(&pkt, &q)).unwrap().rcode, 2);
}

#[test]
fn response_cnames_are_extracted_in_order() {
    let r = parse_response(&cname_packet()).unwrap();
    assert_eq!(r.cnames, vec!["cdn.example.net", "edge.example.org"]);
    assert_eq!(r.min_ttl, 100);
    assert_eq!(r.rcode, 0);
    assert!(!r.truncated);
}

#[test]
fn age_ttls_never_goes_below_one() {
    let mut p = cname_packet();
    age_ttls(&mut p, 150);
    assert_eq!(parse_response(&p).unwrap().min_ttl, 1);
    let mut p = cname_packet();
    age_ttls(&mut p, 50);
    assert_eq!(parse_response(&p).unwrap().min_ttl, 50);
    let mut p = cname_packet();
    age_ttls(&mut p, u32::MAX);
    assert_eq!(parse_response(&p).unwrap().min_ttl, 1);
}

#[test]
fn set_id_rewrites_first_two_bytes() {
    let mut p = cname_packet();
    let tail = p[2..].to_vec();
    set_id(&mut p, 0xBEEF);
    assert_eq!(&p[0..2], &[0xBE, 0xEF]);
    assert_eq!(&p[2..], &tail[..]);
    set_id(&mut [1u8][..], 5); // short buffer must not panic
}

#[test]
fn edns_udp_size_is_read_from_opt() {
    let mut p = make_query("example.com", QTYPE_A);
    p[10..12].copy_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(parse_query(&p).unwrap().udp_size, 4096);
}

// ---- hardening ----

#[test]
fn query_qname_with_compression_pointer_is_rejected() {
    // 12: label "a", 14: pointer to 16, 16: "com" -> would decode to a.com
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.extend_from_slice(&[1, b'a', 0xC0, 16, 3, b'c', b'o', b'm', 0]);
    p.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::Malformed);
    // pointer as the very first thing
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.extend_from_slice(&[0xC0, 14, 1, b'a', 0]);
    p.extend_from_slice(&[0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::Malformed);
}

#[test]
fn root_qname_is_malformed() {
    let mut p = header(1, 0x0100, 1, 0, 0, 0);
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(parse_query(&p).unwrap_err(), ParseError::Malformed);
}

#[test]
fn huge_counts_with_tiny_packet_fail_fast() {
    for (qd, an) in [(65535u16, 0u16), (0, 65535), (65535, 65535)] {
        let p = header(1, 0x8180, qd, an, 65535, 65535);
        assert!(parse_response(&p).is_err(), "qd={qd} an={an}");
    }
    // truncated responses tolerate missing records
    let p = header(1, 0x8380, 0, 65535, 0, 0);
    let r = parse_response(&p).unwrap();
    assert!(r.truncated && r.cnames.is_empty());
    let mut q = header(1, 0x0100, 65535, 65535, 0, 0);
    q.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    assert!(parse_query(&q).is_err());
}

/// Response with one A record whose owner name is `hops` chained pointers.
fn pointer_chain_packet(hops: usize) -> Vec<u8> {
    let mut p = header(1, 0x8180, 0, 1, 0, 0);
    let tail = 24u16;
    p.extend_from_slice(&(0xC000 | tail).to_be_bytes()); // hop 1
    p.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 0]); // type, class, ttl, rdlen 0
    assert_eq!(p.len(), tail as usize);
    for i in 0..hops - 1 {
        let next = tail + 2 * (i as u16 + 1);
        p.extend_from_slice(&(0xC000 | next).to_be_bytes());
    }
    p.extend_from_slice(&[1, b'a', 0]);
    p
}

#[test]
fn pointer_chain_of_16_hops_parses_and_17_is_a_loop() {
    assert_eq!(parse_response(&pointer_chain_packet(16)).unwrap().min_ttl, 60);
    assert_eq!(parse_response(&pointer_chain_packet(17)).unwrap_err(), ParseError::PointerLoop);
}

// ---- Task 6 helpers ----

#[test]
fn set_ttls_rewrites_every_record_ttl() {
    let mut p = cname_packet();
    set_ttls(&mut p, 30);
    let mut want = header(7, 0x8180, 1, 3, 0, 0);
    want.extend(enc_name("www.example.com"));
    want.extend_from_slice(&1u16.to_be_bytes());
    want.extend_from_slice(&1u16.to_be_bytes());
    want.extend(rr(0xC00C, 5, 30, &enc_name("cdn.example.net")));
    want.extend(rr(0xC00C, 5, 30, &enc_name("edge.Example.org")));
    want.extend(rr(0xC00C, 1, 30, &[1, 2, 3, 4]));
    assert_eq!(p, want);
    set_ttls(&mut [0u8; 5][..], 30); // short buffer must not panic
}

#[test]
fn set_ttls_skips_opt_record() {
    let mut p = cname_packet();
    p[10..12].copy_from_slice(&1u16.to_be_bytes());
    // OPT: root name, type 41, class 1232, "ttl" = ext-rcode/flags 0x00008000 (DO bit)
    p.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
    let n = p.len();
    set_ttls(&mut p, 30);
    assert_eq!(&p[n - 6..n - 2], &[0, 0, 0x80, 0], "OPT flags untouched");
    assert_eq!(parse_response(&p).unwrap().min_ttl, 30);
}

#[test]
fn build_truncated_sets_tc_and_has_no_answers() {
    let q_pkt = make_query("example.com", QTYPE_A);
    let q = parse_query(&q_pkt).unwrap();
    let t = build_truncated(&q_pkt, &q);
    let r = parse_response(&t).unwrap();
    assert!(r.truncated);
    assert_eq!(r.rcode, 0);
    assert_eq!(&t[0..2], &[0x12, 0x34]);
    assert_eq!(&t[6..8], &[0, 0], "ANCOUNT 0");
    assert_eq!(&t[12..], &q_pkt[12..]);
}

#[test]
fn same_question_matches_case_insensitively_and_rejects_others() {
    let q_pkt = make_query("www.Example.com", QTYPE_A);
    let q = parse_query(&q_pkt).unwrap();
    let mut resp = cname_packet(); // question www.example.com A
    assert!(same_question(&resp, &q_pkt, &q));
    let aaaa = make_query("www.example.com", QTYPE_AAAA);
    let qa = parse_query(&aaaa).unwrap();
    assert!(!same_question(&resp, &aaaa, &qa), "different qtype");
    let other = make_query("www.example.org", QTYPE_A);
    let qo = parse_query(&other).unwrap();
    assert!(!same_question(&resp, &other, &qo), "different name");
    resp[2] &= 0x7F; // clear QR: a query is not a response
    assert!(!same_question(&resp, &q_pkt, &q));
    assert!(!same_question(&resp[..14], &q_pkt, &q), "short response");
    assert!(!same_question(&[], &q_pkt, &q));
}

// ---- fix round 1: 0x20, exact question match, case restore, EDNS clamp ----

#[test]
fn apply_0x20_changes_only_letter_case_in_the_question() {
    let mut p = make_query("www.example-1.com", QTYPE_A);
    let q = parse_query(&p).unwrap();
    let orig = p.clone();
    let mut calls = 0;
    apply_0x20(&mut p, &q, || {
        calls += 1;
        0xAAAA_AAAA
    });
    assert!(calls >= 1);
    assert_ne!(p, orig, "some letter changed case");
    assert_eq!(p.len(), orig.len());
    assert_eq!(&p[..12], &orig[..12], "header untouched");
    assert_eq!(&p[q.question_end - 4..], &orig[q.question_end - 4..], "type/class untouched");
    assert!(p[12..q.question_end].eq_ignore_ascii_case(&orig[12..q.question_end]));
    // still the same name to the parser (which lower-cases)
    assert_eq!(parse_query(&p).unwrap().name, "www.example-1.com");
    // all-ones flips every letter to upper case, all-zeros to lower case
    let mut up = orig.clone();
    apply_0x20(&mut up, &q, || u32::MAX);
    assert_eq!(&up[13..16], b"WWW");
    let mut low = up.clone();
    apply_0x20(&mut low, &q, || 0);
    assert_eq!(low, orig);
    apply_0x20(&mut [0u8; 3][..], &q, || 1); // short buffer must not panic
}

#[test]
fn same_question_exact_is_case_sensitive() {
    let q_pkt = make_query("www.example.com", QTYPE_A);
    let q = parse_query(&q_pkt).unwrap();
    let resp = cname_packet(); // www.example.com, lower case
    assert!(same_question_exact(&resp, &q_pkt, &q));
    let mut mixed = q_pkt.clone();
    apply_0x20(&mut mixed, &q, || u32::MAX);
    assert!(!same_question_exact(&resp, &mixed, &q), "case differs");
    assert!(same_question(&resp, &mixed, &q), "the insensitive match still holds");
    let mut resp_mixed = resp.clone();
    restore_question(&mut resp_mixed, &mixed, &q);
    assert!(same_question_exact(&resp_mixed, &mixed, &q));
    assert!(!same_question_exact(&resp[..14], &q_pkt, &q));
}

#[test]
fn restore_question_copies_client_case_and_ignores_mismatched_lengths() {
    let client = make_query("WwW.ExAmple.COM", QTYPE_A);
    let q = parse_query(&client).unwrap();
    let mut resp = cname_packet();
    let tail = resp[q.question_end..].to_vec();
    restore_question(&mut resp, &client, &q);
    assert_eq!(&resp[12..q.question_end], &client[12..q.question_end]);
    assert_eq!(&resp[q.question_end..], &tail[..], "records untouched");
    let mut short = vec![0u8; 14];
    restore_question(&mut short, &client, &q); // must not panic
    assert_eq!(short, vec![0u8; 14]);
}

fn with_opt(size: u16) -> Vec<u8> {
    let mut p = make_query("example.com", QTYPE_A);
    p[10..12].copy_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 41]);
    p.extend_from_slice(&size.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    p
}

#[test]
fn clamp_edns_lowers_a_large_udp_size_only() {
    let mut p = with_opt(4096);
    clamp_edns(&mut p, 1232);
    assert_eq!(parse_query(&p).unwrap().udp_size, 1232);
    let mut p = with_opt(1000);
    clamp_edns(&mut p, 1232);
    assert_eq!(parse_query(&p).unwrap().udp_size, 1000, "smaller sizes are kept");
    let mut p = make_query("example.com", QTYPE_A);
    let before = p.clone();
    clamp_edns(&mut p, 1232);
    assert_eq!(p, before, "no OPT: unchanged");
    clamp_edns(&mut [0u8; 5][..], 1232); // must not panic
}
