use dnscore::json::{parse_object, write_str, write_u64, JsonError, Value, MAX_ARRAY, MAX_BODY, MAX_KEYS, MAX_STR};

fn esc(s: &str) -> String {
    let mut out = Vec::new();
    write_str(&mut out, s);
    String::from_utf8(out).expect("escaper emits UTF-8")
}

#[test]
fn escapes_quotes_backslashes_and_controls() {
    assert_eq!(esc("plain.example"), "\"plain.example\"");
    assert_eq!(esc("a\"b\\c"), "\"a\\\"b\\\\c\"");
    assert_eq!(esc("\n\r\t\u{8}\u{c}"), "\"\\n\\r\\t\\b\\f\"");
    assert_eq!(esc("\u{0}\u{1f}\u{7f}"), "\"\\u0000\\u001f\\u007f\"");
    // HTML-significant characters never appear raw (defence in depth for a JSON reply).
    assert_eq!(esc("<script>&"), "\"\\u003cscript\\u003e\\u0026\"");
    // Line/paragraph separators break JS string literals in old engines.
    assert_eq!(esc("a\u{2028}b\u{2029}"), "\"a\\u2028b\\u2029\"");
    // Other non-ASCII passes through as UTF-8.
    assert_eq!(esc("é…"), "\"é…\"");
}

#[test]
fn escaped_output_round_trips_through_the_parser() {
    let nasty = "q\"\\\n\u{1}<>&\u{2028}é x";
    let mut body = b"{\"k\":".to_vec();
    write_str(&mut body, nasty);
    body.push(b'}');
    let o = parse_object(&body).unwrap_err();
    // the parser refuses control characters in values, so use a printable one here
    assert_eq!(o, JsonError::BadString);
    let ok = "q\"\\<>&é x/";
    let mut body = b"{\"k\":".to_vec();
    write_str(&mut body, ok);
    body.push(b'}');
    assert_eq!(parse_object(&body).unwrap().str("k"), Some(ok));
}

#[test]
fn writes_numbers() {
    let mut o = Vec::new();
    write_u64(&mut o, 0);
    o.push(b',');
    write_u64(&mut o, u64::MAX);
    assert_eq!(String::from_utf8(o).unwrap(), "0,18446744073709551615");
}

#[test]
fn parses_the_request_shapes() {
    let o = parse_object(br#" { "op" : "add", "kind":"block", "pattern":"||ads.example^" } "#).unwrap();
    assert_eq!(o.str("op"), Some("add"));
    assert_eq!(o.str("pattern"), Some("||ads.example^"));
    let o = parse_object(br#"{"name":"nas.home","ips":["192.0.2.5","fd00::5"]}"#).unwrap();
    assert_eq!(o.get("ips"), Some(&Value::Arr(vec!["192.0.2.5".into(), "fd00::5".into()])));
    let o = parse_object(br#"{"secs":300,"x":true,"y":false,"z":null,"e":[]}"#).unwrap();
    assert_eq!(o.get("secs"), Some(&Value::Num(300)));
    assert_eq!(o.get("x"), Some(&Value::Bool(true)));
    assert_eq!(o.get("y"), Some(&Value::Bool(false)));
    assert_eq!(o.get("z"), Some(&Value::Null));
    assert_eq!(o.get("e"), Some(&Value::Arr(vec![])));
    assert_eq!(parse_object(b"{}").unwrap().keys().count(), 0);
    let o = parse_object(br#"{"b":1,"a":2}"#).unwrap();
    let keys: Vec<&str> = o.keys().collect();
    assert_eq!(keys, ["b", "a"]);
}

#[test]
fn decodes_string_escapes_including_surrogate_pairs() {
    let o = parse_object(br#"{"k":"a\"b\\c\/d\u00e9\ud83d\ude00"}"#).unwrap();
    assert_eq!(o.str("k"), Some("a\"b\\c/dé😀"));
    // raw UTF-8 is accepted too
    assert_eq!(parse_object("{\"k\":\"é\"}".as_bytes()).unwrap().str("k"), Some("é"));
}

#[test]
fn rejects_bad_strings() {
    for b in [
        &br#"{"k":"\ud83d"}"#[..],       // lone high surrogate
        br#"{"k":"\ude00"}"#,             // lone low surrogate
        br#"{"k":"\ud83dx"}"#,            // high surrogate not followed by \u
        br#"{"k":"\u12"}"#,               // short \u
        br#"{"k":"\uzzzz"}"#,             // bad hex
        br#"{"k":"\q"}"#,                 // unknown escape
        b"{\"k\":\"a\nb\"}",              // raw control character
        br#"{"k":"\u0000"}"#,             // escaped control character
        br#"{"k":"\u007f"}"#,             // DEL
        b"{\"k\":\"\xff\xfe\"}",          // invalid UTF-8
        b"{\"k\":\"\xc3\"}",              // truncated UTF-8
    ] {
        assert_eq!(parse_object(b), Err(JsonError::BadString), "{:?}", String::from_utf8_lossy(b));
    }
}

#[test]
fn rejects_syntax_errors() {
    for b in [
        &b""[..],
        b" ",
        b"[]",
        b"\"x\"",
        b"{",
        b"{\"a\"}",
        b"{\"a\":}",
        b"{\"a\":1,}",
        b"{,}",
        b"{\"a\" 1}",
        b"{\"a\":1 \"b\":2}",
        b"{a:1}",
        b"{'a':1}",
        b"{\"a\":\"x}",
        b"{\"a\":tru}",
        b"{\"a\":nul}",
        b"{\"a\":[\"x\",]}",
        b"{\"a\":[\"x\" \"y\"]}",
        b"{\"a\":[\"x\"}",
    ] {
        assert!(parse_object(b).is_err(), "{:?}", String::from_utf8_lossy(b));
    }
    assert_eq!(parse_object(b"{} x"), Err(JsonError::Trailing));
    assert_eq!(parse_object(b"{}{}"), Err(JsonError::Trailing));
}

#[test]
fn rejects_nesting_beyond_flat_objects() {
    assert_eq!(parse_object(br#"{"a":{"b":1}}"#), Err(JsonError::Depth));
    assert_eq!(parse_object(br#"{"a":[["x"]]}"#), Err(JsonError::Depth));
    assert_eq!(parse_object(br#"{"a":[{"x":1}]}"#), Err(JsonError::Depth));
    // arrays hold strings only
    assert_eq!(parse_object(br#"{"a":[1]}"#), Err(JsonError::Syntax));
    // deep nesting is refused at the first level, without recursion
    let deep = format!("{{\"a\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(parse_object(deep.as_bytes()), Err(JsonError::TooLarge));
    let deep = format!("{{\"a\":{}", "[".repeat(1000));
    assert_eq!(parse_object(deep.as_bytes()), Err(JsonError::Depth));
}

#[test]
fn rejects_numbers_other_than_plain_non_negative_integers() {
    for b in [
        &b"{\"n\":-1}"[..],
        b"{\"n\":1.5}",
        b"{\"n\":1e3}",
        b"{\"n\":01}",
        b"{\"n\":+1}",
        b"{\"n\":1234567890123456}",
    ] {
        assert_eq!(parse_object(b), Err(JsonError::BadNumber), "{:?}", String::from_utf8_lossy(b));
    }
    assert_eq!(parse_object(b"{\"n\":0}").unwrap().get("n"), Some(&Value::Num(0)));
    assert_eq!(parse_object(b"{\"n\":123456789012345}").unwrap().get("n"), Some(&Value::Num(123_456_789_012_345)));
}

#[test]
fn enforces_the_limits() {
    let big = vec![b' '; MAX_BODY + 1];
    assert_eq!(parse_object(&big), Err(JsonError::TooLarge));
    let long = format!("{{\"k\":\"{}\"}}", "x".repeat(MAX_STR + 1));
    assert_eq!(parse_object(long.as_bytes()), Err(JsonError::StringTooLong));
    let ok = format!("{{\"k\":\"{}\"}}", "x".repeat(MAX_STR));
    assert!(parse_object(ok.as_bytes()).is_ok());
    // escapes count after decoding: 512 decoded bytes from \u sequences still fit
    let esc = format!("{{\"k\":\"{}\"}}", "\\u0041".repeat(MAX_STR / 2));
    assert!(esc.len() <= MAX_BODY);
    assert!(parse_object(esc.as_bytes()).is_ok());
    let keys: Vec<String> = (0..=MAX_KEYS).map(|i| format!("\"k{i}\":1")).collect();
    let many = format!("{{{}}}", keys.join(","));
    assert_eq!(parse_object(many.as_bytes()), Err(JsonError::TooManyKeys));
    let items: Vec<String> = (0..=MAX_ARRAY).map(|i| format!("\"{i}\"")).collect();
    let arr = format!("{{\"a\":[{}]}}", items.join(","));
    assert_eq!(parse_object(arr.as_bytes()), Err(JsonError::ArrayTooLong));
    assert_eq!(parse_object(br#"{"a":1,"a":2}"#), Err(JsonError::DuplicateKey));
}

#[test]
fn every_error_has_a_message() {
    for e in [
        JsonError::TooLarge,
        JsonError::Syntax,
        JsonError::Depth,
        JsonError::TooManyKeys,
        JsonError::StringTooLong,
        JsonError::ArrayTooLong,
        JsonError::BadNumber,
        JsonError::BadString,
        JsonError::DuplicateKey,
        JsonError::Trailing,
    ] {
        assert!(!e.message().is_empty());
    }
}

/// Hostile input: random bytes and mutations of valid bodies never panic.
#[test]
fn survives_mutated_input() {
    let seeds: [&[u8]; 4] = [
        br#"{"op":"add","kind":"block","pattern":"||ads.example^"}"#,
        br#"{"name":"nas.home","ips":["192.0.2.5","fd00::5"]}"#,
        br#"{"secs":300}"#,
        br#"{"k":"a\"b\\c\/d\u00e9\ud83d\ude00","t":true,"n":null}"#,
    ];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for i in 0..50_000 {
        let mut b = seeds[i % seeds.len()].to_vec();
        for _ in 0..(rnd() % 4 + 1) {
            let r = rnd();
            let pos = (r as usize >> 8) % (b.len() + 1);
            match r % 3 {
                0 if pos < b.len() => b[pos] = (r >> 32) as u8,
                1 => b.insert(pos, (r >> 32) as u8),
                _ if pos < b.len() => {
                    b.remove(pos);
                }
                _ => {}
            }
        }
        let _ = parse_object(&b);
    }
}
