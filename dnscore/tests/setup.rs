use dnscore::setup::{
    ap_name, html_escape, parse_form, render_form, token_hex, validate, Attempts, FormError, SetupError,
    ATTEMPTS_PER_MIN, MAX_BODY, MAX_FIELD, MAX_FIELDS, MAX_SCAN,
};

const TOKEN: &str = "00112233445566778899aabbccddeeff";

fn body(fields: &[(&str, &str)]) -> Vec<u8> {
    fields.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&").into_bytes()
}

fn good() -> Vec<(&'static str, &'static str)> {
    vec![("t", TOKEN), ("ssid", "Home+Net"), ("psk", "wifi%20pass%26word"), ("admin", "a+long+admin+pw"), ("admin2", "a+long+admin+pw")]
}

// --- escaping ---

#[test]
fn escape_covers_html_metacharacters() {
    assert_eq!(html_escape(r#""><script>alert(1)</script>"#), "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
    assert_eq!(html_escape("a&b 'c'"), "a&amp;b &#39;c&#39;");
    assert_eq!(html_escape("&amp;"), "&amp;amp;", "already-escaped text is escaped again");
    assert_eq!(html_escape("plain ünï"), "plain ünï");
    assert_eq!(html_escape(""), "");
    let long = "<".repeat(10_000);
    assert_eq!(html_escape(&long).len(), 40_000);
}

// --- form parsing ---

#[test]
fn parses_urlencoded_with_plus_and_percent() {
    let f = parse_form(&body(&good())).unwrap();
    assert_eq!(f.get("ssid"), Some("Home Net"));
    assert_eq!(f.get("psk"), Some("wifi pass&word"));
    assert_eq!(f.get("missing"), None);
    let f = parse_form(b"a=%3Cscript%3E&b=%c3%a9&c=&d").unwrap();
    assert_eq!(f.get("a"), Some("<script>"));
    assert_eq!(f.get("b"), Some("é"));
    assert_eq!(f.get("c"), Some(""));
    assert_eq!(f.get("d"), Some(""));
    assert!(parse_form(b"").unwrap().get("a").is_none());
}

#[test]
fn bad_encoding_is_rejected() {
    assert_eq!(parse_form(b"a=%zz").err().unwrap(), FormError::BadEncoding);
    assert_eq!(parse_form(b"a=%4").err().unwrap(), FormError::BadEncoding);
    assert_eq!(parse_form(b"a=%").err().unwrap(), FormError::BadEncoding);
    assert_eq!(parse_form(b"a=%ff%fe").err().unwrap(), FormError::BadEncoding, "invalid UTF-8 after decoding");
    assert_eq!(parse_form(b"a=\xff").err().unwrap(), FormError::BadEncoding, "raw invalid UTF-8");
    assert_eq!(parse_form(b"a=%00").err().unwrap(), FormError::BadEncoding, "control characters");
    assert_eq!(parse_form(b"a=x%0Ay").err().unwrap(), FormError::BadEncoding);
}

#[test]
fn sizes_and_counts_are_bounded() {
    let big = vec![b'a'; MAX_BODY + 1];
    assert_eq!(parse_form(&big).err().unwrap(), FormError::TooLarge);
    let long = format!("a={}", "x".repeat(MAX_FIELD + 1));
    assert_eq!(parse_form(long.as_bytes()).err().unwrap(), FormError::FieldTooLong);
    // percent-encoded length counts after decoding, but the encoded form is bounded by MAX_BODY
    let ok = format!("a={}", "%41".repeat(MAX_FIELD / 3));
    assert!(parse_form(ok.as_bytes()).is_ok());
    let longkey = format!("{}=1", "k".repeat(MAX_FIELD + 1));
    assert_eq!(parse_form(longkey.as_bytes()).err().unwrap(), FormError::FieldTooLong);
    let many: Vec<String> = (0..=MAX_FIELDS).map(|i| format!("f{i}=1")).collect();
    assert_eq!(parse_form(many.join("&").as_bytes()).err().unwrap(), FormError::TooManyFields);
}

#[test]
fn repeated_fields_are_rejected() {
    assert_eq!(parse_form(b"ssid=a&ssid=b").err().unwrap(), FormError::Repeated);
    assert_eq!(parse_form(b"t=1&psk=x&t=1").err().unwrap(), FormError::Repeated);
}

// --- validation ---

#[test]
fn valid_post_gives_the_settings() {
    let r = validate(&parse_form(&body(&good())).unwrap(), TOKEN).unwrap();
    assert_eq!(r.ssid, "Home Net");
    assert_eq!(r.psk.as_str(), "wifi pass&word");
    assert_eq!(r.admin.as_str(), "a long admin pw");
    // open network: empty psk allowed
    let mut f = good();
    f[2] = ("psk", "");
    assert_eq!(validate(&parse_form(&body(&f)).unwrap(), TOKEN).unwrap().psk.as_str(), "");
}

#[test]
fn token_is_checked_first() {
    let mut f = good();
    f[0] = ("t", "00112233445566778899aabbccddeef0");
    assert_eq!(validate(&parse_form(&body(&f)).unwrap(), TOKEN).err().unwrap(), SetupError::BadToken);
    f[0] = ("t", "");
    assert_eq!(validate(&parse_form(&body(&f)).unwrap(), TOKEN).err().unwrap(), SetupError::BadToken);
    let without: Vec<_> = good().into_iter().filter(|(k, _)| *k != "t").collect();
    assert_eq!(validate(&parse_form(&body(&without)).unwrap(), TOKEN).err().unwrap(), SetupError::BadToken);
    // an empty expected token never matches (portal not initialised)
    assert_eq!(validate(&parse_form(b"t=").unwrap(), "").err().unwrap(), SetupError::BadToken);
}

fn with(k: &'static str, v: &'static str) -> Result<dnscore::setup::SetupRequest, SetupError> {
    let f: Vec<_> = good().into_iter().map(|(a, b)| if a == k { (a, v) } else { (a, b) }).collect();
    validate(&parse_form(&body(&f)).unwrap(), TOKEN)
}

fn without(k: &str) -> Result<dnscore::setup::SetupRequest, SetupError> {
    let f: Vec<_> = good().into_iter().filter(|(a, _)| *a != k).collect();
    validate(&parse_form(&body(&f)).unwrap(), TOKEN)
}

#[test]
fn ssid_rules() {
    assert_eq!(with("ssid", "").err().unwrap(), SetupError::SsidMissing);
    assert_eq!(without("ssid").err().unwrap(), SetupError::SsidMissing);
    assert!(with("ssid", "abcdefghijklmnopqrstuvwxyz012345").is_ok(), "32 bytes");
    assert_eq!(with("ssid", "abcdefghijklmnopqrstuvwxyz0123456").err().unwrap(), SetupError::SsidTooLong);
    assert_eq!(with("ssid", "%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9%c3%a9").err().unwrap(), SetupError::SsidTooLong, "17 x 2 bytes");
}

#[test]
fn wifi_password_rules() {
    assert_eq!(with("psk", "short").err().unwrap(), SetupError::PskLength);
    assert!(with("psk", "8chars!!").is_ok());
    assert!(with("psk", "123456789012345678901234567890123456789012345678901234567890123").is_ok(), "63");
    assert!(with("psk", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").is_ok(), "64 hex");
    assert_eq!(with("psk", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg").err().unwrap(), SetupError::PskLength, "64 non-hex");
    assert_eq!(without("psk").unwrap().psk.as_str(), "", "missing psk = open network");
}

#[test]
fn admin_password_rules() {
    let f = |a: &'static str, b: &'static str| {
        let v: Vec<_> = good()
            .into_iter()
            .map(|(k, x)| match k {
                "admin" => (k, a),
                "admin2" => (k, b),
                _ => (k, x),
            })
            .collect();
        validate(&parse_form(&body(&v)).unwrap(), TOKEN)
    };
    assert_eq!(f("", "").err().unwrap(), SetupError::AdminMissing);
    assert_eq!(without("admin").err().unwrap(), SetupError::AdminMissing);
    assert_eq!(f("elevenchars", "elevenchars").err().unwrap(), SetupError::AdminTooShort);
    assert_eq!(f("twelve chars", "twelve chars").unwrap().admin.as_str(), "twelve chars");
    assert_eq!(f("twelve chars", "twelve charz").err().unwrap(), SetupError::AdminMismatch);
    assert_eq!(without("admin2").err().unwrap(), SetupError::AdminMismatch);
    let long: &'static str = Box::leak("x".repeat(129).into_boxed_str());
    assert_eq!(f(long, long).err().unwrap(), SetupError::AdminTooLong);
    assert!(SetupError::AdminTooShort.message().contains("12"));
    for e in [SetupError::BadToken, SetupError::AdminMismatch, SetupError::PskLength] {
        assert!(!e.message().is_empty());
    }
}

// --- rendering ---

#[test]
fn form_escapes_scanned_names_and_never_echoes_passwords() {
    let evil = r#""><script>alert(1)</script>"#.to_string();
    let scan = vec![evil.clone(), "Café & Co".to_string(), "it's".to_string()];
    let html = render_form(TOKEN, &scan, Some("Bad <b>"), Some(&evil), "/save");
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("Café &amp; Co"));
    assert!(html.contains("it&#39;s"));
    assert!(html.contains("Bad &lt;b&gt;"));
    assert!(html.contains(&format!("name=t value=\"{TOKEN}\"")), "token in a hidden field");
    assert!(html.contains("action=\"/save\""));
    assert!(html.contains("method=post"));
    // password inputs carry no value attribute
    for name in ["psk", "admin", "admin2"] {
        let i = html.find(&format!("name={name} ")).unwrap();
        let tag_end = html[i..].find('>').unwrap();
        assert!(!html[i..i + tag_end].contains("value"), "{name} must not be echoed");
    }
}

#[test]
fn scan_list_is_bounded() {
    let scan: Vec<String> = (0..100).map(|i| format!("net{i:03}")).collect();
    let html = render_form(TOKEN, &scan, None, None, "/save");
    assert_eq!(html.matches("<option").count(), MAX_SCAN);
}

// --- attempts, token, AP name ---

#[test]
fn attempts_are_limited_per_minute() {
    let mut a = Attempts::default();
    for i in 0..ATTEMPTS_PER_MIN {
        assert!(a.allow(1000 + u64::from(i)), "attempt {i}");
    }
    assert!(!a.allow(2000));
    assert!(!a.allow(60_999));
    assert!(a.allow(61_000), "a new minute");
    // clock going backwards does not unlock or panic
    let mut a = Attempts::default();
    for _ in 0..ATTEMPTS_PER_MIN {
        a.allow(100_000);
    }
    assert!(!a.allow(5));
}

#[test]
fn token_and_ap_name() {
    assert_eq!(token_hex(&[0xab; 16]), "abababababababababababababababab");
    assert_eq!(token_hex(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0xff]).len(), 32);
    assert_eq!(ap_name([0xe8, 0xf6, 0x0a, 0x4f, 0x1a, 0xdc]), "C3-DNS-1ADC");
}

#[test]
fn wifi_record_round_trips_and_rejects_damage() {
    use dnscore::setup::{decode_wifi, encode_wifi};
    let r = encode_wifi("Home Net", "secret pw").unwrap();
    assert_eq!(decode_wifi(&r), Some(("Home Net".to_string(), "secret pw".to_string())));
    let open = encode_wifi("Cafe", "").unwrap();
    assert_eq!(decode_wifi(&open), Some(("Cafe".to_string(), String::new())));
    assert!(encode_wifi("", "secret pw").is_none());
    assert!(encode_wifi(&"s".repeat(33), "secret pw").is_none());
    assert!(encode_wifi("x", "short").is_none());
    assert!(decode_wifi(&r[..r.len() - 1]).is_none());
    assert!(decode_wifi(&[r.as_slice(), b"x"].concat()).is_none());
    assert!(decode_wifi(&[]).is_none());
    assert!(decode_wifi(&[0, 0]).is_none(), "empty ssid");
    assert!(decode_wifi(&[2, 0xff, 0xfe, 0]).is_none(), "invalid UTF-8");
    assert!(decode_wifi(&[200, 1, 2]).is_none());
}
