use dnscore::rules::{Match, RuleError, RuleKind, Rules};

fn rules() -> Rules {
    Rules::new(500)
}

#[test]
fn exact_matches_only_that_name() {
    let mut r = rules();
    r.add(RuleKind::Block, "example.com").unwrap();
    assert_eq!(r.matches("example.com"), Match::Block("example.com".into()));
    assert_eq!(r.matches("EXAMPLE.com."), Match::Block("example.com".into()));
    assert_eq!(r.matches("a.example.com"), Match::None);
}

#[test]
fn subtree_matches_domain_and_subdomains_not_lookalikes() {
    let mut r = rules();
    r.add(RuleKind::Block, "||example.com^").unwrap();
    for d in ["example.com", "a.b.example.com"] {
        assert_eq!(r.matches(d), Match::Block("||example.com^".into()), "{d}");
    }
    assert_eq!(r.matches("notexample.com"), Match::None);
    assert_eq!(r.matches("example.com.evil.org"), Match::None);
}

#[test]
fn glob_star_matches_across_dots() {
    let mut r = rules();
    r.add(RuleKind::Block, "*.ads.*").unwrap();
    assert_eq!(r.matches("x.ads.net"), Match::Block("*.ads.*".into()));
    assert_eq!(r.matches("a.b.ads.c.d"), Match::Block("*.ads.*".into()));
    assert_eq!(r.matches("ads.net"), Match::None);
}

#[test]
fn allow_beats_block_when_both_match() {
    let mut r = rules();
    r.add(RuleKind::Block, "||example.com^").unwrap();
    r.add(RuleKind::Allow, "ok.example.com").unwrap();
    assert_eq!(r.matches("ok.example.com"), Match::Allow("ok.example.com".into()));
    assert_eq!(r.matches("bad.example.com"), Match::Block("||example.com^".into()));
}

#[test]
fn rejects_empty_invalid_and_duplicate() {
    let mut r = rules();
    assert_eq!(r.add(RuleKind::Block, ""), Err(RuleError::Empty));
    assert_eq!(r.add(RuleKind::Block, "   "), Err(RuleError::Empty));
    assert_eq!(r.add(RuleKind::Block, "bad name.com"), Err(RuleError::Invalid));
    assert_eq!(r.add(RuleKind::Block, "||^"), Err(RuleError::Invalid));
    assert_eq!(r.add(RuleKind::Block, "*"), Err(RuleError::Invalid));
    assert_eq!(r.add(RuleKind::Block, "a..b"), Err(RuleError::Invalid));
    r.add(RuleKind::Block, "example.com").unwrap();
    assert_eq!(r.add(RuleKind::Block, "Example.com."), Err(RuleError::Duplicate));
    r.add(RuleKind::Allow, "example.com").unwrap();
    assert_eq!(r.len(), 2);
}

#[test]
fn enforces_the_cap() {
    let mut r = Rules::new(500);
    for i in 0..500 {
        r.add(RuleKind::Block, &format!("d{i}.example.com")).unwrap();
    }
    assert_eq!(r.add(RuleKind::Block, "one-more.example.com"), Err(RuleError::TooMany));
    assert_eq!(r.len(), 500);
    assert!(r.remove(RuleKind::Block, "d0.example.com"));
    assert!(!r.remove(RuleKind::Block, "d0.example.com"));
    r.add(RuleKind::Block, "one-more.example.com").unwrap();
    assert_eq!(r.list().len(), 500);
}

#[test]
fn glob_is_canonicalised_like_exact() {
    let mut r = rules();
    r.add(RuleKind::Block, "ADS.*.Example.COM.").unwrap();
    assert_eq!(r.list(), vec![(RuleKind::Block, "ads.*.example.com".to_string())]);
    assert_eq!(r.matches("ads.x.example.com"), Match::Block("ads.*.example.com".into()));
    assert_eq!(r.add(RuleKind::Block, "ads.*.example.com"), Err(RuleError::Duplicate));
    assert!(r.remove(RuleKind::Block, "ADS.*.example.com."));
    assert!(r.is_empty());
}

#[test]
fn glob_length_and_star_caps() {
    let mut r = rules();
    let ok = format!("{}*", "a".repeat(127));
    assert_eq!(ok.len(), 128);
    r.add(RuleKind::Block, &ok).unwrap();
    let long = format!("{}*", "a".repeat(128));
    assert_eq!(r.add(RuleKind::Block, &long), Err(RuleError::Invalid));
    r.add(RuleKind::Block, "*.a*.b*.c*.d*.e*.f*.g*").unwrap(); // 8 stars
    assert_eq!(r.add(RuleKind::Block, "*.a*.b*.c*.d*.e*.f*.g*.h*"), Err(RuleError::Invalid));
    assert_eq!(r.add(RuleKind::Block, "*"), Err(RuleError::Invalid));
    assert_eq!(r.add(RuleKind::Block, "*."), Err(RuleError::Invalid));
}
