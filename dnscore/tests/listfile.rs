use dnscore::blocklist::{hash40, BlockList};
use dnscore::listfile::{norm, ListSet};

fn set(text: &str) -> ListSet {
    let mut s = ListSet::default();
    s.add(text);
    s
}

fn names(s: &ListSet) -> Vec<&str> {
    s.domains().map(String::as_str).collect()
}

#[test]
fn hosts_lines_and_bare_domains() {
    let s = set("# header\n0.0.0.0 ads.example tracker.example\n127.0.0.1 localhost\n\
                 ::1 ip6-localhost\nsolo.example # comment\ntwo words.example\nnodot\n");
    assert_eq!(names(&s), ["ads.example", "solo.example", "tracker.example"]);
}

#[test]
fn normalises_case_wildcards_dots_and_www() {
    assert_eq!(norm(" *.WWW.Foo.Example. "), "foo.example");
    assert_eq!(norm("www.bar.example"), "bar.example");
    let s = set("0.0.0.0 www.Foo.example.\n*.wild.example\n");
    // A `*` line is adblock syntax, so only the hosts entry counts.
    assert_eq!(names(&s), ["foo.example"]);
    assert_eq!(s.skipped, 1);
}

#[test]
fn adguard_rules_block_allow_and_skip_modifiers() {
    let s = set("||Ads.Example.COM^\n||ok.example^\n@@||ok.example^\n||mod.example^$client=1\n\
                 |http://x\nweird^thing\n!comment\n/regex/\n[Adblock Plus]\n");
    assert_eq!(names(&s), ["ads.example.com"]);
    assert_eq!(s.skipped, 3);
}

#[test]
fn allow_rules_apply_across_lists() {
    let mut s = ListSet::default();
    s.add("@@||ok.example^\n");
    s.add("0.0.0.0 ok.example bad.example\n");
    assert_eq!(names(&s), ["bad.example"]);
}

#[test]
fn image_is_sorted_unique_five_byte_little_endian_and_searchable() {
    let s = set("a.example\nb.example\nc.example\nb.example\n");
    let (blob, collisions) = s.image();
    assert_eq!((blob.len(), collisions), (15, 0));
    let recs: Vec<u64> = blob
        .chunks(5)
        .map(|c| {
            let mut b = [0u8; 8];
            b[..5].copy_from_slice(c);
            u64::from_le_bytes(b)
        })
        .collect();
    assert!(recs.windows(2).all(|w| w[0] < w[1]));
    assert!(recs.contains(&hash40("b.example")));
    let list = BlockList::new(&blob[..]);
    assert_eq!(list.contains("ads.b.example").as_deref(), Some("b.example"));
    assert_eq!(list.contains("d.example"), None);
}
