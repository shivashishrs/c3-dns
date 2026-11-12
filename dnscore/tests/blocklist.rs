use dnscore::blocklist::{hash40, BlockList};

fn blob(names: &[String]) -> Vec<u8> {
    let mut h: Vec<u64> = names.iter().map(|n| hash40(n)).collect();
    h.sort_unstable();
    h.dedup();
    h.iter().flat_map(|x| x.to_le_bytes()[..5].to_vec()).collect()
}

fn list(names: &[&str]) -> BlockList<Vec<u8>> {
    let v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    BlockList::new(blob(&v))
}

#[test]
fn hash_matches_known_vectors() {
    // computed with fnv() from the old tools/build_blocklist.py
    assert_eq!(hash40("doubleclick.net"), 0xcd127775cd);
    assert_eq!(hash40("example.com"), 0x634e2714c6);
    assert_eq!(hash40("ads.example.com"), 0x58979aa55e);
    assert_eq!(hash40("a.b"), 0x190466522c);
}

#[test]
fn contains_matches_domain_and_parents_not_lookalikes() {
    let l = list(&["example.com"]);
    assert_eq!(l.contains("example.com").as_deref(), Some("example.com"));
    assert_eq!(l.contains("ads.example.com").as_deref(), Some("example.com"));
    assert_eq!(l.contains("A.B.Example.COM.").as_deref(), Some("example.com"));
    assert_eq!(l.contains("notexample.com"), None);
    assert_eq!(l.contains("com"), None);
}

#[test]
fn www_prefix_is_ignored() {
    let l = list(&["example.com"]);
    assert_eq!(l.contains("www.example.com").as_deref(), Some("example.com"));
    assert_eq!(l.contains("www.other.com"), None);
}

#[test]
fn finds_every_entry_of_a_sorted_blob_and_none_of_absent_names() {
    let names: Vec<String> = (0..1000).map(|i| format!("host{i}.tracker.test")).collect();
    let l = BlockList::new(blob(&names));
    assert_eq!(l.len(), 1000);
    for n in &names {
        assert_eq!(l.contains(n).as_deref(), Some(n.as_str()), "{n}");
    }
    for i in 0..1000 {
        assert_eq!(l.contains(&format!("absent{i}.clean.example")), None);
    }
}

#[test]
fn unsorted_or_truncated_blob_never_panics() {
    let junk: Vec<u8> = (0..1003u32).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
    let l = BlockList::new(junk);
    assert_eq!(l.len(), 200);
    let _ = l.contains("example.com");
    let _ = l.contains("");
    let _ = l.contains("a..b");
    assert_eq!(BlockList::new(Vec::<u8>::new()).contains("example.com"), None);
    assert_eq!(BlockList::new(vec![1u8, 2, 3, 4]).len(), 0);
    assert_eq!(BlockList::new(vec![1u8, 2, 3, 4]).contains("example.com"), None);
}

#[test]
fn real_list_blocks_a_known_tracker() {
    let Ok(p) = std::env::var("C3DNS_BLOCKLIST_BIN") else {
        eprintln!("skipped: C3DNS_BLOCKLIST_BIN not set");
        return;
    };
    let Ok(data) = std::fs::read(&p) else {
        eprintln!("skipped: {p} not present");
        return;
    };
    let l = BlockList::new(data);
    assert!(l.len() > 100_000);
    assert!(l.contains("doubleclick.net").is_some());
    assert!(l.contains("stats.doubleclick.net").is_some());
    assert!(l.contains("example.org").is_none());
}

#[test]
fn www_com_reduces_to_com_not_to_itself() {
    // Current behaviour, documented: a leading "www." is stripped before the
    // lookup, so "www.com" is looked up as "com" (never as "www.com").
    let only_com = list(&["com"]);
    assert_eq!(only_com.contains("www.com").as_deref(), Some("com"));
    let only_www_com = list(&["www.com"]);
    assert_eq!(only_www_com.contains("www.com"), None);
    assert_eq!(only_www_com.contains("com"), None);
    let neither = list(&["example.com"]);
    assert_eq!(neither.contains("www.com"), None);
}

// ---- Task 6: erased partition tail ----

#[test]
fn used_len_stops_at_the_erased_tail() {
    use dnscore::blocklist::used_len;
    let mut blob: Vec<u8> = Vec::new();
    for h in [1u64, 5, 9, 1 << 39] {
        blob.extend_from_slice(&h.to_le_bytes()[..5]);
    }
    let real = blob.len();
    blob.extend(std::iter::repeat_n(0xFF, 5 * 7 + 3)); // erased records + partial
    assert_eq!(used_len(&blob), real);
    assert_eq!(used_len(&blob[..real]), real);
    assert_eq!(used_len(&[0xFF; 50]), 0);
    assert_eq!(used_len(&[]), 0);
    assert_eq!(used_len(&[1, 2, 3]), 0, "partial record only");
}
