//! Build the common-blocklist image from hosts files and domain lists.
//!
//!     cargo run --release --example build_blocklist -- <out.bin> <list>...
//!
//! Each `<list>` is a local file (download it first, e.g. with curl). Accepted lines:
//! hosts entries (`0.0.0.0 ads.example`), bare domains (`ads.example`) and basic AdGuard rules
//! (`||ads.example^`; `@@||ok.example^` removes a domain). Other adblock syntax is skipped.
//!
//! Output: sorted, de-duplicated 40-bit FNV-1a hashes, 5 bytes each, little-endian, no header
//! (`dnscore::blocklist`). Write it to the `blocklist` partition with
//! `tools/flash-blocklist.sh`, or with the web installer / release images.

use std::process::exit;

use dnscore::listfile::ListSet;

/// The blocklist partition holds at most this many bytes (`firmware/partitions.csv`).
const PARTITION: usize = 0x1F_0000;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("usage: build_blocklist <out.bin> <list>...   (local hosts files / domain lists)");
        exit(2);
    }
    let (out, sources) = (&args[0], &args[1..]);
    let mut set = ListSet::default();
    for src in sources {
        let bytes = std::fs::read(src).unwrap_or_else(|e| {
            // Fail loudly: silently dropping a source shrinks the list without anyone noticing.
            eprintln!("  !! FAILED to read {src}: {e}");
            exit(1)
        });
        // Invalid UTF-8 is dropped, as the Python tool's errors='ignore' does.
        set.add(&String::from_utf8_lossy(&bytes).replace('\u{FFFD}', ""));
    }
    let removed = set.block.iter().filter(|d| set.allow.contains(*d)).count();
    if !set.allow.is_empty() {
        eprintln!("allowlisted      : {removed} removed ({} @@ rules)", set.allow.len());
    }
    if set.skipped > 0 {
        eprintln!("skipped rules    : {} (adblock syntax that a DNS hash list cannot express)", set.skipped);
    }
    let (blob, collisions) = set.image();
    if blob.len() > PARTITION {
        eprintln!("the list needs {} bytes, more than the {PARTITION}-byte partition", blob.len());
        exit(1);
    }
    std::fs::write(out, &blob).unwrap_or_else(|e| {
        eprintln!("cannot write {out}: {e}");
        exit(1)
    });
    println!("source domains   : {}", set.block.len() - removed);
    println!("hash entries     : {}  (5-byte / 40-bit)", blob.len() / 5);
    println!("collisions       : {collisions}  (domains sharing a hash -> over-block)");
    println!("flash blob       : {} bytes ({:.2} MB, {:.0}% of the partition) -> {out}",
        blob.len(), blob.len() as f64 / 1048576.0, blob.len() as f64 * 100.0 / PARTITION as f64);
}
