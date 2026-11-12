//! Building the common-blocklist image (`crate::blocklist`) from hosts files and domain lists.
//! Host-side only (used by `examples/build_blocklist.rs`); the firmware never calls it.
//!
//! Ported from `tools/build_blocklist.py` of esp32-c3-adblock (MIT,
//! https://github.com/M-Abozaid/esp32-c3-adblock); byte-for-byte compatible with its output.

use std::collections::BTreeSet;

use crate::blocklist::hash40;

const REC: usize = 5;

/// Domains to block and to allow (removed from the block set by [`ListSet::image`]).
#[derive(Default)]
pub struct ListSet {
    pub block: BTreeSet<String>,
    pub allow: BTreeSet<String>,
    /// Adblock rules that a DNS hash list cannot express.
    pub skipped: usize,
}

/// Lower-case, drop leading `*` and `.`, trailing `.`, and a leading `www.`.
pub fn norm(d: &str) -> String {
    let d = d.trim().to_lowercase();
    let d = d.trim_start_matches('*').trim_start_matches('.').trim_end_matches('.');
    d.strip_prefix("www.").unwrap_or(d).to_string()
}

/// `||domain^` or `@@||domain^`, optionally followed by `$modifiers`:
/// Some((allow, domain, has_modifiers)).
fn adguard(line: &str) -> Option<(bool, &str, bool)> {
    let (allow, rest) = match line.strip_prefix("@@") {
        Some(r) => (true, r),
        None => (false, line),
    };
    let rest = rest.strip_prefix("||")?;
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    let (domain, tail) = rest.split_at(end);
    let tail = tail.strip_prefix('^').unwrap_or(tail);
    if tail.is_empty() {
        Some((allow, domain, false))
    } else if tail.starts_with('$') {
        Some((allow, domain, true))
    } else {
        None
    }
}

impl ListSet {
    /// Add one list's text: hosts entries, bare domains and basic AdGuard rules.
    pub fn add(&mut self, text: &str) {
        for raw in text.lines() {
            let t = raw.trim_start();
            let line = if t.starts_with("||") || t.starts_with("@@") {
                raw.trim()
            } else {
                raw.split('#').next().unwrap_or("").trim()
            };
            if line.is_empty() || line.starts_with(['!', '/', '[']) {
                continue;
            }
            if let Some((is_allow, d, modifiers)) = adguard(line) {
                if modifiers {
                    self.skipped += 1; // client/dnstype/... modifiers cannot be expressed
                } else if is_allow {
                    self.allow.insert(norm(d));
                } else {
                    self.block.insert(norm(d));
                }
                continue;
            }
            if line.starts_with('|') || line.starts_with("@@") || line.contains(['^', '$', '*']) {
                self.skipped += 1; // other adblock syntax (regex, wildcards, cosmetic)
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            let entries: &[&str] = match parts.first() {
                Some(&("0.0.0.0" | "127.0.0.1" | "::1" | "::")) => &parts[1..],
                _ if parts.len() == 1 => &parts[..],
                _ => &[],
            };
            for d in entries {
                let d = norm(d);
                if d.contains('.') && !d.contains(' ') {
                    self.block.insert(d);
                }
            }
        }
    }

    /// Blocked domains minus allowed ones.
    pub fn domains(&self) -> impl Iterator<Item = &String> {
        self.block.iter().filter(|d| !self.allow.contains(*d))
    }

    /// The image: sorted, de-duplicated 40-bit hashes, 5 bytes little-endian each, plus the
    /// number of domains that collided with another one's hash.
    pub fn image(&self) -> (Vec<u8>, usize) {
        let mut n = 0usize;
        let uniq: BTreeSet<u64> = self.domains().inspect(|_| n += 1).map(|d| hash40(d)).collect();
        let mut blob = Vec::with_capacity(uniq.len() * REC);
        for h in &uniq {
            blob.extend_from_slice(&h.to_le_bytes()[..REC]);
        }
        (blob, n - uniq.len())
    }
}
