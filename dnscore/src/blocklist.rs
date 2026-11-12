//! The common blocklist: a sorted blob of 40-bit name hashes (5 bytes each, little-endian,
//! no header), binary-searched in place. Compatible with the old `build_blocklist.py`.

use crate::name::normalize;

const REC: usize = 5;
const MASK: u64 = (1 << 40) - 1;

/// FNV-1a 64 over the bytes, truncated to the low 40 bits.
pub fn hash40(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h & MASK
}

/// Bytes of whole records before the erased (all-0xFF) tail of a flash partition.
/// The list is sorted and an erased record compares greater than any real 40-bit hash,
/// so the boundary is found by binary search.
pub fn used_len(blob: &[u8]) -> usize {
    let erased = |i: usize| blob.get(i * REC..i * REC + REC).is_none_or(|r| r.iter().all(|&b| b == 0xFF));
    let (mut lo, mut hi) = (0usize, blob.len() / REC);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if erased(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo * REC
}

pub struct BlockList<B: AsRef<[u8]>> {
    blob: B,
}

impl<B: AsRef<[u8]>> BlockList<B> {
    pub fn new(blob: B) -> Self {
        Self { blob }
    }

    /// Number of whole records; a trailing partial record is ignored.
    pub fn len(&self) -> usize {
        self.blob.as_ref().len() / REC
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn has(&self, h: u64) -> bool {
        let data = self.blob.as_ref();
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let Some(rec) = data.get(mid * REC..mid * REC + REC) else {
                return false;
            };
            let mut b = [0u8; 8];
            b[..REC].copy_from_slice(rec);
            let v = u64::from_le_bytes(b);
            match v.cmp(&h) {
                core::cmp::Ordering::Equal => return true,
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }

    /// The listed name matching `domain` (the domain itself or its first listed parent),
    /// with any leading `www.` ignored.
    pub fn contains(&self, domain: &str) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let n = normalize(domain)?;
        let mut cand: &str = &n;
        loop {
            let key = cand.strip_prefix("www.").filter(|s| !s.is_empty()).unwrap_or(cand);
            if self.has(hash40(key)) {
                return Some(key.to_string());
            }
            cand = cand.split_once('.')?.1;
        }
    }
}
