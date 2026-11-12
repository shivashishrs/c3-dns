//! Bounded response cache with serve-stale. Time is supplied by the caller.
//! Bounded by entry count and by total bytes; a response over [`MAX_ENTRY_BYTES`] is
//! never stored.

use crate::wire::{age_ttls, Response};
use std::collections::{HashMap, VecDeque};

/// Largest response the cache stores (the classic UDP DNS limit).
pub const MAX_ENTRY_BYTES: usize = 512;
/// Bookkeeping charged per entry on top of the response and name bytes.
const ENTRY_OVERHEAD: usize = 64;

/// Whether an upstream answer (`len` bytes) may be cached now: never while blocking is
/// paused (it would bypass uncloaking after resume), never truncated, oversized, an error
/// other than NXDOMAIN, or with a zero TTL.
pub fn cacheable(r: &Response, len: usize, paused: bool) -> bool {
    !paused && !r.truncated && len <= MAX_ENTRY_BYTES && (r.rcode == 0 || r.rcode == 3) && r.min_ttl > 0
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Fresh(Vec<u8>),
    Stale(Vec<u8>),
    Miss,
}

struct Entry {
    resp: Vec<u8>,
    stored: u64,
    expires: u64,
}

pub struct Cache {
    cap: usize,
    max_stale_secs: u32,
    max_bytes: usize,
    bytes: usize,
    map: HashMap<CacheKey, Entry>,
    order: VecDeque<CacheKey>,
}

fn cost(k: &CacheKey, resp_len: usize) -> usize {
    resp_len + k.name.len() + ENTRY_OVERHEAD
}

impl Cache {
    pub fn new(cap: usize, max_stale_secs: u32) -> Self {
        Self::with_budget(cap, max_stale_secs, usize::MAX)
    }

    /// Like `new`, and the stored entries never cost more than `max_bytes` in total
    /// (response + name + a fixed per-entry overhead).
    pub fn with_budget(cap: usize, max_stale_secs: u32, max_bytes: usize) -> Self {
        Cache {
            cap,
            max_stale_secs,
            max_bytes,
            bytes: 0,
            map: HashMap::with_capacity(cap.min(1024)),
            order: VecDeque::with_capacity(cap.min(1024)),
        }
    }

    pub fn get(&mut self, k: &CacheKey, now_secs: u64) -> Lookup {
        let (resp, stored, expires) = match self.map.get(k) {
            Some(e) => (&e.resp, e.stored, e.expires),
            None => return Lookup::Miss,
        };
        if now_secs < expires {
            let mut out = resp.clone();
            let age = now_secs.saturating_sub(stored).min(u32::MAX as u64) as u32;
            age_ttls(&mut out, age);
            return Lookup::Fresh(out);
        }
        if now_secs - expires <= self.max_stale_secs as u64 {
            return Lookup::Stale(resp.clone());
        }
        self.remove(k);
        Lookup::Miss
    }

    fn remove(&mut self, k: &CacheKey) {
        if let Some(e) = self.map.remove(k) {
            self.bytes = self.bytes.saturating_sub(cost(k, e.resp.len()));
        }
        self.order.retain(|x| x != k);
    }

    pub fn put(&mut self, k: CacheKey, resp: Vec<u8>, min_ttl: u32, now_secs: u64) {
        let c = cost(&k, resp.len());
        if self.cap == 0 || resp.len() > MAX_ENTRY_BYTES || c > self.max_bytes {
            return;
        }
        self.remove(&k);
        while self.map.len() >= self.cap || self.bytes + c > self.max_bytes {
            match self.order.pop_front() {
                Some(old) => {
                    if let Some(e) = self.map.remove(&old) {
                        self.bytes = self.bytes.saturating_sub(cost(&old, e.resp.len()));
                    }
                }
                None => break,
            }
        }
        let entry = Entry { resp, stored: now_secs, expires: now_secs.saturating_add(min_ttl as u64) };
        self.bytes += c;
        self.order.push_back(k.clone());
        self.map.insert(k, entry);
    }

    /// Bytes currently charged against the budget.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
