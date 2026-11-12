//! Query admission: a per-client token bucket with a bounded client table, behind which sits
//! one global token bucket for all clients together.
//!
//! The per-client table is bounded (oldest entry evicted), so on its own it does not bound the
//! total: a LAN host rotating source addresses (IPv6 privacy addresses, spoofed IPv4) would get
//! a fresh full burst per address. Two things close that:
//! - once the table is full, a client new to it starts with only `NEW_CLIENT_BURST` tokens;
//! - `Admission` also takes a token from a global bucket (`GLOBAL_PER_SEC` sustained,
//!   `GLOBAL_BURST` burst), so all clients together never exceed what the device can queue.

use crate::engine::ClientKey;
use std::collections::{HashMap, VecDeque};

/// Tokens a client new to a full table starts with (instead of the full burst).
pub const NEW_CLIENT_BURST: u32 = 10;
/// Global admission defaults: every client together. A household's normal peak (a few
/// clients, ~30 q/s sustained, ~100 q/s bursts) stays well inside them.
pub const GLOBAL_BURST: u32 = 300;
pub const GLOBAL_PER_SEC: u32 = 150;
/// Upper bounds for an in-memory override of the global bucket.
pub const MAX_GLOBAL_BURST: u32 = 2000;
pub const MAX_GLOBAL_PER_SEC: u32 = 2000;

/// One token bucket in milli-tokens (1 token = 1000; `per_sec` tokens/s == `per_sec`
/// milli-tokens/ms). Starts full.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    burst_milli: u64,
    per_sec: u64,
    milli: u64,
    last_ms: Option<u64>,
}

impl TokenBucket {
    pub fn new(burst: u32, per_sec: u32) -> Self {
        Self::with_start(burst, per_sec, burst)
    }

    fn with_start(burst: u32, per_sec: u32, start: u32) -> Self {
        let burst_milli = burst as u64 * 1000;
        TokenBucket { burst_milli, per_sec: per_sec as u64, milli: (start as u64 * 1000).min(burst_milli), last_ms: None }
    }

    fn refill(&mut self, now_ms: u64) {
        // A clock that moves backwards yields elapsed == 0 and last_ms is kept.
        let last = *self.last_ms.get_or_insert(now_ms);
        let elapsed = now_ms.saturating_sub(last);
        if now_ms > last {
            self.last_ms = Some(now_ms);
        }
        self.milli = self.milli.saturating_add(elapsed.saturating_mul(self.per_sec)).min(self.burst_milli);
    }

    /// Takes one token if there is one.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        self.refill(now_ms);
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }

    /// Whole tokens available now (after refilling).
    pub fn available(&mut self, now_ms: u64) -> u32 {
        self.refill(now_ms);
        (self.milli / 1000).min(u32::MAX as u64) as u32
    }
}

pub struct RateLimiter {
    burst: u32,
    per_sec: u32,
    new_burst: u32,
    max_clients: usize,
    clients: HashMap<ClientKey, TokenBucket>,
    order: VecDeque<ClientKey>,
}

impl RateLimiter {
    /// `burst` tokens per client, refilled at `per_sec`; at most `max_clients` tracked. A
    /// client new to a full table starts with `min(NEW_CLIENT_BURST, burst)` tokens.
    pub fn new(burst: u32, per_sec: u32, max_clients: usize) -> Self {
        Self::with_new_client_burst(burst, per_sec, max_clients, NEW_CLIENT_BURST)
    }

    pub fn with_new_client_burst(burst: u32, per_sec: u32, max_clients: usize, new_burst: u32) -> Self {
        let max_clients = max_clients.max(1);
        RateLimiter {
            burst,
            per_sec,
            new_burst: new_burst.min(burst),
            max_clients,
            clients: HashMap::with_capacity(max_clients.min(1024)),
            order: VecDeque::with_capacity(max_clients.min(1024)),
        }
    }

    pub fn allow(&mut self, c: ClientKey, now_ms: u64) -> bool {
        if !self.clients.contains_key(&c) {
            let mut start = self.burst;
            while self.clients.len() >= self.max_clients {
                // The table is full: this client displaces another, so it gets the small burst.
                start = self.new_burst;
                match self.order.pop_front() {
                    Some(old) => {
                        self.clients.remove(&old);
                    }
                    None => break,
                }
            }
            self.order.push_back(c);
            self.clients.insert(c, TokenBucket::with_start(self.burst, self.per_sec, start));
        }
        match self.clients.get_mut(&c) {
            Some(b) => b.allow(now_ms),
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// This client is over its own rate.
    ClientLimited,
    /// All clients together are over the global rate.
    GlobalLimited,
}

/// Per-client limiter, then the global bucket. The per-client check comes first so that a
/// single flooding client, already refused by its own bucket, does not use up global tokens
/// that other clients need.
pub struct Admission {
    pub clients: RateLimiter,
    global: TokenBucket,
    global_burst: u32,
    global_per_sec: u32,
}

/// Whether a global-bucket override is within bounds (both at least 1).
pub fn global_rate_valid(burst: u32, per_sec: u32) -> bool {
    (1..=MAX_GLOBAL_BURST).contains(&burst) && (1..=MAX_GLOBAL_PER_SEC).contains(&per_sec)
}

impl Admission {
    /// Per-client `burst`/`per_sec` over `max_clients`, global bucket at the defaults.
    pub fn new(burst: u32, per_sec: u32, max_clients: usize) -> Self {
        Admission {
            clients: RateLimiter::new(burst, per_sec, max_clients),
            global: TokenBucket::new(GLOBAL_BURST, GLOBAL_PER_SEC),
            global_burst: GLOBAL_BURST,
            global_per_sec: GLOBAL_PER_SEC,
        }
    }

    pub fn check(&mut self, c: ClientKey, now_ms: u64) -> Verdict {
        if !self.clients.allow(c, now_ms) {
            return Verdict::ClientLimited;
        }
        if !self.global.allow(now_ms) {
            return Verdict::GlobalLimited;
        }
        Verdict::Allow
    }

    /// Replace the global bucket (in memory only, never persisted). Refused (false) when out
    /// of bounds (`global_rate_valid`).
    pub fn set_global(&mut self, burst: u32, per_sec: u32) -> bool {
        if !global_rate_valid(burst, per_sec) {
            return false;
        }
        self.global = TokenBucket::new(burst, per_sec);
        self.global_burst = burst;
        self.global_per_sec = per_sec;
        true
    }

    /// (burst, per_sec) of the global bucket.
    pub fn global_rate(&self) -> (u32, u32) {
        (self.global_burst, self.global_per_sec)
    }
}
