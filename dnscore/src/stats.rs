//! Bounded statistics: top lists (Space-Saving), query log, client table, daily summaries.
//! No clock here: timestamps arrive in `LogEntry::ts`, the day number in `roll_day`.

use crate::engine::ClientKey;
use std::collections::VecDeque;

/// Longest name kept (a parsed DNS name is at most 253 bytes).
pub const MAX_NAME: usize = 253;

fn clip(name: &str) -> String {
    if name.len() <= MAX_NAME {
        return name.to_string();
    }
    let mut end = MAX_NAME;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

/// Space-Saving heavy hitters with at most `k` counters.
pub struct HeavyHitters {
    k: usize,
    items: Vec<(String, u32)>,
}

impl HeavyHitters {
    pub fn new(k: usize) -> Self {
        Self { k, items: Vec::with_capacity(k.min(1024)) }
    }

    pub fn offer(&mut self, name: &str) {
        if self.k == 0 {
            return;
        }
        let name = clip(name);
        if let Some(it) = self.items.iter_mut().find(|(n, _)| *n == name) {
            it.1 = it.1.saturating_add(1);
        } else if self.items.len() < self.k {
            self.items.push((name, 1));
        } else if let Some(min) = self.items.iter_mut().min_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))) {
            // replace the minimum counter; the newcomer inherits its count + 1
            min.1 = min.1.saturating_add(1);
            min.0 = name;
        }
    }

    /// Sorted by count descending, ties by name ascending.
    pub fn top(&self, n: usize) -> Vec<(String, u32)> {
        let mut v = self.items.clone();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Slot indexes in `top` order (count descending, ties by name), without copying names.
    pub fn order(&self) -> Vec<u16> {
        let mut idx: Vec<u16> = (0..self.items.len().min(u16::MAX as usize) as u16).collect();
        // Unstable sort: no scratch buffer. The stable sort (driftsort) puts a ~4 KB buffer on
        // the stack, which overflowed the device's HTTP task. Names are unique within a list,
        // so the name tie-break makes the order total and deterministic anyway.
        idx.sort_unstable_by(|&a, &b| {
            let (x, y) = (&self.items[a as usize], &self.items[b as usize]);
            y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0))
        });
        idx
    }

    /// The name and count in slot `i` (see `order`).
    pub fn slot(&self, i: u16) -> Option<(&str, u32)> {
        self.items.get(i as usize).map(|(n, c)| (n.as_str(), *c))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub ts: u64,
    pub client: ClientKey,
    pub name: String,
    pub qtype: u16,
    pub blocked: bool,
    pub reason: String,
}

/// Ring of the newest `cap` entries.
pub struct QueryLog {
    cap: usize,
    items: VecDeque<LogEntry>,
    /// Entries pushed since construction: the newest entry has seq `pushed - 1`.
    pushed: u64,
}

impl QueryLog {
    pub fn new(cap: usize) -> Self {
        Self { cap, items: VecDeque::with_capacity(cap.min(1024)), pushed: 0 }
    }

    pub fn push(&mut self, mut e: LogEntry) {
        if self.cap == 0 {
            return;
        }
        self.pushed += 1;
        e.name = clip(&e.name);
        e.reason = clip(&e.reason);
        if self.items.len() >= self.cap {
            self.items.pop_front();
        }
        self.items.push_back(e);
    }

    /// Up to `n` entries, newest first.
    pub fn recent(&self, n: usize) -> Vec<&LogEntry> {
        self.items.iter().rev().take(n).collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// One past the seq of the newest entry (0 when nothing was ever logged).
    pub fn end_seq(&self) -> u64 {
        self.pushed
    }

    /// The entry with sequence number `seq`, if it is still held. A reader that walks seqs
    /// downwards from `end_seq()` (re-locking between entries) sees each entry at most once,
    /// newest first, however many arrive meanwhile.
    pub fn by_seq(&self, seq: u64) -> Option<&LogEntry> {
        let first = self.pushed - self.items.len() as u64;
        if seq < first || seq >= self.pushed {
            return None;
        }
        self.items.get((seq - first) as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRow {
    pub client: ClientKey,
    pub allowed: u32,
    pub blocked: u32,
}

impl ClientRow {
    fn activity(&self) -> u64 {
        self.allowed as u64 + self.blocked as u64
    }
}

pub struct Clients {
    max: usize,
    rows: Vec<ClientRow>,
}

impl Clients {
    pub fn new(max: usize) -> Self {
        Self { max, rows: Vec::with_capacity(max.min(256)) }
    }

    pub fn record(&mut self, c: ClientKey, blocked: bool) {
        let bump = |r: &mut ClientRow| {
            if blocked {
                r.blocked = r.blocked.saturating_add(1);
            } else {
                r.allowed = r.allowed.saturating_add(1);
            }
        };
        if let Some(r) = self.rows.iter_mut().find(|r| r.client == c) {
            bump(r);
            return;
        }
        if self.max == 0 {
            return;
        }
        let mut row = ClientRow { client: c, allowed: 0, blocked: 0 };
        bump(&mut row);
        if self.rows.len() < self.max {
            self.rows.push(row);
        } else if let Some(min) = self.rows.iter_mut().min_by_key(|r| r.activity()) {
            *min = row;
        }
    }

    pub fn rows(&self) -> Vec<ClientRow> {
        self.rows.clone()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Row `i` (table order), copied.
    pub fn row(&self, i: usize) -> Option<ClientRow> {
        self.rows.get(i).copied()
    }

    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StatsCaps {
    pub log_cap: usize,
    pub top_k: usize,
    pub clients_max: usize,
}

impl Default for StatsCaps {
    fn default() -> Self {
        Self { log_cap: 500, top_k: 100, clients_max: 64 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DailySummary {
    pub day: u32,
    pub allowed: u32,
    pub blocked: u32,
    pub top_queried: Vec<(String, u32)>,
    pub top_blocked: Vec<(String, u32)>,
}

pub const SUMMARY_TOP: usize = 10;

/// Longest name kept in a `DailySummary` top list (bytes). Summaries are persisted for 7
/// days: at the full 253 bytes, 7 x 20 names held ~39 KB of RAM and made every save copy it.
pub const SUMMARY_NAME_MAX: usize = 64;
/// Appended to a clipped summary name. Not valid in a DNS name, so a clipped name is visibly
/// clipped and can never be turned into a rule that matches something else.
pub const CLIP_MARK: &str = "\u{2026}";

/// Where `name` is cut when clipped for a summary: `None` if it fits in `SUMMARY_NAME_MAX`,
/// else the byte length of the kept prefix (a char boundary; prefix + `CLIP_MARK` fits).
pub fn clip_point(name: &str) -> Option<usize> {
    if name.len() <= SUMMARY_NAME_MAX {
        return None;
    }
    let mut end = SUMMARY_NAME_MAX - CLIP_MARK.len();
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    Some(end)
}

/// `name` clipped to at most `SUMMARY_NAME_MAX` bytes (prefix + `CLIP_MARK`). Idempotent.
pub fn clip_summary_name(name: &str) -> String {
    match clip_point(name) {
        None => name.to_string(),
        Some(end) => {
            // Exact capacity: these strings are kept for 7 days (`format!` may over-reserve).
            let mut s = String::with_capacity(end + CLIP_MARK.len());
            s.push_str(&name[..end]);
            s.push_str(CLIP_MARK);
            s
        }
    }
}

/// A top list ready for a summary: names clipped, entries whose clipped names collide merged,
/// sorted by count descending (ties by name), at most `SUMMARY_TOP` entries.
pub fn summary_top(items: &[(String, u32)]) -> Vec<(String, u32)> {
    let mut v: Vec<(String, u32)> = Vec::with_capacity(items.len().min(SUMMARY_TOP * 2));
    for (n, c) in items {
        let n = clip_summary_name(n);
        match v.iter_mut().find(|(m, _)| *m == n) {
            Some((_, x)) => *x = x.saturating_add(*c),
            None => v.push((n, *c)),
        }
    }
    v.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    v.truncate(SUMMARY_TOP);
    v.shrink_to_fit(); // kept for 7 days: do not hold the merge's spare capacity
    v
}

pub struct Stats {
    log: QueryLog,
    queried: HeavyHitters,
    blocked_top: HeavyHitters,
    clients: Clients,
    day: Option<u32>,
    day_allowed: u32,
    day_blocked: u32,
    total_allowed: u64,
    total_blocked: u64,
}

impl Stats {
    pub fn new(cfg: StatsCaps) -> Self {
        Self {
            log: QueryLog::new(cfg.log_cap),
            queried: HeavyHitters::new(cfg.top_k),
            blocked_top: HeavyHitters::new(cfg.top_k),
            clients: Clients::new(cfg.clients_max),
            day: None,
            day_allowed: 0,
            day_blocked: 0,
            total_allowed: 0,
            total_blocked: 0,
        }
    }

    pub fn record(&mut self, e: LogEntry) {
        self.clients.record(e.client, e.blocked);
        if e.blocked {
            self.blocked_top.offer(&e.name);
            self.day_blocked = self.day_blocked.saturating_add(1);
            self.total_blocked = self.total_blocked.saturating_add(1);
        } else {
            self.queried.offer(&e.name);
            self.day_allowed = self.day_allowed.saturating_add(1);
            self.total_allowed = self.total_allowed.saturating_add(1);
        }
        self.log.push(e);
    }

    /// Top allowed (non-blocked) names.
    pub fn top_queried(&self, n: usize) -> Vec<(String, u32)> {
        self.queried.top(n)
    }

    pub fn top_blocked(&self, n: usize) -> Vec<(String, u32)> {
        self.blocked_top.top(n)
    }

    /// Slot order of the allowed (`blocked == false`) or blocked top list; see `top_slot`.
    pub fn top_order(&self, blocked: bool) -> Vec<u16> {
        if blocked {
            self.blocked_top.order()
        } else {
            self.queried.order()
        }
    }

    /// One slot of a top list, for streaming it entry by entry. Between calls (with the lock
    /// released) a slot may be taken over by another name: the reply is then slightly stale.
    pub fn top_slot(&self, blocked: bool, i: u16) -> Option<(&str, u32)> {
        if blocked {
            self.blocked_top.slot(i)
        } else {
            self.queried.slot(i)
        }
    }

    pub fn log(&self) -> &QueryLog {
        &self.log
    }

    pub fn clients(&self) -> &Clients {
        &self.clients
    }

    /// Lifetime (allowed, blocked) since construction; not reset by `roll_day`.
    pub fn totals(&self) -> (u64, u64) {
        (self.total_allowed, self.total_blocked)
    }

    /// On a day change returns the previous day's summary and resets the
    /// per-day counters, tops and client table. `None` on first call or same day.
    /// A day number smaller than the current one (clock stepped back) is
    /// ignored: returns `None` and keeps the counters and the current day.
    pub fn roll_day(&mut self, day: u32) -> Option<DailySummary> {
        if self.day.is_some_and(|p| day < p) {
            return None;
        }
        let prev = self.day.replace(day);
        match prev {
            Some(p) if p != day => {
                let s = DailySummary {
                    day: p,
                    allowed: self.day_allowed,
                    blocked: self.day_blocked,
                    top_queried: summary_top(&self.queried.top(SUMMARY_TOP)),
                    top_blocked: summary_top(&self.blocked_top.top(SUMMARY_TOP)),
                };
                self.day_allowed = 0;
                self.day_blocked = 0;
                self.queried.clear();
                self.blocked_top.clear();
                self.clients.clear();
                Some(s)
            }
            _ => None,
        }
    }
}
