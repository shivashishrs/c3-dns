//! Small pure timing rules used by the device: socket timeouts, upstream socket rotation and
//! the 0x20 fallback window. Time is supplied by the caller.

use std::time::Duration;

/// The read/write timeout to set with `left` remaining before a deadline, capped at `idle`.
///
/// `None` means the deadline has passed. lwIP converts a timeout to whole milliseconds and a
/// timeout of 0 means "wait forever", so anything under 1 ms counts as expired and every
/// returned value is a whole number of milliseconds, at least 1.
pub fn read_timeout_for(left: Duration, idle: Duration) -> Option<Duration> {
    let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
    if left_ms == 0 {
        return None;
    }
    let idle_ms = u64::try_from(idle.as_millis()).unwrap_or(u64::MAX);
    Some(Duration::from_millis(left_ms.min(idle_ms).max(1)))
}

/// The upstream socket is due for replacement at `next_at_ms`, or after `rotate_sends` sends.
pub fn rotation_due(now_ms: u64, next_at_ms: u64, sends: u32, rotate_sends: u32) -> bool {
    sends >= rotate_sends || now_ms >= next_at_ms
}

/// When the next rotation is due: `rotate_ms` after a successful one, or `retry_ms` after a
/// failed one (so a failing bind is retried every few seconds, not on every scan).
pub fn next_rotation_at(now_ms: u64, succeeded: bool, rotate_ms: u64, retry_ms: u64) -> u64 {
    now_ms.saturating_add(if succeeded { rotate_ms } else { retry_ms })
}

/// Per-upstream 0x20 fallback: an upstream that echoes the query name in a different case
/// `limit` times in a row gets 0x20 turned off. All state is forgotten every `period_ms`, so one
/// bad streak does not disable 0x20 until reboot. At most `cap` upstreams are tracked.
pub struct CaseFallback<A: PartialEq + Copy> {
    limit: u8,
    period_ms: u64,
    cap: usize,
    since: Option<u64>,
    /// (upstream, consecutive case-only mismatches, disabled)
    rows: Vec<(A, u8, bool)>,
}

impl<A: PartialEq + Copy> CaseFallback<A> {
    pub fn new(limit: u8, period_ms: u64, cap: usize) -> Self {
        Self { limit: limit.max(1), period_ms, cap: cap.max(1), since: None, rows: Vec::new() }
    }

    fn tick(&mut self, now_ms: u64) {
        match self.since {
            Some(s) if now_ms.saturating_sub(s) < self.period_ms => {}
            _ => {
                self.since = Some(now_ms);
                self.rows.clear();
            }
        }
    }

    /// Whether 0x20 is on for `a`.
    pub fn enabled(&mut self, a: A, now_ms: u64) -> bool {
        self.tick(now_ms);
        !self.rows.iter().any(|r| r.0 == a && r.2)
    }

    /// A reply from `a` matched exactly: its streak starts over.
    pub fn on_match(&mut self, a: A, now_ms: u64) {
        self.tick(now_ms);
        if let Some(r) = self.rows.iter_mut().find(|r| r.0 == a) {
            r.1 = 0;
        }
    }

    /// A case-only mismatch from `a`. True when this one turns 0x20 off for `a`.
    pub fn on_mismatch(&mut self, a: A, now_ms: u64) -> bool {
        self.tick(now_ms);
        let i = match self.rows.iter().position(|r| r.0 == a) {
            Some(i) => i,
            None => {
                if self.rows.len() >= self.cap {
                    self.rows.remove(0);
                }
                self.rows.push((a, 0, false));
                self.rows.len() - 1
            }
        };
        let r = &mut self.rows[i];
        if r.2 {
            return false;
        }
        r.1 = r.1.saturating_add(1);
        if r.1 >= self.limit {
            r.2 = true;
            return true;
        }
        false
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}
