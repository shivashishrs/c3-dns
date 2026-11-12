//! Web UI authentication helpers: the HTTP Basic header parser, a small cache of verified
//! Authorization headers (so the ~0.5 s PBKDF2 check runs once per session, not per request)
//! and the failed-login lockout with a global verification budget.
//!
//! The cache stores only a digest (SHA-256, computed by the caller) of the exact header value,
//! never the password. The KDF and the digest function live in the firmware.

use crate::auth::ct_eq;
use crate::engine::ClientKey;
use crate::secret::{wipe_vec, Secret};

/// Longest Authorization header value accepted (bytes). Fits user `admin` and a password of
/// 128 four-byte characters, base64-encoded, with the scheme.
pub const MAX_AUTH_HEADER: usize = 768;
/// Verified headers remembered at once.
pub const SESSION_SLOTS: usize = 4;
/// A remembered header is forgotten after this long without use.
pub const SESSION_IDLE_MS: u64 = 10 * 60 * 1000;
/// Failed checks from one client before it is locked out.
pub const MAX_FAILURES: u32 = 5;
/// How long a lockout lasts.
pub const LOCKOUT_MS: u64 = 60 * 1000;
/// Clients tracked for lockout (the oldest is forgotten when full).
pub const LOCKOUT_CLIENTS: usize = 16;
/// Password checks (successful or not) per minute for all clients together: bounds the CPU a
/// flood of logins from rotating addresses can take (each check is ~0.5 s on the C3).
pub const GLOBAL_VERIFY_PER_MIN: u32 = 12;
const WINDOW_MS: u64 = 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BasicError {
    /// Not of the form `Basic <base64>`.
    NotBasic,
    TooLong,
    BadBase64,
    /// The decoded value has no `user:password` colon.
    NoColon,
    /// Not UTF-8, or contains control characters.
    BadUtf8,
}

/// Decoded Basic credentials. No `Debug`: it holds a password (wiped when dropped, best effort).
pub struct Credentials {
    pub user: String,
    pub password: Secret,
}

fn b64_val(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Standard base64 (RFC 4648, with padding, canonical: unused bits must be zero). The output
/// is allocated once; on a refusal the bytes decoded so far are wiped.
pub fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    if b64_into(s, &mut out).is_none() {
        wipe_vec(&mut out);
        return None;
    }
    Some(out)
}

fn b64_into(s: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let quads = s.len() / 4;
    for (qi, q) in s.chunks(4).enumerate() {
        let last = qi + 1 == quads;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &q[..4 - pad] {
            n = (n << 6) | b64_val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        // Canonical form: the bits below the last kept byte are zero.
        if bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(())
}

/// Parse an `Authorization: Basic ...` header value. The user is everything before the
/// first colon, the password everything after it.
pub fn parse_basic(h: &str) -> Result<Credentials, BasicError> {
    if h.len() > MAX_AUTH_HEADER {
        return Err(BasicError::TooLong);
    }
    let t = h.trim_matches(|c| c == ' ' || c == '\t');
    let (scheme, rest) = t.split_once([' ', '\t']).ok_or(BasicError::NotBasic)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(BasicError::NotBasic);
    }
    let mut raw = base64_decode(rest.trim_start_matches([' ', '\t']).as_bytes()).ok_or(BasicError::BadBase64)?;
    let r = credentials(&raw);
    // The decoded `user:password` bytes are wiped on every path (best effort: httpd's own copy
    // of the header is not ours to wipe).
    wipe_vec(&mut raw);
    r
}

fn credentials(raw: &[u8]) -> Result<Credentials, BasicError> {
    let s = std::str::from_utf8(raw).map_err(|_| BasicError::BadUtf8)?;
    if s.chars().any(char::is_control) {
        return Err(BasicError::BadUtf8);
    }
    let (user, password) = s.split_once(':').ok_or(BasicError::NoColon)?;
    Ok(Credentials { user: user.to_string(), password: Secret::from(password) })
}

#[derive(Clone, Copy)]
struct Slot {
    digest: [u8; 32],
    last_ms: u64,
}

/// Digests of recently verified Authorization headers.
#[derive(Default)]
pub struct SessionCache {
    slots: [Option<Slot>; SESSION_SLOTS],
}

impl SessionCache {
    fn expire(&mut self, now_ms: u64) {
        for s in &mut self.slots {
            if s.is_some_and(|x| now_ms.saturating_sub(x.last_ms) > SESSION_IDLE_MS) {
                *s = None;
            }
        }
    }

    /// True if `digest` was verified and has been used within `SESSION_IDLE_MS`; refreshes
    /// it. Every slot is compared (constant time each, no early exit).
    pub fn check(&mut self, digest: &[u8; 32], now_ms: u64) -> bool {
        self.expire(now_ms);
        let mut hit = None;
        for (i, s) in self.slots.iter().enumerate() {
            if let Some(x) = s {
                if ct_eq(&x.digest, digest) {
                    hit = Some(i);
                }
            }
        }
        match hit.and_then(|i| self.slots[i].as_mut()) {
            Some(x) => {
                x.last_ms = now_ms;
                true
            }
            None => false,
        }
    }

    /// Remember a freshly verified digest (replacing the least recently used one when full).
    pub fn insert(&mut self, digest: [u8; 32], now_ms: u64) {
        self.expire(now_ms);
        if self.check(&digest, now_ms) {
            return;
        }
        let i = match self.slots.iter().position(Option::is_none) {
            Some(i) => i,
            None => (0..SESSION_SLOTS).min_by_key(|&i| self.slots[i].map_or(0, |x| x.last_ms)).unwrap_or(0),
        };
        self.slots[i] = Some(Slot { digest, last_ms: now_ms });
    }

    /// Forget everything (password changed or cleared).
    pub fn clear(&mut self) {
        self.slots = [None; SESSION_SLOTS];
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Whether a password check may run now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    Ok,
    /// This client failed `MAX_FAILURES` times and is locked out.
    Locked { retry_after_secs: u32 },
    /// The global budget of checks for this minute is used up.
    Busy { retry_after_secs: u32 },
}

#[derive(Clone, Copy)]
struct Entry {
    client: ClientKey,
    fails: u32,
    locked_until: u64,
    last: u64,
}

/// Per-client failure counting and lockout, plus the global check budget.
#[derive(Default)]
pub struct Lockout {
    clients: Vec<Entry>,
    window_start: u64,
    window_count: u32,
}

fn secs_until(t: u64, now: u64) -> u32 {
    u32::try_from(t.saturating_sub(now).div_ceil(1000)).unwrap_or(u32::MAX).max(1)
}

impl Lockout {
    /// Seconds left if `c` is locked out now.
    pub fn locked(&self, c: ClientKey, now_ms: u64) -> Option<u32> {
        self.clients
            .iter()
            .find(|e| e.client == c && now_ms < e.locked_until)
            .map(|e| secs_until(e.locked_until, now_ms))
    }

    /// Call before each password check: refuses a locked-out client, then takes one check
    /// from the global budget (`GLOBAL_VERIFY_PER_MIN` per minute).
    pub fn before_verify(&mut self, c: ClientKey, now_ms: u64) -> Gate {
        if let Some(s) = self.locked(c, now_ms) {
            return Gate::Locked { retry_after_secs: s };
        }
        if self.window_count == 0 || now_ms.saturating_sub(self.window_start) >= WINDOW_MS {
            self.window_start = now_ms;
            self.window_count = 0;
        }
        if self.window_count >= GLOBAL_VERIFY_PER_MIN {
            return Gate::Busy { retry_after_secs: secs_until(self.window_start + WINDOW_MS, now_ms) };
        }
        self.window_count += 1;
        Gate::Ok
    }

    /// Count a failed check; true if `c` is now locked out.
    pub fn failed(&mut self, c: ClientKey, now_ms: u64) -> bool {
        let i = match self.clients.iter().position(|e| e.client == c) {
            Some(i) => i,
            None => {
                let e = Entry { client: c, fails: 0, locked_until: 0, last: now_ms };
                if self.clients.len() < LOCKOUT_CLIENTS {
                    self.clients.push(e);
                    self.clients.len() - 1
                } else {
                    let i = (0..self.clients.len()).min_by_key(|&i| self.clients[i].last).unwrap_or(0);
                    self.clients[i] = e;
                    i
                }
            }
        };
        let e = &mut self.clients[i];
        // A lockout that has run out, or an old streak, starts a fresh count.
        if (e.locked_until != 0 && now_ms >= e.locked_until) || now_ms.saturating_sub(e.last) > 10 * LOCKOUT_MS {
            e.fails = 0;
            e.locked_until = 0;
        }
        e.last = now_ms;
        e.fails = e.fails.saturating_add(1);
        if e.fails >= MAX_FAILURES {
            e.locked_until = now_ms + LOCKOUT_MS;
            true
        } else {
            false
        }
    }

    /// A successful check clears the client's failures.
    pub fn succeeded(&mut self, c: ClientKey) {
        self.clients.retain(|e| e.client != c);
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}
