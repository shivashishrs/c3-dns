//! Persistence format (hand-written binary, CRC32-protected) and save policy.
//!
//! Layout: magic `C3DS`, version byte, payload length (u32 LE), payload,
//! CRC32 (u32 LE) over everything before it. Pause state is never stored.

use crate::engine::ClientKey;
use crate::name::normalize;
use crate::rules::{RuleKind, Rules};
use crate::stats::{clip_point, DailySummary, CLIP_MARK};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAGIC: &[u8; 4] = b"C3DS";
const VERSION: u8 = 1;
const HEADER: usize = 9;

pub const MAX_RULES: usize = 500;
pub const MAX_RECORDS: usize = 100;
pub const MAX_RECORD_IPS: usize = 8;
pub const MAX_BANS: usize = 64;
pub const MAX_UPSTREAMS: usize = 8;
pub const MAX_SUMMARIES: usize = 7;
pub const MAX_TOP: usize = 16;
pub const MAX_STR: usize = 253;
pub const MAX_LOG_CAP: usize = 2000;
pub const MAX_CACHE_CAP: usize = 1000;
pub const MAX_STALE_SECS: u32 = 7 * 86_400;
/// Upper bounds of the per-client rate settings (a typo or a lifted debug value must not
/// turn the limiter off). Larger stored values are clamped to these on load and save.
pub const MAX_RATE_BURST: u32 = 1000;
pub const MAX_RATE_PER_SEC: u32 = 1000;

/// RAM budget of the whole encoded blob (header + payload + CRC), and so of one save.
///
/// A save allocates one buffer of exactly the encoded size, at most this much. To stay
/// within it the oldest daily summaries are dropped, then the newest one's top lists cut;
/// the owner's rules, records, bans and settings are never trimmed (over budget, the save is
/// refused instead). Idle free heap on the device is ~110 KB and the floor under load 30 KB.
pub const BLOB_BUDGET: usize = 24 * 1024;

const DEFAULT_UPSTREAMS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
];
const DEFAULT_LOCAL_NAME: &str = "adblock.home";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub upstreams: Vec<IpAddr>,
    pub rate_burst: u32,
    pub rate_per_sec: u32,
    pub stale_secs: u32,
    pub local_name: String,
    pub log_cap: usize,
    pub cache_cap: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            upstreams: DEFAULT_UPSTREAMS.to_vec(),
            rate_burst: 50,
            rate_per_sec: 20,
            stale_secs: 21600,
            local_name: DEFAULT_LOCAL_NAME.to_string(),
            log_cap: 500,
            cache_cap: 300,
        }
    }
}

/// Suffixes the device's own name may live under: names that never exist in public DNS.
/// The engine answers the own name before pause, allow and block rules, so a public name
/// (say `google.com`) would hijack it for every client.
pub const PRIVATE_SUFFIXES: [&str; 4] = ["home.arpa", "home", "lan", "internal"];
/// Labels allowed in front of the suffix (`adblock.home`: 1; `dns.office.lan`: 2).
pub const MAX_LOCAL_LABELS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNameError {
    /// Not a host name (letters, digits and inner hyphens; labels of 1 to 63 characters).
    Invalid,
    /// Not under one of `PRIVATE_SUFFIXES`.
    NotPrivate,
    /// More than `MAX_LOCAL_LABELS` labels in front of the suffix.
    TooDeep,
}

impl LocalNameError {
    pub fn message(self) -> &'static str {
        match self {
            LocalNameError::Invalid => {
                "The local name must be a host name: letters, digits and hyphens, separated by dots."
            }
            LocalNameError::NotPrivate => {
                "The local name must end in .home, .lan, .internal or .home.arpa (for example adblock.home)."
            }
            LocalNameError::TooDeep => "The local name may have at most two labels before its suffix (a.b.home).",
        }
    }
}

/// The device's own-name policy: a host name under a private suffix with at most two labels
/// in front of it. Returns the normalised (lower-case, no trailing dot) name.
pub fn check_local_name(n: &str) -> Result<String, LocalNameError> {
    let n = normalize(n).ok_or(LocalNameError::Invalid)?;
    let ldh = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    if !n.split('.').all(ldh) {
        return Err(LocalNameError::Invalid);
    }
    let front = PRIVATE_SUFFIXES
        .iter()
        .find_map(|s| n.strip_suffix(s).and_then(|f| f.strip_suffix('.')))
        .ok_or(LocalNameError::NotPrivate)?;
    if front.split('.').count() > MAX_LOCAL_LABELS {
        return Err(LocalNameError::TooDeep);
    }
    Ok(n)
}

fn local_name_ok(n: &str) -> bool {
    n.len() <= MAX_STR && check_local_name(n).is_ok()
}

/// The name rule before the private-suffix policy: what an older save may hold. `decode`
/// still loads such a blob (the rest of it is good); the device then replaces the name
/// (`persist::sanitize_local_name`).
fn local_name_loadable(n: &str) -> bool {
    n.len() <= MAX_STR && normalize(n).is_some()
}

/// Every bound except the local name.
fn bounds_ok(s: &Settings) -> bool {
    !s.upstreams.is_empty()
        && s.upstreams.len() <= MAX_UPSTREAMS
        && (1..=MAX_RATE_BURST).contains(&s.rate_burst)
        && (1..=MAX_RATE_PER_SEC).contains(&s.rate_per_sec)
        && s.log_cap <= MAX_LOG_CAP
        && s.cache_cap <= MAX_CACHE_CAP
        && s.stale_secs <= MAX_STALE_SECS
}

/// Whether `s` is within every bound, the local-name policy included (what the UI may set).
pub fn settings_valid(s: &Settings) -> bool {
    bounds_ok(s) && local_name_ok(&s.local_name)
}

/// The default own name.
pub fn default_local_name() -> &'static str {
    DEFAULT_LOCAL_NAME
}

/// `s` with every field brought within its bounds (what `encode` stores).
pub fn clamp_settings(s: &Settings) -> Settings {
    let mut upstreams = s.upstreams.clone();
    upstreams.truncate(MAX_UPSTREAMS);
    if upstreams.is_empty() {
        upstreams = DEFAULT_UPSTREAMS.to_vec();
    }
    let local_name = if local_name_ok(&s.local_name) { s.local_name.clone() } else { DEFAULT_LOCAL_NAME.to_string() };
    Settings {
        upstreams,
        rate_burst: s.rate_burst.clamp(1, MAX_RATE_BURST),
        rate_per_sec: s.rate_per_sec.clamp(1, MAX_RATE_PER_SEC),
        stale_secs: s.stale_secs.min(MAX_STALE_SECS),
        local_name,
        log_cap: s.log_cap.min(MAX_LOG_CAP),
        cache_cap: s.cache_cap.min(MAX_CACHE_CAP),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Persisted {
    pub rules: Vec<(RuleKind, String)>,
    pub records: Vec<(String, Vec<IpAddr>)>,
    pub bans: Vec<ClientKey>,
    pub settings: Settings,
    pub summaries: Vec<DailySummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    Corrupt,
    UnknownVersion,
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreError;

pub trait Store {
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError>;
    fn save(&mut self, bytes: &[u8]) -> Result<(), StoreError>;
}

/// CRC32 (IEEE, reflected 0xEDB88320) table, built at compile time: a table-driven CRC keeps
/// the save path short (it runs while the device holds its state lock).
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Running CRC32 state update (start with `!0`, finish with `^ !0`).
pub(crate) fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

// ---- encoding ----

/// What `try_encode` reads. `Persisted` implements it (host tools, tests), and so does the
/// device's live state (`persist::Live`), which lets a save encode straight from the engine
/// without first cloning everything.
///
/// The visitor methods must yield the same items, in the same order, every time they are
/// called: the encoder walks them once to size the blob and once to write it.
pub trait Source {
    /// Rules to store. Each must be a valid pattern and unique (the decoder rejects the whole
    /// blob otherwise); the encoder only skips over-long ones and caps the count.
    fn rules(&self, f: &mut dyn FnMut(RuleKind, &str));
    /// Local records to store (name already normalised, at least one address).
    fn records(&self, f: &mut dyn FnMut(&str, &[IpAddr]));
    fn bans(&self) -> &[ClientKey];
    fn settings(&self) -> &Settings;
    /// Oldest first.
    fn summaries(&self) -> &[DailySummary];
}

impl Source for Persisted {
    /// Arbitrary input: drop invalid, duplicate and over-long rules (host side only, so the
    /// check's allocations do not matter).
    fn rules(&self, f: &mut dyn FnMut(RuleKind, &str)) {
        let mut check = Rules::new(MAX_RULES);
        for (k, pat) in &self.rules {
            if pat.len() <= MAX_STR && check.add(*k, pat).is_ok() {
                f(*k, pat);
            }
        }
    }

    fn records(&self, f: &mut dyn FnMut(&str, &[IpAddr])) {
        for (n, ips) in &self.records {
            if n.len() <= MAX_STR && !ips.is_empty() && normalize(n).as_deref() == Some(n.as_str()) {
                f(n, ips);
            }
        }
    }

    fn bans(&self) -> &[ClientKey] {
        &self.bans
    }

    fn settings(&self) -> &Settings {
        &self.settings
    }

    fn summaries(&self) -> &[DailySummary] {
        &self.summaries
    }
}

/// Byte sink: the encoder runs once into a counter (sizing) and once into the output.
trait Sink {
    fn put(&mut self, b: &[u8]);
}

struct Count(usize);

impl Sink for Count {
    fn put(&mut self, b: &[u8]) {
        self.0 += b.len();
    }
}

impl Sink for Vec<u8> {
    fn put(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

fn put_u8(o: &mut impl Sink, v: u8) {
    o.put(&[v]);
}

fn put_u16(o: &mut impl Sink, v: usize) {
    o.put(&(v as u16).to_le_bytes());
}

fn put_u32(o: &mut impl Sink, v: u32) {
    o.put(&v.to_le_bytes());
}

/// Length byte + bytes, clipped at a char boundary to `MAX_STR`.
fn put_str(o: &mut impl Sink, s: &str) {
    let mut end = s.len().min(MAX_STR);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    put_u8(o, end as u8);
    o.put(&s.as_bytes()[..end]);
}

/// A summary name, clipped exactly as `stats::clip_summary_name` does (no allocation).
fn put_summary_name(o: &mut impl Sink, s: &str) {
    match clip_point(s) {
        None => put_str(o, s),
        Some(end) => {
            put_u8(o, (end + CLIP_MARK.len()) as u8);
            o.put(&s.as_bytes()[..end]);
            o.put(CLIP_MARK.as_bytes());
        }
    }
}

fn put_ip(o: &mut impl Sink, ip: &IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            put_u8(o, 4);
            o.put(&a.octets());
        }
        IpAddr::V6(a) => {
            put_u8(o, 6);
            o.put(&a.octets());
        }
    }
}

/// Rules, records and bans: the owner's data, never trimmed to fit the budget.
fn write_user(src: &dyn Source, o: &mut impl Sink) {
    let mut n = 0usize;
    src.rules(&mut |_, p| {
        if p.len() <= MAX_STR && n < MAX_RULES {
            n += 1;
        }
    });
    put_u16(o, n);
    let mut k = 0usize;
    src.rules(&mut |kind, p| {
        if p.len() <= MAX_STR && k < n {
            k += 1;
            put_u8(o, match kind {
                RuleKind::Allow => 0,
                RuleKind::Block => 1,
            });
            put_str(o, p);
        }
    });
    let mut n = 0usize;
    src.records(&mut |name, ips| {
        if name.len() <= MAX_STR && !ips.is_empty() && n < MAX_RECORDS {
            n += 1;
        }
    });
    put_u16(o, n);
    let mut k = 0usize;
    src.records(&mut |name, ips| {
        if name.len() <= MAX_STR && !ips.is_empty() && k < n {
            k += 1;
            put_str(o, name);
            let ips = &ips[..ips.len().min(MAX_RECORD_IPS)];
            put_u8(o, ips.len() as u8);
            for ip in ips {
                put_ip(o, ip);
            }
        }
    });
    let bans = src.bans();
    let bans = &bans[..bans.len().min(MAX_BANS)];
    put_u8(o, bans.len() as u8);
    for b in bans {
        match b {
            ClientKey::V4(a) => put_ip(o, &IpAddr::V4(*a)),
            ClientKey::V6(a) => put_ip(o, &IpAddr::V6(*a)),
        }
    }
}

/// Settings, clamped field by field like `clamp_settings` (without building a copy).
fn write_settings(s: &Settings, o: &mut impl Sink) {
    let ups: &[IpAddr] = if s.upstreams.is_empty() { &DEFAULT_UPSTREAMS } else { &s.upstreams };
    let ups = &ups[..ups.len().min(MAX_UPSTREAMS)];
    put_u8(o, ups.len() as u8);
    for ip in ups {
        put_ip(o, ip);
    }
    put_u32(o, s.rate_burst.clamp(1, MAX_RATE_BURST));
    put_u32(o, s.rate_per_sec.clamp(1, MAX_RATE_PER_SEC));
    put_u32(o, s.stale_secs.min(MAX_STALE_SECS));
    if local_name_ok(&s.local_name) {
        put_str(o, &s.local_name);
    } else {
        put_str(o, DEFAULT_LOCAL_NAME);
    }
    put_u32(o, s.log_cap.min(MAX_LOG_CAP) as u32);
    put_u32(o, s.cache_cap.min(MAX_CACHE_CAP) as u32);
}

/// One day; each top list keeps at most `cap` entries, names clipped to `SUMMARY_NAME_MAX`.
fn write_summary(d: &DailySummary, cap: usize, o: &mut impl Sink) {
    put_u32(o, d.day);
    put_u32(o, d.allowed);
    put_u32(o, d.blocked);
    for t in [&d.top_queried, &d.top_blocked] {
        let t = &t[..t.len().min(cap).min(MAX_TOP)];
        put_u8(o, t.len() as u8);
        for (n, c) in t {
            put_summary_name(o, n);
            put_u32(o, *c);
        }
    }
}

fn summary_len(d: &DailySummary, cap: usize) -> usize {
    let mut c = Count(0);
    write_summary(d, cap, &mut c);
    c.0
}

/// A successful encode.
#[derive(Debug)]
pub struct Encoded {
    /// The blob: header, payload, CRC. Never longer than the budget it was encoded with.
    pub bytes: Vec<u8>,
    /// Oldest daily summaries left out to stay within the budget.
    pub dropped_summaries: usize,
    /// Top-list entries cut from the newest summary (only when it alone did not fit).
    pub trimmed_top_entries: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The owner's rules, records, bans and settings alone need `needed` bytes, over the
    /// budget. Nothing is trimmed from them: the save is refused (the previous one stays).
    OverBudget { needed: usize },
    /// The output buffer (`needed` bytes) could not be allocated: skip this save.
    NoMemory { needed: usize },
}

/// What fits in a budget: computed by `plan` without allocating anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Exact length of the blob `encode_planned` will produce (header, payload, CRC).
    pub total: usize,
    /// Index (into the newest `MAX_SUMMARIES` summaries) of the oldest one kept.
    first: usize,
    newest_cap: usize,
    trimmed: usize,
}

/// Size the blob for `src` within `budget` (no allocation).
///
/// To fit, the oldest daily summaries are dropped first; if even the newest one alone does
/// not fit, its top lists are cut. Rules, records, bans and settings are never trimmed: if they
/// alone exceed the budget the result is `OverBudget`.
pub fn plan(src: &dyn Source, budget: usize) -> Result<Plan, EncodeError> {
    let mut fixed = Count(HEADER + 4 + 1); // header, CRC, summary count
    write_user(src, &mut fixed);
    write_settings(src.settings(), &mut fixed);
    let fixed = fixed.0;
    if fixed > budget {
        return Err(EncodeError::OverBudget { needed: fixed });
    }
    let room = budget - fixed;
    let all = src.summaries();
    let sums = &all[all.len().saturating_sub(MAX_SUMMARIES)..];
    // Keep the newest days that fit whole.
    let mut first = sums.len();
    let mut used = 0usize;
    while first > 0 {
        let l = summary_len(&sums[first - 1], MAX_TOP);
        if used + l > room {
            break;
        }
        used += l;
        first -= 1;
    }
    // Not even the newest day fits whole: keep it with shorter top lists if that fits.
    let mut newest_cap = MAX_TOP;
    let mut trimmed = 0usize;
    if first == sums.len() {
        if let Some(newest) = sums.last() {
            let full: usize = newest.top_queried.len().min(MAX_TOP) + newest.top_blocked.len().min(MAX_TOP);
            if let Some(cap) = (0..MAX_TOP).rev().find(|&cap| summary_len(newest, cap) <= room) {
                first = sums.len() - 1;
                newest_cap = cap;
                used = summary_len(newest, cap);
                trimmed = full - (newest.top_queried.len().min(cap) + newest.top_blocked.len().min(cap));
            }
        }
    }
    Ok(Plan { total: fixed + used, first, newest_cap, trimmed })
}

/// Encode `src` as `plan` (made from the same, unchanged `src`) says, into one buffer of
/// exactly `plan.total` bytes. The allocation is fallible (`try_reserve_exact`): a short heap
/// yields `NoMemory` instead of an out-of-memory abort.
pub fn encode_planned(src: &dyn Source, plan: &Plan) -> Result<Encoded, EncodeError> {
    let Plan { total, first, newest_cap, trimmed } = *plan;
    let all = src.summaries();
    let sums = &all[all.len().saturating_sub(MAX_SUMMARIES)..];
    let kept = sums.get(first..).unwrap_or(&[]);
    let mut out: Vec<u8> = Vec::new();
    if out.try_reserve_exact(total).is_err() {
        return Err(EncodeError::NoMemory { needed: total });
    }
    out.put(MAGIC);
    put_u8(&mut out, VERSION);
    put_u32(&mut out, (total - HEADER - 4) as u32);
    write_user(src, &mut out);
    write_settings(src.settings(), &mut out);
    put_u8(&mut out, kept.len() as u8);
    for (i, d) in kept.iter().enumerate() {
        let cap = if i + 1 == kept.len() { newest_cap } else { MAX_TOP };
        write_summary(d, cap, &mut out);
    }
    let crc = crc32(&out);
    put_u32(&mut out, crc);
    // The sizing pass and the writing pass share every write function, so this holds; if a
    // `Source` broke its contract (different items per call), refuse rather than store junk.
    if out.len() != total {
        return Err(EncodeError::OverBudget { needed: out.len() });
    }
    Ok(Encoded { bytes: out, dropped_summaries: all.len() - kept.len(), trimmed_top_entries: trimmed })
}

/// `plan` then `encode_planned`: one exactly sized, fallibly allocated buffer of at most
/// `budget` bytes (see both).
pub fn try_encode(src: &dyn Source, budget: usize) -> Result<Encoded, EncodeError> {
    encode_planned(src, &plan(src, budget)?)
}

/// `try_encode` with `BLOB_BUDGET`, for host tools and tests. Empty (which decodes as
/// `Warning::Empty`) if the owner's data alone is over budget or memory is short.
pub fn encode(p: &Persisted) -> Vec<u8> {
    try_encode(p, BLOB_BUDGET).map(|e| e.bytes).unwrap_or_default()
}

// ---- decoding ----

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn str(&mut self) -> Option<String> {
        let n = self.u8()? as usize;
        if n > MAX_STR {
            return None;
        }
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    fn ip(&mut self) -> Option<IpAddr> {
        match self.u8()? {
            4 => {
                let b = self.take(4)?;
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            6 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(self.take(16)?);
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        }
    }
    /// Reads a count and checks it against `max` and, given each element needs
    /// at least `min_elem` bytes, against the bytes remaining (before any allocation).
    fn count(&mut self, wide: bool, max: usize, min_elem: usize) -> Option<usize> {
        let n = if wide { self.u16()? as usize } else { self.u8()? as usize };
        if n > max || n.checked_mul(min_elem)? > self.0.len() {
            return None;
        }
        Some(n)
    }
    fn top(&mut self) -> Option<Vec<(String, u32)>> {
        let n = self.count(false, MAX_TOP, 5)?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let s = self.str()?;
            v.push((s, self.u32()?));
        }
        Some(v)
    }
}

fn parse(payload: &[u8]) -> Option<Persisted> {
    let mut r = Reader(payload);
    let n = r.count(true, MAX_RULES, 2)?;
    let mut check = Rules::new(MAX_RULES);
    let mut rules = Vec::with_capacity(n);
    for _ in 0..n {
        let kind = match r.u8()? {
            0 => RuleKind::Allow,
            1 => RuleKind::Block,
            _ => return None,
        };
        let pat = r.str()?;
        check.add(kind, &pat).ok()?;
        rules.push((kind, pat));
    }
    let n = r.count(true, MAX_RECORDS, 2)?;
    let mut records = Vec::with_capacity(n);
    for _ in 0..n {
        let name = r.str()?;
        normalize(&name)?;
        let k = r.count(false, MAX_RECORD_IPS, 5)?;
        if k == 0 {
            return None;
        }
        let mut ips = Vec::with_capacity(k);
        for _ in 0..k {
            ips.push(r.ip()?);
        }
        records.push((name, ips));
    }
    let n = r.count(false, MAX_BANS, 5)?;
    let mut bans = Vec::with_capacity(n);
    for _ in 0..n {
        bans.push(match r.ip()? {
            IpAddr::V4(a) => ClientKey::V4(a),
            IpAddr::V6(a) => ClientKey::V6(a),
        });
    }
    let n = r.count(false, MAX_UPSTREAMS, 5)?;
    let mut upstreams = Vec::with_capacity(n);
    for _ in 0..n {
        upstreams.push(r.ip()?);
    }
    // Rates above the bounds (a blob saved by a build without them, e.g. after a lifted debug
    // rate) are clamped rather than rejected: the rest of the blob is still good.
    let rate_burst = r.u32()?.min(MAX_RATE_BURST);
    let rate_per_sec = r.u32()?.min(MAX_RATE_PER_SEC);
    let stale_secs = r.u32()?;
    let local_name = r.str()?;
    let log_cap = r.u32()? as usize;
    let cache_cap = r.u32()? as usize;
    let settings = Settings { upstreams, rate_burst, rate_per_sec, stale_secs, local_name, log_cap, cache_cap };
    if !bounds_ok(&settings) || !local_name_loadable(&settings.local_name) {
        return None;
    }
    let n = r.count(false, MAX_SUMMARIES, 14)?;
    let mut summaries = Vec::with_capacity(n);
    for _ in 0..n {
        let day = r.u32()?;
        let allowed = r.u32()?;
        let blocked = r.u32()?;
        let top_queried = r.top()?;
        let top_blocked = r.top()?;
        summaries.push(DailySummary { day, allowed, blocked, top_queried, top_blocked });
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(Persisted {
        rules,
        records,
        bans,
        settings,
        summaries,
    })
}

/// Never fails: bad input yields defaults plus a warning.
pub fn decode(b: &[u8]) -> (Persisted, Option<Warning>) {
    let bad = |w| (Persisted::default(), Some(w));
    if b.is_empty() {
        return bad(Warning::Empty);
    }
    if b.len() < HEADER + 4 || &b[..4] != MAGIC {
        return bad(Warning::Corrupt);
    }
    if b[4] != VERSION {
        return bad(Warning::UnknownVersion);
    }
    let len = u32::from_le_bytes([b[5], b[6], b[7], b[8]]) as usize;
    if len != b.len() - HEADER - 4 {
        return bad(Warning::Corrupt);
    }
    let (body, crc) = b.split_at(HEADER + len);
    if crc32(body) != u32::from_le_bytes([crc[0], crc[1], crc[2], crc[3]]) {
        return bad(Warning::Corrupt);
    }
    match parse(&body[HEADER..]) {
        Some(p) => (p, None),
        None => bad(Warning::Corrupt),
    }
}

// ---- save policy ----

pub struct Saver {
    min_interval_secs: u32,
    max_per_day: u32,
    last: Option<u64>,
    day: u64,
    count: u32,
}

impl Saver {
    pub fn new(min_interval_secs: u32, max_per_day: u32) -> Self {
        Self { min_interval_secs, max_per_day, last: None, day: 0, count: 0 }
    }

    /// Records the save when it returns true.
    pub fn should_save(&mut self, dirty: bool, now_secs: u64) -> bool {
        if !dirty {
            return false;
        }
        if let Some(l) = self.last {
            // A backwards clock jump counts as the interval having elapsed.
            if now_secs >= l && now_secs - l < self.min_interval_secs as u64 {
                return false;
            }
        }
        let day = now_secs / 86_400;
        // Only a forward day change resets the budget; the marker never moves
        // back, so an oscillating clock cannot earn extra saves.
        if day > self.day {
            self.day = day;
            self.count = 0;
        }
        if self.count >= self.max_per_day {
            return false;
        }
        self.count += 1;
        self.last = Some(now_secs);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::crc32;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
