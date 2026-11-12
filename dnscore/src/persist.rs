//! Device persistence policy, kept here so it is host-tested: plausible wall-clock time, the
//! save gate (time, read-only, interval/budget), dirty tracking, daily summaries, validation
//! of owner-entered rules/records, and moving state between `Persisted` and the `Engine`.

use crate::engine::{ClientKey, Engine};
use crate::name::normalize;
use crate::rules::{canonical, RuleError, RuleKind};
use crate::stats::{summary_top, DailySummary};
use crate::store::{Persisted, Saver, Settings, Source, MAX_RECORD_IPS, MAX_STR, MAX_SUMMARIES};
use std::net::IpAddr;

/// 2026-01-01T00:00:00Z. A clock reading before this has not been set (SNTP not synced).
pub const PLAUSIBLE_MIN_UNIX: u64 = 1_767_225_600;
/// 2100-01-01T00:00:00Z. A reading at or after this is bogus; trusting it would pin the
/// `Saver`'s day marker (it never moves back) and stop all saves until reboot.
pub const PLAUSIBLE_MAX_UNIX: u64 = 4_102_444_800;

pub fn plausible(unix_secs: u64) -> bool {
    (PLAUSIBLE_MIN_UNIX..PLAUSIBLE_MAX_UNIX).contains(&unix_secs)
}

/// Unix day number (the `Stats::roll_day` / `DailySummary::day` unit).
pub fn day_of(unix_secs: u64) -> u32 {
    (unix_secs / 86_400).min(u32::MAX as u64) as u32
}

/// `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian, UTC).
pub fn utc_string(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil-from-days (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveDecision {
    /// Write now.
    Save,
    /// Dirty, but the interval or the daily budget says wait.
    NotDue,
    /// Nothing changed (and not forced).
    Clean,
    /// No trustworthy wall-clock time yet: nothing is saved before SNTP.
    NoTime,
    /// The stored blob came from a newer firmware: never overwrite it.
    ReadOnly,
}

/// Wraps `Saver` so it only ever sees plausible time, and adds read-only and forced saves.
pub struct SaveGate {
    saver: Saver,
    read_only: bool,
}

impl SaveGate {
    pub fn new(min_interval_secs: u32, max_per_day: u32) -> Self {
        Self { saver: Saver::new(min_interval_secs, max_per_day), read_only: false }
    }

    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// `now` is `None` until the clock has been synced. `force` skips the interval and the
    /// budget (debug only) but never read-only or the time check.
    ///
    /// Forced saves are outside the daily budget: they are neither counted against the
    /// `max_per_day` saves nor do they restart the interval, so each one is an extra flash
    /// write on top of the budget. A future UI "save now" that must respect the wear budget
    /// has to go through the unforced path instead.
    pub fn decide(&mut self, dirty: bool, now: Option<u64>, force: bool) -> SaveDecision {
        if self.read_only {
            return SaveDecision::ReadOnly;
        }
        let Some(now) = now.filter(|t| plausible(*t)) else {
            return SaveDecision::NoTime;
        };
        if force {
            return SaveDecision::Save;
        }
        if !dirty {
            return SaveDecision::Clean;
        }
        if self.saver.should_save(true, now) {
            SaveDecision::Save
        } else {
            SaveDecision::NotDue
        }
    }
}

/// Change generations: a snapshot remembers the generation it was taken at, and only that
/// generation is marked saved, so a change made while the write is in progress stays dirty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dirty {
    gen: u64,
    saved: u64,
}

impl Dirty {
    pub fn mark(&mut self) {
        self.gen += 1;
    }

    pub fn is_dirty(&self) -> bool {
        self.gen != self.saved
    }

    pub fn generation(&self) -> u64 {
        self.gen
    }

    /// The snapshot taken at generation `gen` has been written.
    pub fn saved(&mut self, gen: u64) {
        self.saved = self.saved.max(gen.min(self.gen));
    }
}

fn merge_tops(a: &[(String, u32)], b: &[(String, u32)]) -> Vec<(String, u32)> {
    let mut all = a.to_vec();
    all.extend_from_slice(b);
    summary_top(&all)
}

/// Add a finished day. A day already present (the device rebooted that day) is merged into
/// it. Keeps the `MAX_SUMMARIES` newest days, oldest first. Top-list names are clipped to
/// `stats::SUMMARY_NAME_MAX` (also for summaries loaded from an older save), each list keeps
/// at most `SUMMARY_TOP` entries.
pub fn push_summary(v: &mut Vec<DailySummary>, mut s: DailySummary) {
    if let Some(e) = v.iter_mut().find(|e| e.day == s.day) {
        e.allowed = e.allowed.saturating_add(s.allowed);
        e.blocked = e.blocked.saturating_add(s.blocked);
        e.top_queried = merge_tops(&e.top_queried, &s.top_queried);
        e.top_blocked = merge_tops(&e.top_blocked, &s.top_blocked);
    } else {
        s.top_queried = summary_top(&s.top_queried);
        s.top_blocked = summary_top(&s.top_blocked);
        v.push(s);
    }
    v.sort_by_key(|e| e.day);
    while v.len() > MAX_SUMMARIES {
        v.remove(0);
    }
}

/// The own-name policy (`store::check_local_name`) applied to settings loaded from an older
/// save: a non-conforming name is replaced by the default. Returns a warning for the UI then.
pub fn sanitize_local_name(s: &mut Settings) -> Option<String> {
    if crate::store::check_local_name(&s.local_name).is_ok() {
        return None;
    }
    let def = crate::store::default_local_name();
    let w = format!(
        "The stored local name {:?} is not under .home, .lan, .internal or .home.arpa: using {def} instead.",
        s.local_name
    );
    s.local_name = def.to_string();
    Some(w)
}

/// Validate a rule before adding it (owner input). Returns the canonical text. Rejects what
/// `store::encode` would silently drop (canonical text longer than `MAX_STR`).
pub fn check_rule(_kind: RuleKind, pattern: &str) -> Result<String, RuleError> {
    let c = canonical(pattern)?;
    if c.len() > MAX_STR {
        return Err(RuleError::Invalid);
    }
    Ok(c)
}

/// Validate a local record before setting it. Returns the normalised name.
pub fn check_record(name: &str, ips: &[IpAddr]) -> Result<String, RuleError> {
    let n = normalize(name).ok_or(RuleError::Invalid)?;
    if n.len() > MAX_STR {
        return Err(RuleError::Invalid);
    }
    if ips.is_empty() {
        return Err(RuleError::Empty);
    }
    if ips.len() > MAX_RECORD_IPS {
        return Err(RuleError::TooMany);
    }
    Ok(n)
}

/// Load stored rules, records and bans into a fresh engine. Items the engine refuses (over
/// its caps, duplicate, invalid) are dropped and counted; never panics.
pub fn load_into<B: AsRef<[u8]>>(p: &Persisted, e: &mut Engine<B>) -> u32 {
    let mut dropped = 0u32;
    for (k, pat) in &p.rules {
        if check_rule(*k, pat).is_err() || e.rules_mut().add(*k, pat).is_err() {
            dropped += 1;
        }
    }
    for (n, ips) in &p.records {
        if check_record(n, ips).is_err() || e.records_mut().set(n, ips.clone()).is_err() {
            dropped += 1;
        }
    }
    for b in &p.bans {
        if !e.ban(*b) {
            dropped += 1;
        }
    }
    dropped
}

/// The live state as a `store::Source`: the device encodes a save straight from it (under its
/// state lock) instead of cloning everything first, so a save allocates only the output
/// buffer. Pause is never included.
pub struct Live<'a, B: AsRef<[u8]>> {
    pub engine: &'a Engine<B>,
    pub settings: &'a Settings,
    pub summaries: &'a [DailySummary],
}

impl<B: AsRef<[u8]>> Source for Live<'_, B> {
    /// The engine only holds rules that passed `Rules::add` (valid, unique, canonical).
    fn rules(&self, f: &mut dyn FnMut(RuleKind, &str)) {
        for (k, p) in self.engine.rules().entries() {
            f(*k, p);
        }
    }

    /// Names are normalised by `LocalRecords::set`, which also refuses empty address lists.
    fn records(&self, f: &mut dyn FnMut(&str, &[IpAddr])) {
        for (n, ips) in self.engine.records().iter() {
            f(n, ips);
        }
    }

    fn bans(&self) -> &[ClientKey] {
        self.engine.bans()
    }

    fn settings(&self) -> &Settings {
        self.settings
    }

    fn summaries(&self) -> &[DailySummary] {
        self.summaries
    }
}

/// Everything that survives a reboot, cloned from the live state (pause is never included).
/// Host tools and tests only: the device encodes from `Live` without this copy.
pub fn snapshot<B: AsRef<[u8]>>(e: &Engine<B>, settings: &Settings, summaries: &[DailySummary]) -> Persisted {
    Persisted {
        rules: e.rules().list(),
        records: e.records().list(),
        bans: e.banned(),
        settings: settings.clone(),
        summaries: summaries.to_vec(),
    }
}
