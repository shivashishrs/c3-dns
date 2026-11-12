//! The decision engine: banned -> own name -> paused -> allow -> local -> custom block -> list
//! -> default.
//!
//! The "own name" is the device's built-in record (`Settings.local_name`, `adblock.home` by
//! default) pointing at its own addresses. It is kept apart from the owner's records (never
//! persisted, does not count against their cap) and answers before pause and rules: an allow
//! rule would forward it upstream, where it does not exist.

use crate::blocklist::BlockList;
use crate::name::normalize;
use crate::rules::{Match, RuleError, Rules};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Upper bound on banned clients.
pub const MAX_BANNED: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl ClientKey {
    /// The key a client is counted, rate-limited and banned under: its full address
    /// (IPv4-mapped IPv6 as IPv4). Not the IPv6 /64: every on-link client shares the
    /// router's /64, so that would merge all IPv6 clients into one bucket and one ban.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(a) => ClientKey::V4(a),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => ClientKey::V4(v4),
                None => ClientKey::V6(a),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Resolve,
    Block,
    Local,
    Drop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    Paused,
    Banned,
    CustomAllow(String),
    LocalRecord(String),
    CustomBlock(String),
    List(String),
    Cname { via: String, rule: String },
    Default,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Paused => write!(f, "paused"),
            Reason::Banned => write!(f, "banned"),
            Reason::CustomAllow(p) => write!(f, "allow: {p}"),
            Reason::LocalRecord(n) => write!(f, "local: {n}"),
            Reason::CustomBlock(p) => write!(f, "block: {p}"),
            Reason::List(n) => write!(f, "list: {n}"),
            Reason::Cname { via, rule } => write!(f, "cname {via}: {rule}"),
            Reason::Default => write!(f, "default"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub reason: Reason,
}

fn decision(action: Action, reason: Reason) -> Decision {
    Decision { action, reason }
}

/// Local name -> addresses, bounded by `cap` names.
pub struct LocalRecords {
    cap: usize,
    map: HashMap<String, Vec<IpAddr>>,
}

impl LocalRecords {
    pub fn new(cap: usize) -> Self {
        Self { cap, map: HashMap::new() }
    }

    /// Replaces any existing record for `name`. `ips` must be non-empty.
    pub fn set(&mut self, name: &str, ips: Vec<IpAddr>) -> Result<(), RuleError> {
        let n = normalize(name).ok_or(RuleError::Invalid)?;
        if ips.is_empty() {
            return Err(RuleError::Empty);
        }
        if !self.map.contains_key(&n) && self.map.len() >= self.cap {
            return Err(RuleError::TooMany);
        }
        self.map.insert(n, ips);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        normalize(name).is_some_and(|n| self.map.remove(&n).is_some())
    }

    pub fn get(&self, name: &str) -> Option<&[IpAddr]> {
        let n = normalize(name)?;
        self.map.get(&n).map(Vec::as_slice)
    }

    /// All records, unordered, without copying.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[IpAddr])> {
        self.map.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    pub fn list(&self) -> Vec<(String, Vec<IpAddr>)> {
        let mut v: Vec<_> = self.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort();
        v
    }
}

pub struct Engine<B: AsRef<[u8]>> {
    rules: Rules,
    records: LocalRecords,
    /// The device's own name and addresses (at most one name), set by the firmware.
    own: LocalRecords,
    list: BlockList<B>,
    paused_until: Option<u64>,
    banned: Vec<ClientKey>,
}

impl<B: AsRef<[u8]>> Engine<B> {
    pub fn new(rules: Rules, records: LocalRecords, list: BlockList<B>) -> Self {
        Self { rules, records, own: LocalRecords::new(1), list, paused_until: None, banned: Vec::new() }
    }

    /// Set the device's own name and addresses, replacing any previous own name.
    /// `ips` must be non-empty and `name` valid (else nothing changes).
    pub fn set_own(&mut self, name: &str, ips: Vec<IpAddr>) -> Result<(), RuleError> {
        let mut own = LocalRecords::new(1);
        own.set(name, ips)?;
        self.own = own;
        Ok(())
    }

    pub fn clear_own(&mut self) {
        self.own = LocalRecords::new(1);
    }

    /// The own name and its addresses, if set.
    pub fn own(&self) -> Option<(&str, &[IpAddr])> {
        self.own.iter().next()
    }

    /// Addresses for a `Local` decision: the own name first, then the owner's records.
    pub fn local_ips(&self, name: &str) -> Option<&[IpAddr]> {
        self.own.get(name).or_else(|| self.records.get(name))
    }

    /// Names in the common list (hash records).
    pub fn list_len(&self) -> usize {
        self.list.len()
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    pub fn rules_mut(&mut self) -> &mut Rules {
        &mut self.rules
    }

    pub fn records(&self) -> &LocalRecords {
        &self.records
    }

    pub fn records_mut(&mut self) -> &mut LocalRecords {
        &mut self.records
    }

    fn is_paused(&self, now_ms: u64) -> bool {
        self.paused_until.is_some_and(|u| now_ms < u)
    }

    pub fn decide(&self, domain: &str, client: ClientKey, now_ms: u64) -> Decision {
        if self.banned.contains(&client) {
            return decision(Action::Drop, Reason::Banned);
        }
        let n = normalize(domain);
        if let Some(n) = n.as_deref().filter(|n| self.is_own(n)) {
            return decision(Action::Local, Reason::LocalRecord(n.to_string()));
        }
        if self.is_paused(now_ms) {
            return decision(Action::Resolve, Reason::Paused);
        }
        match n {
            Some(n) => self.explain_normalized(n),
            None => decision(Action::Resolve, Reason::Default),
        }
    }

    /// `n` is already normalised (no second allocation on the query path).
    fn is_own(&self, n: &str) -> bool {
        self.own.iter().next().is_some_and(|(o, _)| o == n)
    }

    /// Like `decide` but ignores pause and ban (the UI lookup box).
    pub fn explain(&self, domain: &str) -> Decision {
        match normalize(domain) {
            Some(n) => self.explain_normalized(n),
            None => decision(Action::Resolve, Reason::Default),
        }
    }

    fn explain_normalized(&self, d: String) -> Decision {
        if self.is_own(&d) {
            return decision(Action::Local, Reason::LocalRecord(d));
        }
        let block = match self.rules.matches(&d) {
            Match::Allow(p) => return decision(Action::Resolve, Reason::CustomAllow(p)),
            Match::Block(p) => Some(p),
            Match::None => None,
        };
        if self.records.get(&d).is_some() {
            return decision(Action::Local, Reason::LocalRecord(d));
        }
        if let Some(p) = block {
            return decision(Action::Block, Reason::CustomBlock(p));
        }
        if let Some(n) = self.list.contains(&d) {
            return decision(Action::Block, Reason::List(n));
        }
        decision(Action::Resolve, Reason::Default)
    }

    /// CNAME uncloaking: `Some(Block)` if a chain member is blocked and none is allowed.
    /// Does not consider pause or ban; the caller checks those first.
    pub fn uncloak(&self, chain: &[String]) -> Option<Decision> {
        let mut hit: Option<Decision> = None;
        for member in chain {
            let Some(m) = normalize(member) else { continue };
            let rule = match self.rules.matches(&m) {
                Match::Allow(_) => return None,
                Match::Block(p) => Some(p),
                Match::None => self.list.contains(&m),
            };
            if hit.is_none() {
                if let Some(rule) = rule {
                    hit = Some(decision(Action::Block, Reason::Cname { via: m, rule }));
                }
            }
        }
        hit
    }

    pub fn pause(&mut self, secs: u32, now_ms: u64) {
        self.paused_until = Some(now_ms.saturating_add(u64::from(secs) * 1000));
    }

    pub fn resume(&mut self) {
        self.paused_until = None;
    }

    /// Whole seconds left (rounded up); 0 when not paused.
    pub fn paused_for(&self, now_ms: u64) -> u32 {
        match self.paused_until {
            Some(u) if now_ms < u => {
                u32::try_from((u - now_ms).div_ceil(1000)).unwrap_or(u32::MAX)
            }
            _ => 0,
        }
    }

    /// False if already banned or the ban table (`MAX_BANNED`) is full.
    pub fn ban(&mut self, c: ClientKey) -> bool {
        if self.banned.contains(&c) || self.banned.len() >= MAX_BANNED {
            return false;
        }
        self.banned.push(c);
        true
    }

    pub fn unban(&mut self, c: ClientKey) -> bool {
        let before = self.banned.len();
        self.banned.retain(|b| *b != c);
        self.banned.len() != before
    }

    pub fn banned(&self) -> Vec<ClientKey> {
        self.banned.clone()
    }

    /// The banned clients, without copying.
    pub fn bans(&self) -> &[ClientKey] {
        &self.banned
    }
}
