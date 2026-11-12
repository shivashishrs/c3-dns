//! The owner-data budget: what the owner's rules, local records and bans cost, counted as
//! bytes in a save (the `store` format) and as estimated heap on the device, and whether a
//! new item still fits.
//!
//! The RAM estimate models the ESP32-C3 (32-bit pointers, 4-byte heap alignment and block
//! headers): a rule is held twice (the ordered entry list and the matching set, each with its
//! own heap copy of the text), plus table slots and growth slack. The constants were fitted
//! to free-heap deltas measured on the spare (Task 9 report) and err on the high side.

use std::net::IpAddr;

use crate::engine::{ClientKey, Engine};
use crate::rules::{RuleError, RuleKind};

/// Heap per rule besides its text: entry slot (16 B), set slot with control byte, both with
/// growth slack, and two heap block headers.
pub const RULE_RAM_FIXED: usize = 72;
/// Heap per local record besides its name and addresses: map slot (name + address list
/// headers) with growth slack, and two block headers.
pub const RECORD_RAM_FIXED: usize = 64;
/// Bytes per stored address (`IpAddr` is 17 bytes on the C3).
pub const ADDR_RAM: usize = 17;
/// Heap per ban (one `ClientKey` in a vector, with growth slack).
pub const BAN_RAM: usize = 26;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Bytes in a save.
    pub encoded: usize,
    /// Estimated heap on the device.
    pub ram: usize,
}

fn heap_text(len: usize) -> usize {
    len.div_ceil(4) * 4
}

fn ip_encoded(a: &IpAddr) -> usize {
    match a {
        IpAddr::V4(_) => 5,
        IpAddr::V6(_) => 17,
    }
}

/// A rule, given its canonical text. The matching set holds the text without `||` and `^`
/// for a subtree rule; counting the full text there too keeps the estimate on the high side.
pub fn rule_cost(canonical: &str) -> Cost {
    let n = canonical.len();
    Cost { encoded: 2 + n, ram: RULE_RAM_FIXED + 2 * heap_text(n) }
}

/// A local record (normalised name and its addresses).
pub fn record_cost(name: &str, ips: &[IpAddr]) -> Cost {
    let encoded = 1 + name.len() + 1 + ips.iter().map(ip_encoded).sum::<usize>();
    Cost { encoded, ram: RECORD_RAM_FIXED + heap_text(name.len()) + heap_text(ADDR_RAM * ips.len()) }
}

pub fn ban_cost(c: ClientKey) -> Cost {
    let encoded = match c {
        ClientKey::V4(_) => 5,
        ClientKey::V6(_) => 17,
    };
    Cost { encoded, ram: BAN_RAM }
}

/// The owner's data as it stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub rules: usize,
    pub records: usize,
    pub bans: usize,
    pub encoded: usize,
    pub ram: usize,
}

impl Usage {
    pub fn entries(&self) -> usize {
        self.rules + self.records + self.bans
    }

    fn add(&mut self, c: Cost) {
        self.encoded += c.encoded;
        self.ram += c.ram;
    }
}

/// Sum over the engine's rules, records and bans (no allocation).
pub fn usage<B: AsRef<[u8]>>(e: &Engine<B>) -> Usage {
    let mut u = Usage::default();
    for (_, p) in e.rules().entries() {
        u.rules += 1;
        u.add(rule_cost(p));
    }
    for (n, ips) in e.records().iter() {
        u.records += 1;
        u.add(record_cost(n, ips));
    }
    for b in e.bans() {
        u.bans += 1;
        u.add(ban_cost(*b));
    }
    u
}

/// Refusal: adding `need` bytes (estimated heap) to `used` would pass `budget`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetError {
    pub used: usize,
    pub budget: usize,
    pub need: usize,
}

/// Bytes as KB with one decimal, rounded.
pub fn kb(b: usize) -> String {
    let tenths = (b.saturating_mul(10) + 512) / 1024;
    format!("{}.{} KB", tenths / 10, tenths % 10)
}

impl BudgetError {
    pub fn message(&self) -> String {
        format!(
            "No room: your rules, records and bans use {} of {} of memory and this needs {} bytes more. \
             Remove entries (or shorten them) first.",
            kb(self.used),
            kb(self.budget),
            self.need
        )
    }
}

/// Whether `add` fits next to `u` within `budget` (estimated heap bytes).
pub fn check(u: &Usage, add: Cost, budget: usize) -> Result<(), BudgetError> {
    if u.ram.saturating_add(add.ram) <= budget {
        Ok(())
    } else {
        Err(BudgetError { used: u.ram, budget, need: add.ram })
    }
}

/// The warning shown while the owner's data is over the budget: data loaded at boot from an
/// older or bigger save, or added through a debug hook. Such data keeps working (DNS uses it);
/// only additions are refused until entries are removed. `None` within the budget.
pub fn over_budget_warning(u: &Usage, budget: usize) -> Option<String> {
    (u.ram > budget).then(|| {
        format!(
            "Owner rules use {} of {} budget: remove entries (adding new ones is refused until then).",
            kb(u.ram),
            kb(budget)
        )
    })
}

/// Why an owner addition was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddError {
    /// The same entry already exists (reported before any budget check).
    Exists,
    Budget(BudgetError),
    Rule(RuleError),
}

/// Add a rule (canonical text) if it is new and fits `budget`. A duplicate is `Exists` even
/// when the budget is full.
pub fn add_rule<B: AsRef<[u8]>>(e: &mut Engine<B>, kind: RuleKind, canonical: &str, budget: usize) -> Result<(), AddError> {
    if e.rules().contains(kind, canonical) {
        return Err(AddError::Exists);
    }
    check(&usage(e), rule_cost(canonical), budget).map_err(AddError::Budget)?;
    e.rules_mut().add(kind, canonical).map_err(|r| match r {
        RuleError::Duplicate => AddError::Exists,
        r => AddError::Rule(r),
    })
}

/// Set a local record (normalised name). The same name with the same addresses is `Exists`;
/// replacing a record frees what the old one held before the budget check.
pub fn set_record<B: AsRef<[u8]>>(e: &mut Engine<B>, name: &str, ips: Vec<IpAddr>, budget: usize) -> Result<(), AddError> {
    let mut u = usage(e);
    if let Some(old) = e.records().get(name) {
        if old == ips.as_slice() {
            return Err(AddError::Exists);
        }
        u.ram = u.ram.saturating_sub(record_cost(name, old).ram);
    }
    check(&u, record_cost(name, &ips), budget).map_err(AddError::Budget)?;
    e.records_mut().set(name, ips).map_err(AddError::Rule)
}
