//! Persistent storage on the device: `dnscore::ring::Ring` (which implements
//! `dnscore::store::Store`) over the raw `storage` partition, the boot load, and the
//! once-a-minute save/day-roll. All policy lives in `dnscore::{ring, persist}` (host-tested);
//! this file is the partition glue and the wiring.
//!
//! Boot never fails because of storage: a missing partition, an empty, corrupt or
//! newer-version blob all start with defaults and a warning string for the UI. A blob from a
//! newer firmware also makes storage read-only for this boot (never overwritten).

use std::sync::Arc;

use dnscore::persist::{self, SaveDecision, SaveGate};
use dnscore::ring::{Flash, Ring, SECTOR};
use dnscore::store::{self, EncodeError, Persisted, Store, StoreError, Warning, BLOB_BUDGET};
use esp_idf_svc::sys;
use log::{info, warn};

use crate::clock::Clock;
use crate::dns::Shared;

/// At most one save per 10 minutes and 144 per day (spec: flash life in years).
const SAVE_INTERVAL_SECS: u32 = 600;
const SAVES_PER_DAY: u32 = 144;
/// A save starts only if, after allocating its one buffer (sized first, at most
/// `BLOB_BUDGET`), free heap would still be at least this (10 KB above the 30 KB floor; the
/// buffer lives only for the few milliseconds of the write). Otherwise the save waits for a
/// later tick (the gate is not consumed), so a save never pushes a loaded device to the floor.
const SAVE_HEAP_AFTER: u32 = 40 * 1024;

fn free_heap() -> u32 {
    // SAFETY: plain read of allocator statistics.
    unsafe { sys::esp_get_free_heap_size() }
}

/// The `storage` data partition, found by label (subtype `undefined`).
pub struct PartitionFlash {
    part: *const sys::esp_partition_t,
    size: u32,
    /// Sectors erased successfully since boot (wear accounting).
    pub erased: u32,
    /// Sector erases that failed since boot.
    pub erase_failed: u32,
}

// SAFETY: the descriptor points into the static partition table, valid for the program's
// life; the ESP-IDF partition API is thread-safe. Access is serialised by `Persist`'s Mutex.
unsafe impl Send for PartitionFlash {}

impl PartitionFlash {
    fn find() -> Option<Self> {
        // SAFETY: returns a pointer to a static partition descriptor or null.
        let part = unsafe {
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                c"storage".as_ptr(),
            )
        };
        if part.is_null() {
            return None;
        }
        // SAFETY: non-null static descriptor.
        let size = unsafe { (*part).size } / SECTOR * SECTOR;
        Some(Self { part, size, erased: 0, erase_failed: 0 })
    }
}

fn check(err: sys::esp_err_t) -> Result<(), StoreError> {
    if err == sys::ESP_OK {
        Ok(())
    } else {
        warn!("store: flash error {err}");
        Err(StoreError)
    }
}

fn in_range(off: u32, len: usize, size: u32) -> Result<(), StoreError> {
    match (off as usize).checked_add(len) {
        Some(end) if end <= size as usize => Ok(()),
        _ => Err(StoreError),
    }
}

impl Flash for PartitionFlash {
    fn size(&self) -> u32 {
        self.size
    }

    fn read(&self, off: u32, buf: &mut [u8]) -> Result<(), StoreError> {
        in_range(off, buf.len(), self.size)?;
        // SAFETY: valid partition, in-range offset, buf is valid for buf.len() bytes.
        check(unsafe { sys::esp_partition_read(self.part, off as usize, buf.as_mut_ptr().cast(), buf.len()) })
    }

    fn write(&mut self, off: u32, data: &[u8]) -> Result<(), StoreError> {
        in_range(off, data.len(), self.size)?;
        // SAFETY: as above; data is valid for data.len() bytes.
        check(unsafe { sys::esp_partition_write(self.part, off as usize, data.as_ptr().cast(), data.len()) })
    }

    fn erase_sector(&mut self, off: u32) -> Result<(), StoreError> {
        in_range(off, SECTOR as usize, self.size)?;
        // SAFETY: valid partition, sector-aligned in-range region.
        let r = check(unsafe { sys::esp_partition_erase_range(self.part, off as usize, SECTOR as usize) });
        if r.is_ok() {
            self.erased += 1;
        } else {
            self.erase_failed += 1;
        }
        r
    }
}

/// Counters for `/debug/storage` (and later the UI).
#[derive(Default)]
pub struct Status {
    /// Records written since boot (each is one save: its sectors erased and written).
    pub writes: u32,
    pub failures: u32,
    pub last_save_unix: Option<u64>,
    pub last_bytes: usize,
    /// Seq of the record loaded at boot.
    pub loaded_seq: Option<u32>,
    /// Free heap just before the last save's encode, with its buffer allocated, and after.
    pub last_heap: (u32, u32, u32),
    /// Daily summaries left out of the last save to stay within `BLOB_BUDGET`.
    pub last_dropped_summaries: usize,
    /// Saves put off because free heap was under `SAVE_MIN_FREE` or the buffer could not be
    /// allocated (the state stays dirty; retried on a later tick).
    pub skipped_low_heap: u32,
    /// Saves refused because the owner's data alone exceeds `BLOB_BUDGET`.
    pub over_budget: u32,
}

pub struct Persist {
    ring: Option<Ring<PartitionFlash>>,
    gate: SaveGate,
    pub status: Status,
    /// Budget warnings are logged once per boot (they would repeat on every tick).
    warned_trim: bool,
    warned_over: bool,
}

/// Open storage and load it. Never fails: problems become defaults plus a warning.
pub fn open() -> (Persist, Persisted, Option<String>) {
    let mut p = Persist {
        ring: None,
        gate: SaveGate::new(SAVE_INTERVAL_SECS, SAVES_PER_DAY),
        status: Status::default(),
        warned_trim: false,
        warned_over: false,
    };
    let Some(flash) = PartitionFlash::find() else {
        let w = "No storage partition: settings will not be kept.".to_string();
        warn!("store: {w}");
        return (p, Persisted::default(), Some(w));
    };
    let ring = Ring::open(flash);
    let scan = ring.scan().clone();
    let (stored, warn_kind) = match ring.load() {
        Ok(Some(b)) => store::decode(&b),
        Ok(None) => (Persisted::default(), Some(Warning::Empty)),
        Err(_) => (Persisted::default(), Some(Warning::Corrupt)),
    };
    p.status.loaded_seq = ring.newest().map(|s| s.seq);
    p.ring = Some(ring);
    let warning = match warn_kind {
        Some(Warning::Empty) => Some("Storage is empty: started with default settings.".to_string()),
        Some(Warning::Corrupt) => {
            Some("Stored settings were corrupt: started with defaults (the next save replaces them).".to_string())
        }
        Some(Warning::UnknownVersion) => {
            p.gate.set_read_only(true);
            if let Some(r) = p.ring.as_mut() {
                r.set_read_only(true);
            }
            Some(
                "Stored settings come from a newer firmware: started with defaults; storage is read-only \
                 (nothing is saved) until it is reset."
                    .to_string(),
            )
        }
        None if scan.torn_newer > 0 => Some(format!(
            "The last save was interrupted (power loss?): loaded the previous save (#{}).",
            p.status.loaded_seq.unwrap_or(0)
        )),
        None => None,
    };
    match (&warning, p.status.loaded_seq) {
        (Some(w), seq) => warn!("store: {w} (loaded seq {seq:?}, torn {})", scan.torn_newer),
        (None, Some(seq)) => info!(
            "store: loaded seq {seq}: {} rules, {} records, {} bans, {} summaries",
            stored.rules.len(),
            stored.records.len(),
            stored.bans.len(),
            stored.summaries.len()
        ),
        (None, None) => {}
    }
    (p, stored, warning)
}

#[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))] // read by /debug/storage and the Task 9 UI
impl Persist {
    pub fn read_only(&self) -> bool {
        self.gate.read_only()
    }

    pub fn seq(&self) -> Option<u32> {
        self.ring.as_ref().and_then(|r| r.newest()).map(|s| s.seq)
    }

    pub fn sectors_erased(&self) -> u32 {
        self.ring.as_ref().map_or(0, |r| r.flash().erased)
    }

    pub fn erase_failures(&self) -> u32 {
        self.ring.as_ref().map_or(0, |r| r.flash().erase_failed)
    }

    /// Save if the gate allows it. The blob is encoded straight from the live state under the
    /// state lock (no copy of the state: one exactly sized buffer of at most `BLOB_BUDGET`,
    /// allocated fallibly); the flash write happens outside the lock. Marked clean only after
    /// the write. Low heap, a failed allocation or owner data over budget skip the save and
    /// leave the state dirty; nothing here can abort on out-of-memory.
    pub fn save(&mut self, shared: &Shared, now: Option<u64>, force: bool, reason: &str) -> Result<(), String> {
        if self.ring.is_none() {
            return Err("not saved: no storage partition".to_string());
        }
        // Size the blob first (no allocation) and check the heap before the gate, so a skipped
        // save does not use up its slot.
        let (planned, dirty) = {
            let st = shared.lock();
            let live = persist::Live { engine: &st.engine, settings: &st.settings, summaries: &st.summaries };
            (store::plan(&live, BLOB_BUDGET).map(|p| p.total), st.dirty.is_dirty())
        };
        let heap_before = free_heap();
        if let Ok(total) = planned {
            let need = SAVE_HEAP_AFTER.saturating_add(total as u32);
            if heap_before < need {
                self.status.skipped_low_heap += 1;
                return Err(format!("not saved: low heap ({heap_before} < {need} for a {total}-byte blob)"));
            }
        }
        match self.gate.decide(dirty, now, force) {
            SaveDecision::Save => {}
            d => return Err(format!("not saved: {d:?}")),
        }
        let Some(ring) = self.ring.as_mut() else {
            return Err("not saved: no storage partition".to_string());
        };
        let (encoded, gen, heap_during) = {
            let st = shared.lock();
            let live = persist::Live { engine: &st.engine, settings: &st.settings, summaries: &st.summaries };
            let e = store::try_encode(&live, BLOB_BUDGET);
            (e, st.dirty.generation(), free_heap())
        };
        let enc = match encoded {
            Ok(e) => e,
            Err(EncodeError::NoMemory { needed }) => {
                self.status.skipped_low_heap += 1;
                warn!("store: save skipped: could not allocate {needed} bytes (free {heap_during}); stays dirty");
                return Err("not saved: no memory".to_string());
            }
            Err(EncodeError::OverBudget { needed }) => {
                self.status.over_budget += 1;
                if !self.warned_over {
                    self.warned_over = true;
                    warn!(
                        "store: NOT SAVED: rules, records and bans need {needed} bytes, over the {BLOB_BUDGET}-byte \
                         budget; the previous save is kept (warned once per boot)"
                    );
                }
                return Err(format!("not saved: owner data over budget ({needed} > {BLOB_BUDGET})"));
            }
        };
        self.status.last_dropped_summaries = enc.dropped_summaries;
        if (enc.dropped_summaries > 0 || enc.trimmed_top_entries > 0) && !self.warned_trim {
            self.warned_trim = true;
            warn!(
                "store: blob budget {BLOB_BUDGET} B: left out the {} oldest daily summaries and {} top entries \
                 (warned once per boot)",
                enc.dropped_summaries, enc.trimmed_top_entries
            );
        }
        let bytes = enc.bytes;
        let erased_before = ring.flash().erased;
        let result = ring.save(&bytes);
        let len = bytes.len();
        drop(bytes);
        let heap_after = free_heap();
        self.status.last_heap = (heap_before, heap_during, heap_after);
        match result {
            Ok(()) => {
                self.status.writes += 1;
                self.status.last_save_unix = now;
                self.status.last_bytes = len;
                shared.lock().dirty.saved(gen);
                let seq = ring.newest().map_or(0, |s| s.seq);
                info!(
                    "store: saved {len} bytes, seq {seq}, {} sectors erased, reason {reason} (writes since boot: {}), \
                     heap {heap_before}/{heap_during}/{heap_after} before/during/after",
                    ring.flash().erased - erased_before,
                    self.status.writes
                );
                Ok(())
            }
            Err(_) => {
                self.status.failures += 1;
                warn!("store: save of {len} bytes FAILED, reason {reason}");
                Err("save failed".to_string())
            }
        }
    }

    /// Once a minute: roll the day (pushing the finished day's summary) and save if due.
    /// Both need plausible synced time; until then stats still count but nothing else happens.
    pub fn tick(&mut self, shared: &Shared, clock: &Clock) {
        let Some(now) = clock.now() else {
            return;
        };
        {
            let mut st = shared.lock();
            if let Some(s) = st.stats.roll_day(persist::day_of(now)) {
                info!("stats: day {} closed: {} allowed, {} blocked", s.day, s.allowed, s.blocked);
                persist::push_summary(&mut st.summaries, s);
                st.dirty.mark();
            }
        }
        let _ = self.save(shared, Some(now), false, "periodic");
    }
}

/// `Persist` shared between the main loop and (debug) HTTP handlers.
pub type SharedPersist = Arc<std::sync::Mutex<Persist>>;
