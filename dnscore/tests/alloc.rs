//! Peak heap use of the save and load paths, measured with a counting global allocator.
//! (The device aborts on a failed allocation, so these bound what a save or a boot needs.)

use dnscore::persist::Live;
use dnscore::ring::{MemFlash, Ring, MAX_RECORD};
use dnscore::stats::{DailySummary, SUMMARY_TOP};
use dnscore::store::{decode, try_encode, Settings, Store, StoreError, BLOB_BUDGET};
use dnscore::{BlockList, ClientKey, Engine, LocalRecords, RuleKind, Rules};
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;

struct Counting;

static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    let c = CUR.fetch_add(n, SeqCst) + n;
    PEAK.fetch_max(c, SeqCst);
}

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        LARGEST.fetch_max(l.size(), SeqCst);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CUR.fetch_sub(l.size(), SeqCst);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            grew(new);
            CUR.fetch_sub(l.size(), SeqCst);
        } else {
            CUR.fetch_sub(l.size() - new, SeqCst);
        }
        LARGEST.fetch_max(new, SeqCst);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// The counters are process-wide: measured sections run one at a time.
static ONE: Mutex<()> = Mutex::new(());

/// (result, peak bytes above the starting level, largest single allocation)
fn measure<R>(f: impl FnOnce() -> R) -> (R, usize, usize) {
    let base = CUR.load(SeqCst);
    PEAK.store(base, SeqCst);
    LARGEST.store(0, SeqCst);
    let r = f();
    (r, PEAK.load(SeqCst) - base, LARGEST.load(SeqCst))
}

fn name_253(i: usize) -> String {
    format!("{i:03}{}.{}.{}.{}", "a".repeat(60), "b".repeat(63), "c".repeat(63), "d".repeat(61))
}

/// The review's case: 7 days x 20 names of 253 bytes held in RAM (bypassing `push_summary`'s
/// clip, i.e. the worst a summary list could ever hold), plus 300 rules and 50 records.
#[test]
fn encoding_a_save_needs_one_buffer_within_the_budget() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let mut e = Engine::new(Rules::new(500), LocalRecords::new(100), BlockList::new(Vec::new()));
    for i in 0..300 {
        e.rules_mut().add(RuleKind::Block, &format!("ads{i}.tracker{i}.example.com")).unwrap();
    }
    for i in 0..50u8 {
        e.records_mut().set(&format!("host{i}.home"), vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))]).unwrap();
    }
    e.ban(ClientKey::V4(Ipv4Addr::new(192, 0, 2, 99)));
    let settings = Settings::default();
    let sums: Vec<DailySummary> = (0..7)
        .map(|d| DailySummary {
            day: 20_000 + d,
            allowed: 1,
            blocked: 1,
            top_queried: (0..SUMMARY_TOP).map(|i| (name_253(i), 9)).collect(),
            top_blocked: (0..SUMMARY_TOP).map(|i| (name_253(100 + i), 9)).collect(),
        })
        .collect();
    let live = Live { engine: &e, settings: &settings, summaries: &sums };
    let (enc, peak, largest) = measure(|| try_encode(&live, BLOB_BUDGET));
    let enc = enc.unwrap();
    let len = enc.bytes.len();
    println!("encode: blob {len} B, peak heap {peak} B, largest allocation {largest} B");
    assert!(len <= BLOB_BUDGET);
    assert_eq!(enc.bytes.capacity(), len, "exactly sized, never doubled");
    assert_eq!(largest, len, "the output buffer is the only large allocation");
    assert!(peak <= len + 512, "peak {peak} vs blob {len}: no copy of the state, no second buffer");
    assert_eq!(decode(&enc.bytes).1, None);
}

#[test]
fn loading_a_record_over_the_cap_is_corrupt_without_allocating_it() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let huge = vec![0x5Au8; 200_000];
    let mut w = Ring::open_with_max_record(MemFlash::new(128), usize::MAX);
    w.save(&huge).unwrap();
    let flash = w.flash().clone();
    drop(w);
    drop(huge);
    let r = Ring::open(flash);
    assert!(r.newest().is_some(), "the record itself is intact (header and CRC)");
    let (res, peak, _) = measure(|| r.load());
    println!("load of a {} B record: {res:?}, peak heap {peak} B", 200_000);
    assert_eq!(res, Err(StoreError));
    assert!(peak < 1024, "nothing like the claimed length was allocated: {peak}");
}

#[test]
fn loading_a_normal_record_allocates_its_length_once() {
    let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let blob = vec![7u8; MAX_RECORD];
    let mut w = Ring::open(MemFlash::new(128));
    w.save(&blob).unwrap();
    let r = Ring::open(w.flash().clone());
    let (res, peak, largest) = measure(|| r.load());
    assert_eq!(res.unwrap().unwrap().len(), MAX_RECORD);
    assert_eq!(largest, MAX_RECORD);
    assert!(peak <= MAX_RECORD + 512);
    assert!(w.save(&vec![7u8; MAX_RECORD + 1]).is_err(), "never write what would not load");
}
