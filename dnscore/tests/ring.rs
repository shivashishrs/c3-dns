use dnscore::ring::{MemFlash, Ring, Scan, SECTOR, SLOT_HEADER};
use dnscore::store::{Store, StoreError};

const SECTORS: u32 = 16;

fn blob(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add((i % 251) as u8)).collect()
}

fn reopen(f: &MemFlash) -> Ring<MemFlash> {
    let mut f = f.clone();
    f.set_budget(None);
    Ring::open(f)
}

#[test]
fn empty_flash_loads_none_and_reports_empty() {
    let r = Ring::open(MemFlash::new(SECTORS));
    assert_eq!(r.load(), Ok(None));
    assert_eq!(r.scan(), &Scan { newest: None, torn_newer: 0, data_present: false });
}

#[test]
fn save_then_reopen_loads_latest() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 100)).unwrap();
    r.save(&blob(2, 5000)).unwrap();
    assert_eq!(r.load(), Ok(Some(blob(2, 5000))));
    let r2 = reopen(r.flash());
    assert_eq!(r2.load(), Ok(Some(blob(2, 5000))));
    assert_eq!(r2.newest().unwrap().seq, 2);
}

#[test]
fn empty_payload_round_trips() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&[]).unwrap();
    assert_eq!(reopen(r.flash()).load(), Ok(Some(vec![])));
}

#[test]
fn sizes_around_sector_boundaries_round_trip() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    let first = SECTOR as usize - SLOT_HEADER;
    let cont = SECTOR as usize - 4;
    for len in [first - 1, first, first + 1, first + cont, first + cont + 1, r.max_payload()] {
        r.save(&blob(len as u8, len)).unwrap();
        assert_eq!(reopen(r.flash()).load(), Ok(Some(blob(len as u8, len))), "len {len}");
    }
}

#[test]
fn payload_over_half_the_ring_is_refused_and_nothing_written() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 10)).unwrap();
    let before = r.flash().clone();
    assert_eq!(r.save(&blob(2, r.max_payload() + 1)), Err(StoreError));
    assert_eq!(r.flash().bytes(), before.bytes());
    assert_eq!(r.load(), Ok(Some(blob(1, 10))));
}

#[test]
fn read_only_refuses_and_writes_nothing() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 10)).unwrap();
    r.set_read_only(true);
    let erases = r.flash().erase_counts().to_vec();
    let before = r.flash().bytes().to_vec();
    assert_eq!(r.save(&blob(2, 10)), Err(StoreError));
    assert_eq!(r.flash().bytes(), &before[..]);
    assert_eq!(r.flash().erase_counts(), &erases[..]);
}

#[test]
fn flipped_bit_in_newest_falls_back_to_previous() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 3000)).unwrap();
    r.save(&blob(2, 3000)).unwrap();
    let s = r.newest().unwrap();
    let mut f = r.flash().clone();
    f.flip_bit(s.sector * SECTOR + SLOT_HEADER as u32 + 100, 3);
    let r2 = Ring::open(f);
    assert_eq!(r2.load(), Ok(Some(blob(1, 3000))));
    assert_eq!(r2.scan().torn_newer, 1);
}

#[test]
fn truncated_newest_falls_back_to_previous() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 9000)).unwrap();
    r.save(&blob(2, 9000)).unwrap();
    let s = r.newest().unwrap();
    // Re-erase the newest record's last sector: its tail reads as 0xFF (half-written).
    let mut f = r.flash().clone();
    f.erase_raw((s.sector + 2) % SECTORS);
    let r2 = Ring::open(f);
    assert_eq!(r2.load(), Ok(Some(blob(1, 9000))));
    assert_eq!(r2.scan().torn_newer, 1);
}

#[test]
fn only_record_corrupt_is_reported_as_corrupt_not_empty() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 300)).unwrap();
    let mut f = r.flash().clone();
    f.flip_bit(SLOT_HEADER as u32 + 7, 0);
    let r2 = Ring::open(f);
    assert_eq!(r2.load(), Err(StoreError));
    assert!(r2.scan().data_present);
}

#[test]
fn garbage_flash_is_corrupt_and_saving_over_it_works() {
    let mut f = MemFlash::new(SECTORS);
    f.fill_raw(0x5A);
    let mut r = Ring::open(f);
    assert_eq!(r.load(), Err(StoreError));
    r.save(&blob(9, 50)).unwrap();
    assert_eq!(reopen(r.flash()).load(), Ok(Some(blob(9, 50))));
}

#[test]
fn header_lookalikes_inside_payload_never_win() {
    // A payload made of copies of a valid-looking header with a huge seq: it must load back
    // as plain data, and the next save must still work.
    let mut r = Ring::open(MemFlash::new(SECTORS));
    let fake = Ring::<MemFlash>::header_bytes(u32::MAX - 1, 10, 0);
    let p: Vec<u8> = fake.iter().copied().cycle().take(3 * SECTOR as usize).collect();
    r.save(&p).unwrap();
    let mut r2 = reopen(r.flash());
    assert_eq!(r2.load(), Ok(Some(p.clone())));
    assert_eq!(r2.newest().unwrap().seq, 1);
    r2.save(&blob(3, 10)).unwrap();
    assert_eq!(reopen(r2.flash()).load(), Ok(Some(blob(3, 10))));
}

#[test]
fn seq_keeps_increasing_across_reopen() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    for i in 0..5 {
        r.save(&blob(i, 10)).unwrap();
    }
    let mut r2 = reopen(r.flash());
    assert_eq!(r2.newest().unwrap().seq, 5);
    r2.save(&blob(7, 10)).unwrap();
    assert_eq!(r2.newest().unwrap().seq, 6);
}

/// Cut the power after every possible number of flash operations of a save (byte writes and
/// sector erases) and reboot: the store must always load either the old or the new blob.
#[test]
fn power_cut_at_any_point_keeps_old_or_new() {
    for (old_len, new_len) in [(100, 200), (5000, 9000), (9000, 300), (20000, 20000)] {
        let mut base = Ring::open(MemFlash::new(SECTORS));
        // Move the write position around so the new record wraps the ring end sometimes.
        for i in 0..(old_len % 7 + 3) {
            base.save(&blob(i as u8, old_len)).unwrap();
        }
        let old = base.load().unwrap().unwrap();
        let new = blob(0xEE, new_len);
        // Count the operations of a full save.
        let mut probe = base.flash().clone();
        probe.set_budget(Some(usize::MAX));
        let mut rp = Ring::open(probe);
        rp.save(&new).unwrap();
        let ops = usize::MAX - rp.flash().budget().unwrap();
        // Ring::open does no writes, so the budget counts the save alone.
        let step = (ops / 400).max(1);
        let mut k = 0;
        while k <= ops {
            let mut f = base.flash().clone();
            f.set_budget(Some(k));
            let mut r = Ring::open(f);
            let res = r.save(&new);
            let got = reopen(r.flash()).load().unwrap().unwrap();
            if res.is_ok() {
                assert_eq!(got, new, "k={k}: save reported ok but new not loaded");
            } else {
                assert!(got == old || got == new, "k={k}/{ops}: loaded neither old nor new");
            }
            k += if k < 64 || ops - k < 64 { 1 } else { step };
        }
    }
}

/// After an interrupted save, the next save (after reboot) must succeed and load.
#[test]
fn save_after_interrupted_save_works() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    r.save(&blob(1, 6000)).unwrap();
    let mut f = r.flash().clone();
    f.set_budget(Some(5000));
    let mut r2 = Ring::open(f);
    assert!(r2.save(&blob(2, 6000)).is_err());
    let mut r3 = reopen(r2.flash());
    assert_eq!(r3.load(), Ok(Some(blob(1, 6000))));
    r3.save(&blob(3, 6000)).unwrap();
    assert_eq!(reopen(r3.flash()).load(), Ok(Some(blob(3, 6000))));
}

#[test]
fn wear_is_spread_evenly_over_the_ring() {
    let mut r = Ring::open(MemFlash::new(SECTORS));
    for i in 0..1000u32 {
        r.save(&blob(i as u8, 100 + (i as usize % 3) * 2000)).unwrap();
    }
    let e = r.flash().erase_counts();
    let (min, max) = (*e.iter().min().unwrap(), *e.iter().max().unwrap());
    assert!(max - min <= 2, "erase counts uneven: {e:?}");
}

#[test]
fn ring_with_one_sector_is_unusable_but_does_not_panic() {
    let mut r = Ring::open(MemFlash::new(1));
    assert_eq!(r.max_payload(), 0);
    assert_eq!(r.save(&[1]), Err(StoreError));
    assert_eq!(r.load(), Ok(None));
}

#[test]
fn max_payload_is_capped_by_the_record_limit() {
    use dnscore::ring::MAX_RECORD;
    let r = Ring::open(MemFlash::new(128));
    assert_eq!(r.max_payload(), MAX_RECORD);
    let small = Ring::open(MemFlash::new(4));
    assert!(small.max_payload() < MAX_RECORD, "half the ring still applies");
}

#[test]
fn a_valid_record_larger_than_the_load_cap_loads_as_corrupt() {
    let mut w = Ring::open_with_max_record(MemFlash::new(128), usize::MAX);
    w.save(&blob(1, 100_000)).unwrap();
    let r = Ring::open(w.flash().clone());
    assert_eq!(r.load(), Err(StoreError), "Corrupt: defaults + warning, the next save replaces it");
    // The next save goes after it and is loadable.
    let mut r = r;
    r.save(&blob(2, 50)).unwrap();
    assert_eq!(reopen(r.flash()).load(), Ok(Some(blob(2, 50))));
}
