//! Power-loss-safe record ring over a raw flash partition (the device's `storage`).
//!
//! The partition is a ring of 4 KB sectors. Each save writes one record into the sectors right
//! after the newest good record (wrapping round the end), erasing only those sectors first. A
//! record never takes more than half the ring, so the newest good record is never inside the
//! erased area: a power cut during a save leaves it loadable. On open, the record with the
//! highest sequence number whose header and payload CRCs both check out wins.
//!
//! Record layout, starting on a sector boundary:
//! - first sector: header (`SLOT_HEADER` bytes: magic, seq, payload length, payload CRC32,
//!   header CRC32), then payload bytes;
//! - every further sector: the 4-byte continuation tag `CONT`, then payload bytes.
//!
//! Payload bytes therefore never sit at a sector start, so data inside a payload (such as
//! query names in the daily summaries) can never pose as a record header.
//!
//! Write order: erase, payload sectors, then the header last, then a read-back check.

use crate::store::{crc32_update, Store, StoreError, BLOB_BUDGET};

pub const SECTOR: u32 = 4096;
pub const SLOT_HEADER: usize = 20;
const CONT_LEN: usize = 4;
/// Not printable ASCII and not 0xFF/0x00, so neither erased flash nor text matches it.
const MAGIC: [u8; 4] = [0xC3, 0x5E, 0xA7, 0x01];
const CONT: [u8; 4] = [0xC3, 0x5E, 0xC0, 0x7E];
const FIRST_DATA: usize = SECTOR as usize - SLOT_HEADER;
const CONT_DATA: usize = SECTOR as usize - CONT_LEN;
/// Largest record payload `load` reads into RAM and `save` accepts: the blob budget plus a
/// margin (room for a later, slightly larger budget). A record that claims more is treated as
/// corrupt without allocating it, so a bad or hostile image cannot abort the boot.
pub const MAX_RECORD: usize = BLOB_BUDGET + 8 * 1024;

/// Raw NOR flash: erase sets a sector to 0xFF, writes can only clear bits.
pub trait Flash {
    /// Size in bytes (a multiple of `SECTOR`).
    fn size(&self) -> u32;
    fn read(&self, off: u32, buf: &mut [u8]) -> Result<(), StoreError>;
    fn write(&mut self, off: u32, data: &[u8]) -> Result<(), StoreError>;
    /// Erase the one sector starting at `off` (sector-aligned).
    fn erase_sector(&mut self, off: u32) -> Result<(), StoreError>;
}

/// A record found on flash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub seq: u32,
    /// First sector of the record.
    pub sector: u32,
    /// Payload length in bytes.
    pub len: u32,
}

impl Slot {
    pub fn sectors(&self) -> u32 {
        sectors_for(self.len as usize)
    }
}

/// What `Ring::open` found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scan {
    /// The newest record whose header and payload check out.
    pub newest: Option<Slot>,
    /// Records with a good header and a higher seq than `newest` whose payload is bad:
    /// an interrupted (torn) save, so the newest changes were lost.
    pub torn_newer: u32,
    /// Some sector start is not erased: with `newest == None` this means corrupt, not empty.
    pub data_present: bool,
}

/// Sectors a payload of `len` bytes needs.
pub fn sectors_for(len: usize) -> u32 {
    if len <= FIRST_DATA {
        1
    } else {
        (1 + (len - FIRST_DATA).div_ceil(CONT_DATA)) as u32
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(!0, data) ^ !0
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

pub struct Ring<F: Flash> {
    flash: F,
    sectors: u32,
    newest: Option<Slot>,
    next_seq: u32,
    read_only: bool,
    scan: Scan,
    max_record: usize,
}

impl<F: Flash> Ring<F> {
    /// Encoded record header (used by tests and image tools).
    pub fn header_bytes(seq: u32, len: u32, payload_crc: u32) -> [u8; SLOT_HEADER] {
        let mut h = [0u8; SLOT_HEADER];
        h[..4].copy_from_slice(&MAGIC);
        h[4..8].copy_from_slice(&seq.to_le_bytes());
        h[8..12].copy_from_slice(&len.to_le_bytes());
        h[12..16].copy_from_slice(&payload_crc.to_le_bytes());
        let c = crc32(&h[..16]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        h
    }

    /// Scan the flash. Never fails: unreadable sectors count as bad data.
    pub fn open(flash: F) -> Self {
        Self::open_with_max_record(flash, MAX_RECORD)
    }

    /// `open` with a different `MAX_RECORD` (tests and image tools).
    pub fn open_with_max_record(flash: F, max_record: usize) -> Self {
        let sectors = flash.size() / SECTOR;
        let mut r = Ring {
            flash,
            sectors,
            newest: None,
            next_seq: 1,
            read_only: false,
            scan: Scan { newest: None, torn_newer: 0, data_present: false },
            max_record,
        };
        let mut cands: Vec<Slot> = Vec::new();
        for s in 0..sectors {
            let mut h = [0u8; SLOT_HEADER];
            if r.flash.read(s * SECTOR, &mut h).is_err() {
                r.scan.data_present = true;
                continue;
            }
            if h.iter().any(|&b| b != 0xFF) {
                r.scan.data_present = true;
            }
            if let Some(slot) = r.parse_header(s, &h) {
                cands.push(slot);
            }
        }
        // Highest seq first; the first one whose payload checks out wins.
        cands.sort_by_key(|a| std::cmp::Reverse(a.seq));
        if let Some(max) = cands.first() {
            r.next_seq = max.seq.saturating_add(1);
        }
        for c in &cands {
            if r.payload_ok(c) {
                r.newest = Some(*c);
                break;
            }
            r.scan.torn_newer += 1;
        }
        if r.newest.is_none() {
            r.scan.torn_newer = 0;
        }
        r.scan.newest = r.newest;
        r
    }

    fn max_record_sectors(&self) -> u32 {
        self.sectors / 2
    }

    /// Largest payload that fits in half the ring (the power-loss rule).
    fn ring_payload_max(&self) -> usize {
        match self.max_record_sectors() {
            0 => 0,
            m => FIRST_DATA + (m as usize - 1) * CONT_DATA,
        }
    }

    /// Largest payload a save accepts (and a load reads): half the ring, at most `max_record`.
    pub fn max_payload(&self) -> usize {
        self.ring_payload_max().min(self.max_record)
    }

    fn parse_header(&self, sector: u32, h: &[u8; SLOT_HEADER]) -> Option<Slot> {
        if h[..4] != MAGIC || crc32(&h[..16]) != u32_at(h, 16) {
            return None;
        }
        let seq = u32_at(h, 4);
        let len = u32_at(h, 8);
        if seq == 0 || seq == u32::MAX || len as usize > self.ring_payload_max() {
            return None;
        }
        Some(Slot { seq, sector, len })
    }

    fn sector_off(&self, first: u32, k: u32) -> u32 {
        ((first + k) % self.sectors) * SECTOR
    }

    /// Visit the record's payload chunks in order: (flash offset, chunk length).
    fn chunks(&self, slot: &Slot, mut f: impl FnMut(u32, usize) -> Result<(), StoreError>) -> Result<(), StoreError> {
        let mut left = slot.len as usize;
        let mut k = 0;
        while left > 0 || k == 0 {
            let (skip, room) = if k == 0 { (SLOT_HEADER, FIRST_DATA) } else { (CONT_LEN, CONT_DATA) };
            let n = left.min(room);
            if n > 0 {
                f(self.sector_off(slot.sector, k) + skip as u32, n)?;
            }
            left -= n;
            k += 1;
        }
        Ok(())
    }

    fn payload_ok(&self, slot: &Slot) -> bool {
        let mut h = [0u8; SLOT_HEADER];
        if self.flash.read(slot.sector * SECTOR, &mut h).is_err() {
            return false;
        }
        let want = u32_at(&h, 12);
        for k in 1..slot.sectors() {
            let mut t = [0u8; CONT_LEN];
            if self.flash.read(self.sector_off(slot.sector, k), &mut t).is_err() || t != CONT {
                return false;
            }
        }
        let mut crc = !0u32;
        let mut buf = [0u8; 256];
        let res = self.chunks(slot, |off, n| {
            let mut done = 0;
            while done < n {
                let m = (n - done).min(buf.len());
                self.flash.read(off + done as u32, &mut buf[..m])?;
                crc = crc32_update(crc, &buf[..m]);
                done += m;
            }
            Ok(())
        });
        res.is_ok() && crc ^ !0 == want
    }

    pub fn scan(&self) -> &Scan {
        &self.scan
    }

    /// The newest good record (after a successful save: the one just written).
    pub fn newest(&self) -> Option<Slot> {
        self.newest
    }

    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn flash(&self) -> &F {
        &self.flash
    }

    fn write_record(&mut self, slot: &Slot, bytes: &[u8]) -> Result<(), StoreError> {
        let n = slot.sectors();
        for k in 0..n {
            let off = self.sector_off(slot.sector, k);
            self.flash.erase_sector(off)?;
        }
        for k in 1..n {
            let off = self.sector_off(slot.sector, k);
            self.flash.write(off, &CONT)?;
        }
        let mut chunks = Vec::new();
        self.chunks(slot, |off, len| {
            chunks.push((off, len));
            Ok(())
        })?;
        let mut pos = 0;
        for (off, len) in chunks {
            self.flash.write(off, &bytes[pos..pos + len])?;
            pos += len;
        }
        let h = Self::header_bytes(slot.seq, slot.len, crc32(bytes));
        self.flash.write(slot.sector * SECTOR, &h)?;
        if !self.payload_ok(slot) {
            return Err(StoreError);
        }
        Ok(())
    }
}

impl<F: Flash> Store for Ring<F> {
    /// `Ok(None)`: nothing stored (all erased). `Err`: data present but no good record, or
    /// the newest record is larger than `max_payload()` or cannot be allocated (checked before
    /// allocating: never aborts on a huge length).
    fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(slot) = self.newest else {
            return if self.scan.data_present { Err(StoreError) } else { Ok(None) };
        };
        let len = slot.len as usize;
        if len > self.max_payload() {
            return Err(StoreError);
        }
        let mut h = [0u8; SLOT_HEADER];
        self.flash.read(slot.sector * SECTOR, &mut h)?;
        let mut out: Vec<u8> = Vec::new();
        out.try_reserve_exact(len).map_err(|_| StoreError)?;
        out.resize(len, 0);
        let mut pos = 0;
        self.chunks(&slot, |off, n| {
            self.flash.read(off, &mut out[pos..pos + n])?;
            pos += n;
            Ok(())
        })?;
        // Re-checked here: the flash could have changed since `open`.
        if crc32(&out) != u32_at(&h, 12) {
            return Err(StoreError);
        }
        Ok(Some(out))
    }

    /// Never touches the newest good record. Refused when read-only, when the payload is
    /// over `max_payload()`, or when the sequence numbers are used up.
    fn save(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        if self.read_only || bytes.len() > self.max_payload() || self.next_seq == u32::MAX {
            return Err(StoreError);
        }
        let start = self.newest.map_or(0, |s| (s.sector + s.sectors()) % self.sectors);
        let slot = Slot { seq: self.next_seq, sector: start, len: bytes.len() as u32 };
        // Consume the seq even if the write fails, so a torn header is never reused.
        self.next_seq += 1;
        self.write_record(&slot, bytes)?;
        self.newest = Some(slot);
        Ok(())
    }
}

/// In-memory NOR flash for tests and image tools, with erase counters and an optional
/// operation budget that simulates a power cut (each written byte costs 1, each sector
/// erase 2; running out mid-erase leaves the sector half erased).
#[derive(Clone, Debug)]
pub struct MemFlash {
    data: Vec<u8>,
    erases: Vec<u32>,
    budget: Option<usize>,
}

impl MemFlash {
    /// A fully erased flash of `sectors` sectors.
    pub fn new(sectors: u32) -> Self {
        Self { data: vec![0xFF; (sectors * SECTOR) as usize], erases: vec![0; sectors as usize], budget: None }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn erase_counts(&self) -> &[u32] {
        &self.erases
    }

    pub fn set_budget(&mut self, b: Option<usize>) {
        self.budget = b;
    }

    pub fn budget(&self) -> Option<usize> {
        self.budget
    }

    pub fn flip_bit(&mut self, off: u32, bit: u8) {
        self.data[off as usize] ^= 1 << (bit & 7);
    }

    /// Erase a sector by index without counting it (test setup).
    pub fn erase_raw(&mut self, sector: u32) {
        let o = (sector * SECTOR) as usize;
        self.data[o..o + SECTOR as usize].fill(0xFF);
    }

    pub fn fill_raw(&mut self, v: u8) {
        self.data.fill(v);
    }

    fn take(&mut self, n: usize) -> usize {
        match &mut self.budget {
            None => n,
            Some(b) => {
                let t = n.min(*b);
                *b -= t;
                t
            }
        }
    }
}

impl Flash for MemFlash {
    fn size(&self) -> u32 {
        self.data.len() as u32
    }

    fn read(&self, off: u32, buf: &mut [u8]) -> Result<(), StoreError> {
        let o = off as usize;
        let src = self.data.get(o..o + buf.len()).ok_or(StoreError)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write(&mut self, off: u32, data: &[u8]) -> Result<(), StoreError> {
        let o = off as usize;
        if o + data.len() > self.data.len() {
            return Err(StoreError);
        }
        let n = self.take(data.len());
        for (d, s) in self.data[o..o + n].iter_mut().zip(data) {
            *d &= *s;
        }
        if n < data.len() {
            return Err(StoreError);
        }
        Ok(())
    }

    fn erase_sector(&mut self, off: u32) -> Result<(), StoreError> {
        if !off.is_multiple_of(SECTOR) || off >= self.size() {
            return Err(StoreError);
        }
        let o = off as usize;
        let n = self.take(2);
        if n == 0 {
            return Err(StoreError);
        }
        let end = if n == 2 { SECTOR as usize } else { SECTOR as usize / 2 };
        self.data[o..o + end].fill(0xFF);
        self.erases[o / SECTOR as usize] += 1;
        if n < 2 {
            return Err(StoreError);
        }
        Ok(())
    }
}
