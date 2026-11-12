//! Build `storage` partition images (512 KB) for the device boot-path tests, written to the
//! spare with `tools/write-storage.sh`. Uses the same ring code as the firmware.
//!
//!   cargo run --example storage_image -- <kind> <out.bin>
//!
//! kinds:
//!   valid    one good record (seq 1): block rule `image.test`
//!   corrupt  that record with one payload bit flipped (record CRC fails -> Corrupt)
//!   future   a good record whose blob has version byte 2 (blob CRC recomputed -> UnknownVersion)
//!   torn     record seq 1 (block `older.test`), then a second save (block `newer.test`) cut
//!            off by a simulated power loss half-way -> loads seq 1
//!   torn-hdr record seq 1 (`older.test`), record seq 2 (`newer.test`) whose last sector is
//!            erased afterwards (header intact, payload short) -> loads seq 1 + warning

use dnscore::ring::{crc32, MemFlash, Ring, SECTOR, SLOT_HEADER};
use dnscore::store::{encode, Persisted, Store};
use dnscore::RuleKind;

const SECTORS: u32 = 0x80000 / SECTOR;

fn with_rule(name: &str) -> Vec<u8> {
    let p = Persisted { rules: vec![(RuleKind::Block, name.to_string())], ..Persisted::default() };
    encode(&p)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: storage_image <valid|corrupt|future|torn|torn-hdr> <out.bin>");
        std::process::exit(2);
    }
    let mut ring = Ring::open(MemFlash::new(SECTORS));
    let flash = match args[1].as_str() {
        "valid" => {
            ring.save(&with_rule("image.test")).unwrap();
            ring.flash().clone()
        }
        "corrupt" => {
            ring.save(&with_rule("image.test")).unwrap();
            let mut f = ring.flash().clone();
            f.flip_bit(SLOT_HEADER as u32 + 12, 2);
            f
        }
        "future" => {
            let mut b = with_rule("image.test");
            b[4] = 2; // version byte
            let n = b.len() - 4;
            let c = crc32(&b[..n]);
            b[n..].copy_from_slice(&c.to_le_bytes());
            ring.save(&b).unwrap();
            ring.flash().clone()
        }
        "torn" => {
            ring.save(&with_rule("older.test")).unwrap();
            let newer = with_rule("newer.test");
            // A full save costs 2 per sector erased + 1 per byte written; stop half-way.
            let mut probe = ring.flash().clone();
            probe.set_budget(Some(usize::MAX));
            let mut rp = Ring::open(probe);
            rp.save(&newer).unwrap();
            let ops = usize::MAX - rp.flash().budget().unwrap();
            let mut f = ring.flash().clone();
            f.set_budget(Some(ops / 2));
            let mut r2 = Ring::open(f);
            assert!(r2.save(&newer).is_err());
            let mut f = r2.flash().clone();
            f.set_budget(None);
            f
        }
        "torn-hdr" => {
            ring.save(&with_rule("older.test")).unwrap();
            // Pad the rule set so the second record spans two sectors.
            let mut p = Persisted::default();
            for i in 0..300 {
                p.rules.push((RuleKind::Block, format!("newer{i}.test")));
            }
            ring.save(&encode(&p)).unwrap();
            let s = ring.newest().unwrap();
            assert!(s.sectors() >= 2);
            let mut f = ring.flash().clone();
            f.erase_raw(s.sector + s.sectors() - 1);
            f
        }
        k => {
            eprintln!("unknown kind {k}");
            std::process::exit(2);
        }
    };
    let check = Ring::open(flash.clone());
    eprintln!(
        "{}: newest {:?}, torn_newer {}, data_present {}, load ok {}",
        args[1],
        check.newest(),
        check.scan().torn_newer,
        check.scan().data_present,
        check.load().is_ok()
    );
    std::fs::write(&args[2], flash.bytes()).unwrap();
}
