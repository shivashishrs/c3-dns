use dnscore::*;
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn q(name: &str, qtype: u16, arcount: u16, extra: &[u8]) -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, (arcount >> 8) as u8, arcount as u8];
    for l in name.split('.') {
        p.push(l.len() as u8);
        p.extend_from_slice(l.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]);
    p.extend_from_slice(extra);
    p
}

fn seeds() -> Vec<Vec<u8>> {
    let query = q("www.example.com", 1, 0, &[]);
    let parsed = parse_query(&query).unwrap();
    let blocked = build_blocked(&query, &parsed);
    // response with two CNAMEs and an A
    let mut cn = q("www.example.com", 1, 0, &[]);
    cn[2] = 0x81;
    cn[3] = 0x80;
    cn[7] = 3;
    for (t, rd) in [(5u16, vec![3, b'c', b'd', b'n', 0xC0, 0x10]), (5, vec![1, b'x', 0xC0, 0x10]), (1, vec![9, 9, 9, 9])] {
        cn.extend_from_slice(&[0xC0, 0x0C]);
        cn.extend_from_slice(&t.to_be_bytes());
        cn.extend_from_slice(&[0, 1, 0, 0, 1, 0x2C]);
        cn.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        cn.extend_from_slice(&rd);
    }
    let mut trunc = cn.clone();
    trunc[2] |= 0x02;
    trunc.truncate(trunc.len() - 7);
    let edns = q("example.org", 28, 1, &[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    vec![query, blocked, cn, trunc, edns]
}

fn mutate(rng: &mut Rng, p: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(4) {
        match rng.below(3) {
            0 if !p.is_empty() => {
                let i = rng.below(p.len());
                p[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(p.len() + 1);
                p.insert(i, rng.next() as u8);
            }
            _ if !p.is_empty() => {
                let i = rng.below(p.len());
                p.remove(i);
            }
            _ => {}
        }
        // bias towards interesting bytes (pointers, big counts)
        if !p.is_empty() && rng.below(4) == 0 {
            let i = rng.below(p.len());
            p[i] = [0xC0, 0xFF, 0x3F, 0x00, 0x40][rng.below(5)];
        }
    }
}

#[test]
fn parser_survives_mutated_packets() {
    let seeds = seeds();
    for s in &seeds {
        assert!(parse_query(s).is_ok() || parse_response(s).is_ok());
    }
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let start = Instant::now();
    let mut worst = Duration::ZERO;
    for i in 0..200_000usize {
        let mut p = seeds[i % seeds.len()].clone();
        mutate(&mut rng, &mut p);
        let t = Instant::now();
        let _ = parse_query(&p);
        let _ = parse_response(&p);
        let mut c = p.clone();
        age_ttls(&mut c, 5);
        set_id(&mut c, 1);
        if let Ok(qq) = parse_query(&p) {
            let _ = build_blocked(&p, &qq);
        }
        worst = worst.max(t.elapsed());
        assert!(t.elapsed() < Duration::from_millis(100), "slow input: {p:?}");
    }
    assert!(start.elapsed() < Duration::from_secs(60), "loop took {:?}, worst {worst:?}", start.elapsed());
}
