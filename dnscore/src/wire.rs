//! DNS wire format parsing and building.
//!
//! Every access to packet data is bounds-checked; no allocation is sized from a
//! count field; compression pointers are followed at most [`MAX_HOPS`] times.
use std::net::{Ipv4Addr, Ipv6Addr};

pub const QTYPE_A: u16 = 1;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_AAAA: u16 = 28;

const TYPE_OPT: u16 = 41;
const HEADER: usize = 12;
const MAX_HOPS: u32 = 16;
const MAX_NAME: usize = 253;
const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_TC: u16 = 0x0200;
const BLOCKED_TTL: u32 = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub id: u16,
    pub flags: u16,
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub question_end: usize,
    pub udp_size: u16,
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    Short,
    BadLabel,
    PointerLoop,
    NotAQuery,
    TooLong,
    Malformed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub rcode: u8,
    pub truncated: bool,
    pub min_ttl: u32,
    pub cnames: Vec<String>,
}

fn u16_at(p: &[u8], i: usize) -> Result<u16, ParseError> {
    let b = p.get(i..i.checked_add(2).ok_or(ParseError::Short)?).ok_or(ParseError::Short)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(p: &[u8], i: usize) -> Result<u32, ParseError> {
    let b = p.get(i..i.checked_add(4).ok_or(ParseError::Short)?).ok_or(ParseError::Short)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a (possibly compressed) name at `start`. Returns the lowercase dotted
/// name (empty for the root) and the offset just past the name in the
/// original (uncompressed) position.
fn read_name(pkt: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut hops = 0u32;
    let mut out = String::new();
    loop {
        let len = *pkt.get(pos).ok_or(ParseError::Short)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    if end.is_none() {
                        end = Some(pos + 1);
                    }
                    break;
                }
                let l = len as usize;
                let lab = pkt.get(pos + 1..pos + 1 + l).ok_or(ParseError::Short)?;
                if !lab.iter().all(|&b| (0x21..=0x7e).contains(&b) && b != b'.') {
                    return Err(ParseError::BadLabel);
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.extend(lab.iter().map(|&b| b.to_ascii_lowercase() as char));
                if out.len() > MAX_NAME {
                    return Err(ParseError::TooLong);
                }
                pos += 1 + l;
            }
            0xC0 => {
                let b2 = *pkt.get(pos + 1).ok_or(ParseError::Short)? as usize;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                hops += 1;
                if hops > MAX_HOPS {
                    return Err(ParseError::PointerLoop);
                }
                pos = ((len as usize & 0x3F) << 8) | b2;
            }
            _ => return Err(ParseError::BadLabel),
        }
    }
    Ok((out, end.unwrap_or(pos + 1)))
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Section {
    Answer,
    Authority,
    Additional,
}

struct Rec {
    section: Section,
    rtype: u16,
    class: u16,
    ttl_off: usize,
    rdata: usize,
    rdata_end: usize,
}

struct Scan {
    records: Vec<Rec>,
    /// Error hit while walking the record sections (records before it are valid).
    rec_err: Option<ParseError>,
}

/// Walk header, questions and resource records. Errors in the header or
/// question section are returned; errors later are reported in `rec_err`.
fn scan(pkt: &[u8]) -> Result<Scan, ParseError> {
    if pkt.len() < HEADER {
        return Err(ParseError::Short);
    }
    let qd = u16_at(pkt, 4)?;
    let counts = [
        (Section::Answer, u16_at(pkt, 6)?),
        (Section::Authority, u16_at(pkt, 8)?),
        (Section::Additional, u16_at(pkt, 10)?),
    ];
    let mut pos = HEADER;
    for _ in 0..qd {
        let (_, e) = read_name(pkt, pos)?;
        if e + 4 > pkt.len() {
            return Err(ParseError::Short);
        }
        pos = e + 4;
    }
    let mut records = Vec::new();
    let mut rec_err = None;
    'outer: for (section, n) in counts {
        for _ in 0..n {
            let r = (|| -> Result<(Rec, usize), ParseError> {
                let (_, e) = read_name(pkt, pos)?;
                let rtype = u16_at(pkt, e)?;
                let class = u16_at(pkt, e + 2)?;
                let rdlen = u16_at(pkt, e + 8)? as usize;
                let rdata = e + 10;
                let rdata_end = rdata + rdlen;
                if rdata_end > pkt.len() {
                    return Err(ParseError::Short);
                }
                Ok((Rec { section, rtype, class, ttl_off: e + 4, rdata, rdata_end }, rdata_end))
            })();
            match r {
                Ok((rec, next)) => {
                    records.push(rec);
                    pos = next;
                }
                Err(e) => {
                    rec_err = Some(e);
                    break 'outer;
                }
            }
        }
    }
    Ok(Scan { records, rec_err })
}

pub fn parse_query(pkt: &[u8]) -> Result<Query, ParseError> {
    if pkt.len() < HEADER {
        return Err(ParseError::Short);
    }
    let id = u16_at(pkt, 0)?;
    let flags = u16_at(pkt, 2)?;
    if flags & FLAG_QR != 0 || (flags >> 11) & 0xF != 0 || u16_at(pkt, 4)? != 1 {
        return Err(ParseError::NotAQuery);
    }
    let (name, e) = read_name(pkt, HEADER)?;
    if name.is_empty() {
        return Err(ParseError::Malformed);
    }
    // A question name is never compressed (nothing precedes it to point at).
    // An uncompressed name occupies exactly len + 2 bytes; any pointer makes
    // `e` differ. Rejected as `Malformed`.
    if e - HEADER != name.len() + 2 {
        return Err(ParseError::Malformed);
    }
    let qtype = u16_at(pkt, e)?;
    let qclass = u16_at(pkt, e + 2)?;
    let question_end = e + 4;
    let mut udp_size = 512;
    if let Ok(s) = scan(pkt) {
        if let Some(opt) = s.records.iter().find(|r| r.rtype == TYPE_OPT) {
            udp_size = opt.class.max(512);
        }
    }
    Ok(Query { id, flags, name, qtype, qclass, question_end, udp_size })
}

/// Header + copy of the question; `an` answers announced.
fn begin(pkt: &[u8], q: &Query, rcode: u8, an: u16) -> Vec<u8> {
    let question = pkt.get(HEADER..q.question_end).unwrap_or(&[]);
    let qd: u16 = if question.is_empty() { 0 } else { 1 };
    let flags = FLAG_QR | FLAG_RA | (q.flags & FLAG_RD) | rcode as u16;
    let mut v = Vec::with_capacity(HEADER + question.len() + 32);
    v.extend_from_slice(&q.id.to_be_bytes());
    v.extend_from_slice(&flags.to_be_bytes());
    v.extend_from_slice(&qd.to_be_bytes());
    v.extend_from_slice(&an.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(question);
    v
}

fn push_answer(v: &mut Vec<u8>, q: &Query, ttl: u32, rdata: &[u8]) {
    v.extend_from_slice(&[0xC0, 0x0C]);
    v.extend_from_slice(&q.qtype.to_be_bytes());
    v.extend_from_slice(&q.qclass.to_be_bytes());
    v.extend_from_slice(&ttl.to_be_bytes());
    v.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(rdata);
}

/// A -> 0.0.0.0, AAAA -> ::, anything else: empty NOERROR.
pub fn build_blocked(pkt: &[u8], q: &Query) -> Vec<u8> {
    match q.qtype {
        QTYPE_A => {
            let mut v = begin(pkt, q, 0, 1);
            push_answer(&mut v, q, BLOCKED_TTL, &[0; 4]);
            v
        }
        QTYPE_AAAA => {
            let mut v = begin(pkt, q, 0, 1);
            push_answer(&mut v, q, BLOCKED_TTL, &[0; 16]);
            v
        }
        _ => begin(pkt, q, 0, 0),
    }
}

/// Answer A with all `v4`, AAAA with all `v6`, other types empty NOERROR.
pub fn build_local(pkt: &[u8], q: &Query, v4: &[Ipv4Addr], v6: &[Ipv6Addr], ttl: u32) -> Vec<u8> {
    let rdatas: Vec<Vec<u8>> = match q.qtype {
        QTYPE_A => v4.iter().map(|a| a.octets().to_vec()).collect(),
        QTYPE_AAAA => v6.iter().map(|a| a.octets().to_vec()).collect(),
        _ => Vec::new(),
    };
    let n = rdatas.len().min(u16::MAX as usize);
    let mut v = begin(pkt, q, 0, n as u16);
    for r in rdatas.iter().take(n) {
        push_answer(&mut v, q, ttl, r);
    }
    v
}

pub fn build_refused(pkt: &[u8], q: &Query) -> Vec<u8> {
    begin(pkt, q, 5, 0)
}

pub fn build_servfail(pkt: &[u8], q: &Query) -> Vec<u8> {
    begin(pkt, q, 2, 0)
}

/// Parse a response. A result with `truncated == true` carries partial data
/// (records after a cut-off are missing): it must not be cached or followed
/// (e.g. for CNAME uncloaking); retry over TCP instead.
pub fn parse_response(pkt: &[u8]) -> Result<Response, ParseError> {
    let s = scan(pkt)?;
    let flags = u16_at(pkt, 2)?;
    let truncated = flags & FLAG_TC != 0;
    if let Some(e) = s.rec_err {
        if !truncated {
            return Err(e);
        }
    }
    let mut min_ttl: Option<u32> = None;
    let mut cnames = Vec::new();
    for r in &s.records {
        if r.rtype == TYPE_OPT {
            continue;
        }
        if r.section != Section::Additional {
            let ttl = u32_at(pkt, r.ttl_off)?;
            min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
        }
        if r.section == Section::Answer && r.rtype == QTYPE_CNAME {
            if r.rdata_end <= r.rdata {
                return Err(ParseError::Malformed);
            }
            let (name, _) = read_name(pkt, r.rdata)?;
            cnames.push(name);
        }
    }
    Ok(Response { rcode: (flags & 0xF) as u8, truncated, min_ttl: min_ttl.unwrap_or(0), cnames })
}

pub fn set_id(pkt: &mut [u8], id: u16) {
    if let Some(b) = pkt.get_mut(0..2) {
        b.copy_from_slice(&id.to_be_bytes());
    }
}

/// Subtract `secs` from every record TTL (OPT excluded), flooring at 1.
pub fn age_ttls(pkt: &mut [u8], secs: u32) {
    let offs: Vec<usize> = match scan(pkt) {
        Ok(s) => s.records.iter().filter(|r| r.rtype != TYPE_OPT).map(|r| r.ttl_off).collect(),
        Err(_) => return,
    };
    for o in offs {
        if let Some(b) = pkt.get_mut(o..o + 4) {
            let ttl = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            b.copy_from_slice(&ttl.saturating_sub(secs).max(1).to_be_bytes());
        }
    }
}

/// Set every record TTL (OPT excluded) to `ttl`; used for serve-stale answers.
pub fn set_ttls(pkt: &mut [u8], ttl: u32) {
    let offs: Vec<usize> = match scan(pkt) {
        Ok(s) => s.records.iter().filter(|r| r.rtype != TYPE_OPT).map(|r| r.ttl_off).collect(),
        Err(_) => return,
    };
    for o in offs {
        if let Some(b) = pkt.get_mut(o..o + 4) {
            b.copy_from_slice(&ttl.to_be_bytes());
        }
    }
}

/// An empty NOERROR reply with TC set: tells a UDP client to retry over TCP.
pub fn build_truncated(pkt: &[u8], q: &Query) -> Vec<u8> {
    let mut v = begin(pkt, q, 0, 0);
    if let Some(b) = v.get_mut(2) {
        *b |= (FLAG_TC >> 8) as u8;
    }
    v
}

/// True if `resp` is a response (QR set, QDCOUNT 1) whose question equals the question of
/// `query` (parsed as `q`), ignoring ASCII case in the name.
pub fn same_question(resp: &[u8], query: &[u8], q: &Query) -> bool {
    let (Ok(flags), Ok(qd)) = (u16_at(resp, 2), u16_at(resp, 4)) else {
        return false;
    };
    if flags & FLAG_QR == 0 || qd != 1 {
        return false;
    }
    match (resp.get(HEADER..q.question_end), query.get(HEADER..q.question_end)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// Case-sensitive variant of [`same_question`], for matching upstream replies to a query
/// sent with 0x20 case randomisation: the resolver must echo the exact case.
pub fn same_question_exact(resp: &[u8], query: &[u8], q: &Query) -> bool {
    same_question(resp, query, q)
        && matches!(
            (resp.get(HEADER..q.question_end), query.get(HEADER..q.question_end)),
            (Some(a), Some(b)) if a == b
        )
}

/// 0x20 case randomisation: give each ASCII letter of the question name a random case,
/// one bit of `rand()` per letter (a new call every 32 letters). Lengths, type and class are
/// untouched. Does nothing if `pkt` does not hold the question described by `q`.
pub fn apply_0x20(pkt: &mut [u8], q: &Query, mut rand: impl FnMut() -> u32) {
    let Some(name) = q.question_end.checked_sub(4).and_then(|end| pkt.get_mut(HEADER..end)) else {
        return;
    };
    let mut pos = 0usize;
    let mut bits = 0u32;
    let mut left = 0u32;
    while let Some(&len) = name.get(pos) {
        if len == 0 || len > 63 {
            break;
        }
        let Some(label) = name.get_mut(pos + 1..pos + 1 + len as usize) else { break };
        for b in label.iter_mut().filter(|b| b.is_ascii_alphabetic()) {
            if left == 0 {
                bits = rand();
                left = 32;
            }
            *b = if bits & 1 == 1 { b.to_ascii_uppercase() } else { b.to_ascii_lowercase() };
            bits >>= 1;
            left -= 1;
        }
        pos += 1 + len as usize;
    }
}

/// Copy the question bytes of `client` (the client's original case) into `resp`, so a reply
/// to a 0x20-randomised upstream query carries the case the client asked with. Does nothing
/// unless both packets hold a question of the same length at the same place.
pub fn restore_question(resp: &mut [u8], client: &[u8], q: &Query) {
    if let (Some(dst), Some(src)) = (resp.get_mut(HEADER..q.question_end), client.get(HEADER..q.question_end)) {
        if dst.eq_ignore_ascii_case(src) {
            dst.copy_from_slice(src);
        }
    }
}

/// Lower the EDNS UDP payload size advertised in an OPT record to at most `max`, so that
/// large answers come back truncated (and are fetched over TCP) instead of as IP fragments.
pub fn clamp_edns(pkt: &mut [u8], max: u16) {
    let offs: Vec<usize> = match scan(pkt) {
        Ok(s) => s
            .records
            .iter()
            .filter(|r| r.rtype == TYPE_OPT && r.section == Section::Additional)
            .map(|r| r.ttl_off - 2) // CLASS (= UDP size) sits just before the TTL
            .collect(),
        Err(_) => return,
    };
    for o in offs {
        if let Some(b) = pkt.get_mut(o..o + 2) {
            let size = u16::from_be_bytes([b[0], b[1]]);
            if size > max {
                b.copy_from_slice(&max.to_be_bytes());
            }
        }
    }
}
