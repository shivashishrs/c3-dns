//! Forwarding to the upstream resolvers.
//!
//! One dual-stack UDP socket (`[::]:0`) talks to every upstream; it is replaced by a new one
//! (new ephemeral port) every `ROTATE_MS` or `ROTATE_SENDS` queries, and an old socket is
//! closed once no pending entry is tied to it or after `RETIRE_MS`. Queries go out with 0x20
//! case randomisation of the name and the EDNS UDP size clamped to `EDNS_MAX`. In-flight
//! queries live in a pending table of at most `MAX_PENDING` entries, matched by (upstream id,
//! socket, upstream address, exact question including case); anything else (late or
//! duplicate replies, spoofs) is dropped and counted. An upstream that echoes the name in a
//! different case 3 times in a row has 0x20 turned off (logged once). Each
//! attempt has `ATTEMPT_MS`; on timeout, SERVFAIL or REFUSED the next upstream is tried. A
//! truncated UDP answer is retried over TCP by a worker. When every upstream fails, the
//! client gets a stale cached answer (TTL `STALE_TTL`) if there is one, else SERVFAIL.
//!
//! After a good answer: pause/ban are checked, then CNAME uncloaking (`Engine::uncloak`),
//! then the answer (or the block that replaces it) is cached.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use std::sync::Arc;

use dnscore::cache::{cacheable, CacheKey, Lookup};
use dnscore::timing::{next_rotation_at, read_timeout_for, rotation_due, CaseFallback};
use dnscore::{
    apply_0x20, build_blocked, build_servfail, clamp_edns, parse_response, restore_question,
    same_question, same_question_exact, set_id, set_ttls, ClientKey, Query, Response,
};
use esp_idf_svc::sys;
use log::warn;

use crate::dns::{send_with_retry, unmap, Client, Dns, Job, State, STALE_TTL};

pub const MAX_PENDING: usize = 32;
const ATTEMPT_MS: u64 = 800;
const SCAN_EVERY_MS: u64 = 50;
const POLL: Duration = Duration::from_millis(10);
/// How long a worker waits for a free pending slot before giving up on a query.
const SLOT_WAIT: Duration = Duration::from_millis(100);
/// Largest upstream answer accepted over TCP.
const MAX_TCP_ANSWER: usize = 8192;
/// Answers carrying a TTL beyond this are cached for this long.
const MAX_CACHE_TTL: u32 = 86_400;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_REFUSED: u8 = 5;
/// TTL of blocked answers (matches dnscore's `build_blocked`).
const BLOCKED_TTL: u32 = 60;
/// Upstream socket rotation: a new source port every minute or 2,000 queries.
const ROTATE_MS: u64 = 60_000;
const ROTATE_SENDS: u32 = 2_000;
/// An old socket is closed when no entry uses it any more, or after this long.
const RETIRE_MS: u64 = 2_000;
/// EDNS UDP size advertised upstream: larger answers come truncated and go to TCP instead
/// of arriving as IP fragments (lwIP reassembly is off).
const EDNS_MAX: u16 = 1232;
/// Consecutive case-mismatch-only replies after which 0x20 is turned off for an upstream.
const CASE_MISS_LIMIT: u8 = 3;
/// The 0x20 fallback state is forgotten this often.
const CASE_RESET_MS: u64 = 10 * 60_000;
/// A failed socket rotation is retried after this long; its warning at most this often.
const ROTATE_RETRY_MS: u64 = 5_000;
const ROTATE_WARN_MS: u64 = 10_000;

/// One client query in flight.
pub struct Pending {
    /// The client's query, with the client's id.
    pub query: Vec<u8>,
    pub q: Query,
    pub key: ClientKey,
    pub client: Client,
    /// Eligible upstreams in order; `idx` is the one being tried.
    pub ups: Vec<SocketAddr>,
    idx: usize,
    up_id: u16,
    deadline: u64,
    /// Generation of the socket the current attempt went out on.
    gen: u32,
    /// The exact packet of the current attempt (our id, 0x20 case, clamped EDNS).
    sent: Vec<u8>,
}

impl Pending {
    pub fn new(query: Vec<u8>, q: Query, key: ClientKey, client: Client, ups: Vec<SocketAddr>, now: u64) -> Self {
        Pending { query, q, key, client, ups, idx: 0, up_id: 0, deadline: now + ATTEMPT_MS, gen: 0, sent: Vec::new() }
    }

    fn target(&self) -> Option<SocketAddr> {
        self.ups.get(self.idx).copied()
    }

    /// Build the packet for the current attempt and remember it in `sent`.
    fn build(&mut self, use_0x20: bool) -> Vec<u8> {
        let mut w = self.query.clone();
        clamp_edns(&mut w, EDNS_MAX);
        if use_0x20 {
            // SAFETY: esp_random reads the hardware RNG; no arguments.
            apply_0x20(&mut w, &self.q, || unsafe { sys::esp_random() });
        }
        set_id(&mut w, self.up_id);
        self.sent = w.clone();
        w
    }
}

/// A truncated UDP answer to retry over TCP (on a worker).
pub struct TcpJob {
    p: Pending,
    /// The truncated UDP answer (upstream id), passed on if TCP fails.
    tc: Vec<u8>,
}

/// Pending entries plus the socket state they refer to, under one lock.
struct Table {
    slots: Vec<Option<Pending>>,
    cur: Arc<UdpSocket>,
    gen: u32,
    /// When the socket is next due for rotation.
    next_rot_ms: u64,
    rot_warned_ms: Option<u64>,
    sends: u32,
    /// Sockets being retired: (socket, generation, close at).
    old: Vec<(Arc<UdpSocket>, u32, u64)>,
    /// 0x20 fallback per upstream (off after 3 case-only mismatches in a row; all forgotten
    /// every 10 minutes).
    case: CaseFallback<SocketAddr>,
}

pub struct Upstream {
    table: Mutex<Table>,
    /// Signalled whenever an entry leaves the table.
    freed: Condvar,
}

/// Upstreams to try, in order: IPv6 ones only when the uplink has a global IPv6 address.
pub fn eligible(st: &State) -> Vec<SocketAddr> {
    st.settings
        .upstreams
        .iter()
        .filter(|ip| ip.is_ipv4() || st.v6_uplink)
        .map(|ip| SocketAddr::new(*ip, 53))
        .collect()
}

/// The dual-stack socket only takes IPv6 socket addresses: IPv4 goes as IPv4-mapped.
fn to_v6(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

fn same_addr(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && unmap(a.ip()) == unmap(b.ip())
}

fn random_u16() -> u16 {
    // SAFETY: esp_random reads the hardware RNG; no arguments.
    (unsafe { sys::esp_random() } & 0xFFFF) as u16
}

fn new_socket() -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))?;
    // Non-blocking: the receive task drains replies, then polls once per tick.
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// A random id not used by any pending entry.
fn fresh_id(t: &[Option<Pending>]) -> u16 {
    loop {
        let id = random_u16();
        if !t.iter().flatten().any(|e| e.up_id == id) {
            return id;
        }
    }
}

impl Upstream {
    pub fn bind() -> io::Result<Self> {
        let mut slots = Vec::with_capacity(MAX_PENDING);
        slots.resize_with(MAX_PENDING, || None);
        let t = Table {
            slots,
            cur: Arc::new(new_socket()?),
            gen: 0,
            next_rot_ms: ROTATE_MS,
            rot_warned_ms: None,
            sends: 0,
            old: Vec::new(),
            case: CaseFallback::new(CASE_MISS_LIMIT, CASE_RESET_MS, dnscore::store::MAX_UPSTREAMS),
        };
        Ok(Upstream { table: Mutex::new(t), freed: Condvar::new() })
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Put `p` in the pending table and send it to its first upstream. When the table is
    /// full, wait up to `SLOT_WAIT` for a slot (the lock is released while waiting).
    /// `Err(p)` when no slot freed up or there is no upstream.
    // The entry is handed back unchanged on failure (moved, not copied): no box needed.
    #[allow(clippy::result_large_err)]
    pub fn submit(&self, dns: &Dns, mut p: Pending) -> Result<(), Pending> {
        let Some(to) = p.target() else { return Err(p) };
        let now = dns.shared.now_ms();
        let (id, wire, sock) = {
            let mut t = self.table();
            let mut slot = t.slots.iter().position(Option::is_none);
            if slot.is_none() {
                t = self
                    .freed
                    .wait_timeout_while(t, SLOT_WAIT, |t| t.slots.iter().all(Option::is_some))
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
                slot = t.slots.iter().position(Option::is_none);
            }
            let Some(slot) = slot else { return Err(p) };
            p.up_id = fresh_id(&t.slots);
            p.gen = t.gen;
            let wire = p.build(t.case.enabled(to, now));
            t.sends = t.sends.saturating_add(1);
            let out = (p.up_id, wire, t.cur.clone());
            t.slots[slot] = Some(p);
            out
        };
        self.send(dns, id, &wire, to, &sock);
        Ok(())
    }

    /// Send to an upstream. If the stack is out of buffers even after the retries, the
    /// attempt is treated as lost and its normal timeout applies (failing over at once would
    /// add load exactly when the TX path is saturated). Any other error (e.g. no route to an
    /// IPv6 upstream) expires the entry now so the next scan fails over.
    fn send(&self, dns: &Dns, id: u16, wire: &[u8], to: SocketAddr, sock: &UdpSocket) {
        if let Err(e) = send_with_retry(sock, wire, to_v6(to), &dns.shared.counters) {
            if crate::dns::is_no_buffer(&e) {
                return;
            }
            let mut t = self.table();
            if let Some(e) = t.slots.iter_mut().flatten().find(|e| e.up_id == id) {
                e.deadline = 0;
            }
        }
    }

    /// Replace the socket after `ROTATE_MS` or `ROTATE_SENDS`, and close retired sockets
    /// that no entry uses any more (or that are older than `RETIRE_MS`).
    fn maintain(&self, dns: &Dns, now: u64) {
        let due = {
            let t = self.table();
            rotation_due(now, t.next_rot_ms, t.sends, ROTATE_SENDS)
        };
        if due {
            match new_socket() {
                Ok(sock) => {
                    let mut t = self.table();
                    let old = std::mem::replace(&mut t.cur, Arc::new(sock));
                    let gen = t.gen;
                    t.old.push((old, gen, now + RETIRE_MS));
                    t.gen = t.gen.wrapping_add(1);
                    t.next_rot_ms = next_rotation_at(now, true, ROTATE_MS, ROTATE_RETRY_MS);
                    t.sends = 0;
                    dns.shared.counters.rotations.fetch_add(1, Relaxed);
                }
                Err(e) => {
                    // Keep the current socket; retry in ROTATE_RETRY_MS (not on every 50 ms
                    // scan), and say so at most once per ROTATE_WARN_MS.
                    let mut t = self.table();
                    t.next_rot_ms = next_rotation_at(now, false, ROTATE_MS, ROTATE_RETRY_MS);
                    t.sends = 0;
                    let warn_now = t.rot_warned_ms.is_none_or(|w| now.saturating_sub(w) >= ROTATE_WARN_MS);
                    if warn_now {
                        t.rot_warned_ms = Some(now);
                    }
                    drop(t);
                    if warn_now {
                        warn!("upstream: new socket failed: {e}; keeping the current one");
                    }
                }
            }
        }
        let mut t = self.table();
        let Table { slots, old, .. } = &mut *t;
        old.retain(|(_, g, until)| now < *until && slots.iter().flatten().any(|e| e.gen == *g));
    }

    /// All sockets to read from: the current one and those being retired.
    fn sockets(&self) -> Vec<(Arc<UdpSocket>, u32)> {
        let t = self.table();
        let mut v = vec![(t.cur.clone(), t.gen)];
        v.extend(t.old.iter().map(|(s, g, _)| (s.clone(), *g)));
        v
    }
}

/// What to do with a matched reply, decided under the table lock and done after it.
enum Act {
    Resend(u16, Vec<u8>, SocketAddr, Arc<UdpSocket>),
    Done(Box<Pending>, Vec<u8>, Response),
    Tcp(Box<Pending>, Vec<u8>),
    Fail(Box<Pending>, Option<Vec<u8>>),
}

/// Move entry `e` to its next upstream (in place), or take it out when none is left.
fn advance(t: &mut Table, slot: usize, now: u64, last: Option<Vec<u8>>) -> Act {
    let id = fresh_id(&t.slots);
    let (gen, sock) = (t.gen, t.cur.clone());
    let next = t.slots[slot].as_ref().and_then(|e| e.ups.get(e.idx + 1).copied());
    match next {
        Some(to) => {
            t.sends = t.sends.saturating_add(1);
            let use_0x20 = t.case.enabled(to, now);
            let e = t.slots[slot].as_mut().expect("slot is occupied");
            e.idx += 1;
            e.up_id = id;
            e.gen = gen;
            e.deadline = now + ATTEMPT_MS;
            Act::Resend(id, e.build(use_0x20), to, sock)
        }
        None => {
            let p = t.slots[slot].take().expect("slot is occupied");
            Act::Fail(Box::new(p), last)
        }
    }
}

/// The upstream receive task: match replies, and every `SCAN_EVERY_MS` fail over or
/// give up on entries whose attempt timed out.
pub fn rx_loop(dns: std::sync::Arc<Dns>) {
    let mut buf = vec![0u8; 1500];
    let mut last_scan = 0u64;
    let mut k = 0u32;
    loop {
        if k % 64 == 1 {
            crate::dns::note_stack(crate::dns::ROLE_UP);
        }
        k = k.wrapping_add(1);
        // Drain every reply that is already waiting before looking for timeouts, so that an
        // entry whose answer sits unread in the socket is never failed over.
        let mut got = false;
        for (sock, gen) in dns.up.sockets() {
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                got = true;
                if let Some(act) = on_reply(&dns, &buf[..n], from, gen) {
                    if !matches!(act, Act::Resend(..)) {
                        dns.up.freed.notify_all();
                    }
                    perform(&dns, act);
                }
            }
        }
        let now = dns.shared.now_ms();
        if now.saturating_sub(last_scan) >= SCAN_EVERY_MS {
            last_scan = now;
            dns.up.maintain(&dns, now);
            let acts: Vec<Act> = {
                let mut t = dns.up.table();
                let expired: Vec<usize> = (0..t.slots.len())
                    .filter(|&i| t.slots[i].as_ref().is_some_and(|e| e.deadline <= now))
                    .collect();
                expired.into_iter().map(|i| advance(&mut t, i, now, None)).collect()
            };
            if acts.iter().any(|a| !matches!(a, Act::Resend(..))) {
                dns.up.freed.notify_all();
            }
            for a in acts {
                perform(&dns, a);
            }
        }
        if !got {
            // One FreeRTOS tick (10 ms): yields the CPU; adds at most one tick to an answer.
            std::thread::sleep(POLL);
        }
    }
}

fn on_reply(dns: &Dns, resp: &[u8], from: SocketAddr, gen: u32) -> Option<Act> {
    let id = u16::from_be_bytes([*resp.first()?, *resp.get(1)?]);
    let now = dns.shared.now_ms();
    let c = &dns.shared.counters;
    let mut t = dns.up.table();
    let slot = t.slots.iter().position(|e| {
        e.as_ref().is_some_and(|e| {
            e.up_id == id
                && e.gen == gen
                && e.target().is_some_and(|to| same_addr(to, from))
                && same_question(resp, &e.query, &e.q)
        })
    });
    let Some(slot) = slot else {
        c.dup.fetch_add(1, Relaxed);
        return None;
    };
    let (to, exact) = {
        let e = t.slots[slot].as_ref().expect("slot is occupied");
        (e.target().expect("matched a target"), same_question_exact(resp, &e.sent, &e.q))
    };
    if !exact {
        // Right id, socket and address, but the name's case differs: either a spoof that
        // guessed the id, or a resolver that does not echo 0x20. Drop it and keep waiting.
        c.case_miss.fetch_add(1, Relaxed);
        if t.case.on_mismatch(to, now) {
            warn!("upstream: {to} does not echo the query case; 0x20 off for it for up to 10 min");
        }
        return None;
    }
    t.case.on_match(to, now);
    Some(match parse_response(resp) {
        Err(_) => advance(&mut t, slot, now, None),
        Ok(r) if r.truncated => {
            let p = t.slots[slot].take().expect("slot is occupied");
            Act::Tcp(Box::new(p), resp.to_vec())
        }
        Ok(r) if r.rcode == RCODE_SERVFAIL || r.rcode == RCODE_REFUSED => {
            advance(&mut t, slot, now, Some(resp.to_vec()))
        }
        Ok(r) => {
            let p = t.slots[slot].take().expect("slot is occupied");
            Act::Done(Box::new(p), resp.to_vec(), r)
        }
    })
}

fn perform(dns: &Dns, act: Act) {
    let c = &dns.shared.counters;
    match act {
        Act::Resend(id, wire, to, sock) => {
            c.failover.fetch_add(1, Relaxed);
            dns.up.send(dns, id, &wire, to, &sock);
        }
        Act::Done(p, resp, r) => finish(dns, *p, resp, &r),
        Act::Tcp(p, tc) => {
            // Queue full: pass the truncated answer on instead of retrying over TCP.
            if let Err(Job::TcpRetry(j)) = dns.jobs.push(Job::TcpRetry(Box::new(TcpJob { p: *p, tc }))) {
                tcp_failed(dns, *j);
            }
        }
        Act::Fail(p, last) => {
            // The last upstream answered SERVFAIL/REFUSED: prefer stale, else pass it on.
            match last {
                Some(mut resp) if !has_stale(dns, &p) => {
                    restore_question(&mut resp, &p.query, &p.q);
                    set_id(&mut resp, p.q.id);
                    c.servfail.fetch_add(1, Relaxed);
                    dns.deliver(&p.client, &p.query, &p.q, resp);
                }
                _ => fail(dns, *p),
            }
        }
    }
}

/// A usable cached answer exists (never while paused: the cache may hold answers that
/// CNAME uncloaking blocked, and nothing fetched while paused is cached).
fn has_stale(dns: &Dns, p: &Pending) -> bool {
    let ck = CacheKey { name: p.q.name.clone(), qtype: p.q.qtype };
    let now = dns.shared.now_ms();
    let mut st = dns.shared.lock();
    st.engine.paused_for(now) == 0 && !matches!(st.cache.get(&ck, now / 1000), Lookup::Miss)
}

/// Every upstream failed: a stale (or meanwhile fresh) cached answer, else SERVFAIL.
/// While paused the cache is not read at all.
pub fn fail(dns: &Dns, p: Pending) {
    let c = &dns.shared.counters;
    let ck = CacheKey { name: p.q.name.clone(), qtype: p.q.qtype };
    let now = dns.shared.now_ms();
    let cached = {
        let mut st = dns.shared.lock();
        if st.engine.paused_for(now) > 0 {
            Lookup::Miss
        } else {
            st.cache.get(&ck, now / 1000)
        }
    };
    let reply = match cached {
        Lookup::Fresh(mut r) => {
            // Another query refreshed the entry meanwhile: an ordinary cache hit.
            restore_question(&mut r, &p.query, &p.q);
            set_id(&mut r, p.q.id);
            c.cache_hit.fetch_add(1, Relaxed);
            r
        }
        Lookup::Stale(mut r) => {
            set_ttls(&mut r, STALE_TTL);
            restore_question(&mut r, &p.query, &p.q);
            set_id(&mut r, p.q.id);
            c.stale.fetch_add(1, Relaxed);
            r
        }
        Lookup::Miss => {
            c.servfail.fetch_add(1, Relaxed);
            build_servfail(&p.query, &p.q)
        }
    };
    dns.deliver(&p.client, &p.query, &p.q, reply);
}

/// A good upstream answer: pause/ban check, CNAME uncloaking, cache, deliver.
fn finish(dns: &Dns, p: Pending, mut resp: Vec<u8>, r: &Response) {
    // The upstream echoed our 0x20 case; the client gets the case it asked with.
    restore_question(&mut resp, &p.query, &p.q);
    let now = dns.shared.now_ms();
    let ck = CacheKey { name: p.q.name.clone(), qtype: p.q.qtype };
    let reply = {
        let mut st = dns.shared.lock();
        if st.engine.banned().contains(&p.key) {
            dns.shared.counters.banned.fetch_add(1, Relaxed);
            return; // banned while the query was in flight: no answer
        }
        let paused = st.engine.paused_for(now) > 0;
        // uncloak ignores pause/ban, so it runs only when not paused (ban checked above).
        let cloaked = if paused { None } else { st.engine.uncloak(&r.cnames) };
        match cloaked {
            Some(d) => {
                let b = build_blocked(&p.query, &p.q);
                // Cached for BLOCKED_TTL (60 s): a newly added allow rule takes effect for this
                // name only after that (accepted; the UI flushes nothing yet).
                st.cache.put(ck, b.clone(), BLOCKED_TTL, now / 1000);
                st.stats.record(dnscore::stats::LogEntry {
                    ts: now / 1000,
                    client: p.key,
                    name: p.q.name.clone(),
                    qtype: p.q.qtype,
                    blocked: true,
                    reason: d.reason.to_string(),
                });
                dns.shared.counters.blocked.fetch_add(1, Relaxed);
                b
            }
            None => {
                // Nothing fetched while paused is cached: it would bypass uncloaking later.
                if cacheable(r, resp.len(), paused) {
                    st.cache.put(ck, resp.clone(), r.min_ttl.min(MAX_CACHE_TTL), now / 1000);
                }
                let reason = if paused { dnscore::Reason::Paused } else { dnscore::Reason::Default };
                st.stats.record(dnscore::stats::LogEntry {
                    ts: now / 1000,
                    client: p.key,
                    name: p.q.name.clone(),
                    qtype: p.q.qtype,
                    blocked: false,
                    reason: reason.to_string(),
                });
                set_id(&mut resp, p.q.id);
                resp
            }
        }
    };
    dns.deliver(&p.client, &p.query, &p.q, reply);
}

/// TCP failed or could not be queued: a UDP client gets the truncated answer (it can retry
/// over TCP itself); a TCP client gets stale or SERVFAIL.
fn tcp_failed(dns: &Dns, j: TcpJob) {
    let TcpJob { p, mut tc } = j;
    match p.client {
        Client::Udp(_) => {
            restore_question(&mut tc, &p.query, &p.q);
            set_id(&mut tc, p.q.id);
            dns.deliver(&p.client, &p.query, &p.q, tc);
        }
        Client::Tcp(_) => fail(dns, p),
    }
}

/// Worker side of a truncated answer: the same query over TCP to the same upstream.
pub fn tcp_retry(dns: &Dns, j: TcpJob) {
    dns.shared.counters.tcp_retry.fetch_add(1, Relaxed);
    let Some(to) = j.p.target() else { return tcp_failed(dns, j) };
    let wire = j.p.sent.clone();
    match tcp_query(to, &wire) {
        Ok(resp) if same_question_exact(&resp, &wire, &j.p.q) && resp.get(0..2) == wire.get(0..2) => {
            match parse_response(&resp) {
                Ok(r) if !r.truncated && r.rcode != RCODE_SERVFAIL && r.rcode != RCODE_REFUSED => {
                    finish(dns, j.p, resp, &r)
                }
                _ => tcp_failed(dns, j),
            }
        }
        Ok(_) => tcp_failed(dns, j),
        Err(e) => {
            warn!("upstream: tcp retry to {to} failed: {e}");
            tcp_failed(dns, j)
        }
    }
}

fn tcp_query(to: SocketAddr, wire: &[u8]) -> io::Result<Vec<u8>> {
    let t = Duration::from_millis(ATTEMPT_MS);
    // Whole milliseconds, never 0 (lwIP turns 0 into "wait forever"): see read_timeout_for.
    let io_t = read_timeout_for(t, t).ok_or(io::ErrorKind::TimedOut)?;
    let mut s = TcpStream::connect_timeout(&to, t)?;
    s.set_read_timeout(Some(io_t))?;
    s.set_write_timeout(Some(io_t))?;
    let n = u16::try_from(wire.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(wire);
    s.write_all(&out)?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let len = usize::from(u16::from_be_bytes(len));
    if !(12..=MAX_TCP_ANSWER).contains(&len) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut resp = vec![0u8; len];
    s.read_exact(&mut resp)?;
    Ok(resp)
}
