//! The DNS server: one dual-stack UDP socket and one dual-stack TCP listener on port 53
//! (`[::]:53` without IPV6_V6ONLY, so IPv4 clients arrive as IPv4-mapped addresses).
//!
//! UDP path: a receiver task drops non-LAN packets, then rate-limited ones (per client, then the
//! global bucket for all clients together), then everything while the heap is low, and queues
//! the rest on a bounded channel (full queue: the newest packet is dropped and counted). A fixed
//! pool of worker tasks parses, decides, answers from blocks, local records or the cache, and
//! hands misses to `upstream`. Replies that hit ENOMEM/ENOBUFS in `sendto` are retried a few
//! times with a short backoff, then dropped and counted.
//!
//! The shared state sits behind one `Mutex`, held only for in-memory work: never across a
//! socket call or a sleep.

use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use dnscore::cache::{Cache, CacheKey, Lookup};
use dnscore::lan::LanPolicy;
use dnscore::limit::{Admission, Verdict};
use dnscore::stats::{LogEntry, Stats, StatsCaps};
use dnscore::persist::{self, Dirty};
use dnscore::stats::DailySummary;
use dnscore::store::{Persisted, Settings};
use dnscore::timing::read_timeout_for;
use dnscore::{
    build_blocked, build_local, build_truncated, parse_query, restore_question, set_id, set_ttls, Action,
    ClientKey, Engine, LocalRecords, Reason, RuleError, RuleKind, Rules,
};
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::sys;
use log::{info, warn};

use crate::upstream::{self, Upstream};

/// The common blocklist: the used part of the memory-mapped `blocklist` partition.
pub type List = &'static [u8];

/// FreeRTOS priority of the DNS tasks: above the HTTP server (5) and the main task (1),
/// below lwIP (18) and Wi-Fi (23), which must run for DNS to make progress.
const DNS_PRIO: u8 = 10;
/// The UDP receiver alone runs just above lwIP's tcpip task (18), below Wi-Fi (23).
/// Measured on the spare: at priority 10, lwIP received all 200 packets of a burst but the
/// socket's receive mailbox overflowed (dropped silently) because tcpip kept preempting the
/// receiver; only ~60 reached the app. The receiver only copies each packet into a small
/// buffer and queues it (microseconds, no sleeps), so it cannot starve lwIP.
const RX_PRIO: u8 = 19;
/// The upstream receive task runs just above the workers: finishing queries already in
/// flight (bounded by the 32-entry pending table) goes before starting new ones.
const UP_PRIO: u8 = 11;
const WORKERS: usize = 3;
/// Bounded work queue between the UDP receiver and the workers. Deep enough to absorb a
/// 200-query burst at the measured service rate; queries older than `MAX_JOB_AGE` are
/// dropped unanswered (the client has given up), so a deep queue cannot turn into stale work.
const QUEUE: usize = 128;
const MAX_JOB_AGE_MS: u32 = 900;
const MAX_TCP: usize = 4;
const TCP_IDLE: Duration = Duration::from_secs(3);
/// A TCP connection is closed after this long in total, however it trickles (slowloris).
const TCP_CONN_DEADLINE: Duration = Duration::from_secs(10);
/// One framed query (length + body) must arrive within this long.
const TCP_FRAME_DEADLINE: Duration = Duration::from_secs(2);
/// Queries served on one TCP connection before it is closed.
const TCP_MAX_QUERIES: usize = 16;
/// How long a TCP client waits for an upstream answer (all upstreams + a TCP retry).
const TCP_WAIT: Duration = Duration::from_secs(6);
/// TTL given to serve-stale answers.
pub const STALE_TTL: u32 = 30;
const LOCAL_TTL: u32 = 60;
/// Device caps (heap measured on the spare, Task 6): applied on top of `Settings`, following
/// the spec's cut order (log first, then cache). Both structures preallocate to their cap,
/// so these bound their RAM up front instead of growing under load. With the spec defaults
/// (log 500, top-k 100, cache 300) the state alone took 71 KB at boot (264.6 -> 193.2 KB
/// free), idle free heap was ~62 KB and bursts drove it to 0.5-9 KB. With these caps: idle
/// ~112 KB, and the lowest free heap across 200-query and 1,000-query bursts was 34.6 KB
/// (floor 30 KB). Raise them only with a re-measurement.
///
/// Task 9 (web UI, owner-data budget) cut them again, in the spec's order (log, then cache),
/// measured on the spare (debug build, 30 q/s of unique names, UI polling every second):
/// log 128 -> 64 and cache 96/16 KB -> 80/12 KB. With the owner budget full (10 KB, see
/// `http::OWNER_RAM_BUDGET`): loaded steady free heap 73.4 KB, lowest with the UI polling 55.7 KB
/// (52 KB guard; before the cuts, with the budget full: 69.9 KB steady, 52.9 KB lowest).
const DEVICE_LOG_MAX: usize = 64;
const DEVICE_TOP_K: usize = 50;
const DEVICE_CACHE_MAX: usize = 80;
/// Byte budget of the response cache (responses + names + per-entry overhead).
const CACHE_BYTES: usize = 12 * 1024;
pub const LIMITER_CLIENTS: usize = 64;
/// sendto retries on ENOMEM/ENOBUFS/EAGAIN, with 2, 4, 8 ms backoff.
const SEND_RETRIES: u32 = 3;
const NONLAN_LOG_EVERY_MS: u32 = 10_000;
/// At most one "global rate limit" log line per this long.
const GLOBAL_LOG_EVERY_MS: u32 = 10_000;
/// Below this much free heap new queries are dropped (counted as `lowmem`), so that a burst
/// cannot push the allocator into an out-of-memory abort. Under a flood the heap rides this
/// level, and work already in flight (pending upstream queries, queued jobs, Wi-Fi frames held
/// by up to 8 dynamic RX buffers, see sdkconfig.defaults) dips ~15-20 KB below it. Measured on
/// the spare (review fix 1, 400 q/s of upstream misses, global bucket at its default): guard
/// 44 KB -> min free 30.2 KB; 52 KB -> 37.7 KB (35.7 KB with two sources at 600 q/s), for the
/// 30 KB floor. A household's 30 q/s of real names never trips it.
pub const MIN_FREE_HEAP: u32 = 52 * 1024;
/// Task stacks, sized from high-water marks measured on the spare (used: worker ~2.1 KB,
/// udp ~1.6 KB, upstream ~1.9 KB, tcp client ~1.9 KB) with margin for logging paths.
const STACK_WORKER: usize = 6144;
const STACK_UDP: usize = 4096;
const STACK_UP: usize = 5120;
const STACK_TCP_ACCEPT: usize = 3072;
const STACK_TCP_CONN: usize = 5120;

pub struct State {
    pub engine: Engine<List>,
    pub cache: Cache,
    /// Per-client limiter, then the global bucket (`dnscore::limit`).
    pub admission: Admission,
    pub stats: Stats,
    pub lan: LanPolicy,
    pub settings: Settings,
    /// The uplink has a global IPv6 address, so IPv6 upstreams may be used.
    pub v6_uplink: bool,
    /// Finished days (at most 7), persisted.
    pub summaries: Vec<DailySummary>,
    /// Changes not yet saved (rules, records, bans, settings, summaries). Set only through
    /// `Shared::mutate` and the day roll.
    pub dirty: Dirty,
    /// Storage problem found at boot, for the UI (`None` when storage loaded cleanly).
    pub warning: Option<String>,
    /// Stored items the current caps or validation refused at boot.
    #[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))] // read by the Task 9 UI
    pub load_dropped: u32,
}

/// The query log's capacity on this device (the web UI's `/api/log` cap).
pub fn log_cap(st: &State) -> usize {
    st.settings.log_cap.min(DEVICE_LOG_MAX)
}

/// Event counters, shown in the 5-second status line.
#[derive(Default)]
pub struct Counters {
    pub rx: AtomicU32,
    pub queue_full: AtomicU32,
    pub lowmem: AtomicU32,
    pub late: AtomicU32,
    /// Upstream replies dropped because the echoed name case differed (0x20).
    pub case_miss: AtomicU32,
    /// Upstream socket rotations (new source port).
    pub rotations: AtomicU32,
    /// Worker time spent on UDP jobs (microseconds) and the job count, for the average.
    pub busy_us: AtomicU32,
    pub jobs: AtomicU32,
    pub nonlan: AtomicU32,
    /// Refused by the client's own rate limit.
    pub limited: AtomicU32,
    /// Refused by the global (all clients) rate limit.
    pub global_drop: AtomicU32,
    pub malformed: AtomicU32,
    pub banned: AtomicU32,
    pub blocked: AtomicU32,
    pub cache_hit: AtomicU32,
    pub forwarded: AtomicU32,
    pub sent: AtomicU32,
    pub send_retry: AtomicU32,
    pub send_drop: AtomicU32,
    pub pending_full: AtomicU32,
    pub failover: AtomicU32,
    pub servfail: AtomicU32,
    pub stale: AtomicU32,
    pub dup: AtomicU32,
    pub tcp_retry: AtomicU32,
    pub tcp_conns: AtomicU32,
    pub tcp_refused: AtomicU32,
    /// TCP connections being served right now (at most MAX_TCP).
    pub tcp_active: AtomicU32,
}

/// Lowest free stack seen (bytes) per task role: worker, udp rx, upstream rx, tcp client.
pub static STACK_FREE: [AtomicU32; 4] =
    [AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX)];
pub const ROLE_WORKER: usize = 0;
pub const ROLE_UDP: usize = 1;
pub const ROLE_UP: usize = 2;
pub const ROLE_TCP: usize = 3;

/// Record the calling task's stack high-water mark (cheap enough every few hundred packets).
pub fn note_stack(role: usize) {
    // SAFETY: null means the calling task.
    let free = unsafe { sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) } as u32;
    STACK_FREE[role].fetch_min(free, Relaxed);
}

pub struct Shared {
    state: Mutex<State>,
    pub counters: Counters,
    boot: Instant,
    /// Uptime (ms, wrapping u32: no 64-bit atomics on this core) of the last non-LAN line.
    nonlan_logged_ms: AtomicU32,
    /// Same, for the global rate-limit line.
    global_logged_ms: AtomicU32,
}

impl Shared {
    /// Build the state from what storage held (defaults if it held nothing usable).
    pub fn new(list: List, stored: &Persisted, warning: Option<String>) -> Self {
        let mut settings = stored.settings.clone();
        // A local name stored before the private-suffix policy is replaced (and saved later).
        let name_warning = persist::sanitize_local_name(&mut settings);
        if let Some(w) = &name_warning {
            warn!("store: {w}");
        }
        let warning = match (warning, name_warning.clone()) {
            (Some(a), Some(b)) => Some(format!("{a} {b}")),
            (a, b) => a.or(b),
        };
        let mut engine = Engine::new(
            Rules::new(dnscore::store::MAX_RULES),
            LocalRecords::new(dnscore::store::MAX_RECORDS),
            dnscore::BlockList::new(list),
        );
        let load_dropped = persist::load_into(stored, &mut engine);
        // Stored owner data over the current budget stays in use (DNS keeps serving it); the
        // UI shows a warning (`http::overview`) and additions are refused until entries go.
        if let Some(w) = dnscore::budget::over_budget_warning(&dnscore::budget::usage(&engine), crate::http::OWNER_RAM_BUDGET) {
            warn!("store: {w}");
        }
        if load_dropped > 0 {
            warn!("store: {load_dropped} stored items dropped (over the current caps or invalid)");
        }
        let mut summaries = Vec::new();
        for d in &stored.summaries {
            persist::push_summary(&mut summaries, d.clone());
        }
        let mut dirty = Dirty::default();
        if name_warning.is_some() {
            dirty.mark();
        }
        let state = State {
            engine,
            cache: Cache::with_budget(
                settings.cache_cap.min(DEVICE_CACHE_MAX),
                settings.stale_secs,
                CACHE_BYTES,
            ),
            admission: Admission::new(settings.rate_burst, settings.rate_per_sec, LIMITER_CLIENTS),
            stats: Stats::new(StatsCaps {
                log_cap: settings.log_cap.min(DEVICE_LOG_MAX),
                top_k: DEVICE_TOP_K,
                ..StatsCaps::default()
            }),
            lan: LanPolicy::default(),
            settings,
            v6_uplink: false,
            summaries,
            dirty,
            warning,
            load_dropped,
        };
        Shared {
            state: Mutex::new(state),
            counters: Counters::default(),
            boot: Instant::now(),
            nonlan_logged_ms: AtomicU32::new(0),
            global_logged_ms: AtomicU32::new(0),
        }
    }

    /// The one way to change what is persisted (rules, records, bans, settings): runs `f`
    /// under the lock and marks the state dirty if it returns `Ok`. Pause does not go here.
    pub fn mutate<T, E>(&self, f: impl FnOnce(&mut State) -> Result<T, E>) -> Result<T, E> {
        let mut st = self.lock();
        let r = f(&mut st);
        if r.is_ok() {
            st.dirty.mark();
        }
        r
    }

    /// Validated rule add (owner input); returns the canonical pattern.
    #[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))] // Task 9 UI
    pub fn add_rule(&self, kind: RuleKind, pattern: &str) -> Result<String, RuleError> {
        let canon = persist::check_rule(kind, pattern)?;
        self.mutate(|st| st.engine.rules_mut().add(kind, &canon))?;
        Ok(canon)
    }

    #[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))] // Task 9 UI
    pub fn remove_rule(&self, kind: RuleKind, pattern: &str) -> bool {
        self.mutate(|st| if st.engine.rules_mut().remove(kind, pattern) { Ok(()) } else { Err(()) }).is_ok()
    }

    /// Validated local record set (owner input); returns the normalised name.
    #[allow(dead_code)] // Task 9 UI
    pub fn set_record(&self, name: &str, ips: Vec<IpAddr>) -> Result<String, RuleError> {
        let n = persist::check_record(name, &ips)?;
        self.mutate(|st| st.engine.records_mut().set(&n, ips))?;
        Ok(n)
    }

    #[allow(dead_code)] // Task 9 UI
    pub fn remove_record(&self, name: &str) -> bool {
        self.mutate(|st| if st.engine.records_mut().remove(name) { Ok(()) } else { Err(()) }).is_ok()
    }

    #[allow(dead_code)] // Task 9 UI
    pub fn ban(&self, c: ClientKey) -> bool {
        self.mutate(|st| if st.engine.ban(c) { Ok(()) } else { Err(()) }).is_ok()
    }

    #[allow(dead_code)] // Task 9 UI
    pub fn unban(&self, c: ClientKey) -> bool {
        self.mutate(|st| if st.engine.unban(c) { Ok(()) } else { Err(()) }).is_ok()
    }

    /// Lock the state. Keep the guard short: never hold it across socket calls or sleeps.
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn now_ms(&self) -> u64 {
        self.boot.elapsed().as_millis() as u64
    }

    /// One compact status line (counters since boot).
    pub fn status_line(&self) -> String {
        let c = &self.counters;
        let g = |a: &AtomicU32| a.load(Relaxed);
        let (cache_len, cache_bytes) = {
            let st = self.lock();
            (st.cache.len(), st.cache.bytes())
        };
        format!(
            "dns rx={} sent={} blk={} hit={} fwd={} stale={} sf={} qfull={} lowmem={} late={} sretry={} sdrop={} \
             pfull={} fo={} dup={} casemiss={} rot={} rl={} grl={} nonlan={} bad={} ban={} tcp={}/{}/{} tcpup={} cache={}/{}B \
             stackfree={:?} job_us={}",
            g(&c.rx),
            g(&c.sent),
            g(&c.blocked),
            g(&c.cache_hit),
            g(&c.forwarded),
            g(&c.stale),
            g(&c.servfail),
            g(&c.queue_full),
            g(&c.lowmem),
            g(&c.late),
            g(&c.send_retry),
            g(&c.send_drop),
            g(&c.pending_full),
            g(&c.failover),
            g(&c.dup),
            g(&c.case_miss),
            g(&c.rotations),
            g(&c.limited),
            g(&c.global_drop),
            g(&c.nonlan),
            g(&c.malformed),
            g(&c.banned),
            g(&c.tcp_conns),
            g(&c.tcp_refused),
            g(&c.tcp_active),
            g(&c.tcp_retry),
            cache_len,
            cache_bytes,
            STACK_FREE.iter().map(|a| a.load(Relaxed)).collect::<Vec<_>>(),
            g(&c.busy_us) / g(&c.jobs).max(1),
        )
    }

    /// True at most once per `every_ms` (per `slot`), for rate-limited log lines.
    fn log_due(&self, slot: &AtomicU32, every_ms: u32) -> bool {
        let now = self.now_ms() as u32;
        let last = slot.load(Relaxed);
        (last == 0 || now.wrapping_sub(last) >= every_ms)
            && slot.compare_exchange(last, now.max(1), Relaxed, Relaxed).is_ok()
    }

    /// Count a dropped non-LAN packet; log at most one line per 10 s so drops are observable.
    fn nonlan(&self, ip: IpAddr) {
        let n = self.counters.nonlan.fetch_add(1, Relaxed) + 1;
        if self.log_due(&self.nonlan_logged_ms, NONLAN_LOG_EVERY_MS) {
            warn!("dns: dropped query from non-LAN source {ip} (non-LAN drops so far: {n})");
        }
    }

    /// Count a query refused by the global rate limit; log at most one line per 10 s.
    fn global_drop(&self) {
        let n = self.counters.global_drop.fetch_add(1, Relaxed) + 1;
        if self.log_due(&self.global_logged_ms, GLOBAL_LOG_EVERY_MS) {
            warn!("dns: global rate limit reached: dropping queries (global drops so far: {n})");
        }
    }
}

/// Bounded job queue and one-shot reply slot built on `Mutex` + `Condvar`.
///
/// Not `std::sync::mpsc`: its bounded channel spin-waits while another thread is mid-way
/// through a slot. Under FreeRTOS's strict priorities the priority-19 receiver then spins
/// forever on a priority-10 worker that never gets the CPU (seen on the spare as a task
/// watchdog in `Channel::try_send`). A FreeRTOS mutex has priority inheritance instead.
pub struct JobQueue {
    q: Mutex<VecDeque<Job>>,
    ready: Condvar,
    cap: usize,
}

impl JobQueue {
    fn new(cap: usize) -> Self {
        JobQueue { q: Mutex::new(VecDeque::with_capacity(cap)), ready: Condvar::new(), cap }
    }

    /// Queue `j`, or hand it back when the queue is full (the newest job is the one dropped).
    pub fn push(&self, j: Job) -> Result<(), Job> {
        let mut q = self.q.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= self.cap {
            return Err(j);
        }
        q.push_back(j);
        drop(q);
        self.ready.notify_one();
        Ok(())
    }

    fn pop(&self) -> Job {
        let mut q = self.q.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(j) = q.pop_front() {
                return j;
            }
            q = self.ready.wait(q).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// One answer handed from the task that finishes a query to the waiting TCP connection.
#[derive(Default)]
pub struct ReplySlot {
    v: Mutex<Option<Vec<u8>>>,
    ready: Condvar,
}

impl ReplySlot {
    pub fn put(&self, r: Vec<u8>) {
        *self.v.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
        self.ready.notify_one();
    }

    fn take(&self, timeout: Duration) -> Option<Vec<u8>> {
        let g = self.v.lock().unwrap_or_else(|e| e.into_inner());
        let (mut g, _) = self
            .ready
            .wait_timeout_while(g, timeout, |v| v.is_none())
            .unwrap_or_else(|e| e.into_inner());
        g.take()
    }
}

/// Where the answer to a query goes.
pub enum Client {
    Udp(SocketAddr),
    Tcp(Arc<ReplySlot>),
}

pub enum Job {
    /// `at_ms`: uptime (wrapping u32) when the packet arrived.
    Query { pkt: Vec<u8>, peer: SocketAddr, key: ClientKey, at_ms: u32 },
    /// Boxed so that every slot of the bounded queue stays small.
    TcpRetry(Box<upstream::TcpJob>),
}

pub struct Dns {
    pub shared: Arc<Shared>,
    udp: UdpSocket,
    pub up: Upstream,
    pub jobs: JobQueue,
}

/// IPv4-mapped IPv6 (how the dual-stack sockets report IPv4 peers) back to IPv4.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

pub fn is_no_buffer(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
        || matches!(
            e.raw_os_error(),
            Some(c) if c == sys::ENOMEM as i32 || c == sys::ENOBUFS as i32 || c == sys::EAGAIN as i32
        )
}

/// `send_to` with a few short retries when the network stack is out of buffers.
pub fn send_with_retry(sock: &UdpSocket, pkt: &[u8], to: SocketAddr, c: &Counters) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match sock.send_to(pkt, to) {
            Ok(_) => return Ok(()),
            Err(e) if is_no_buffer(&e) && attempt < SEND_RETRIES => {
                c.send_retry.fetch_add(1, Relaxed);
                thread::sleep(Duration::from_millis(2 << attempt));
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

impl Dns {
    pub fn send_udp(&self, pkt: &[u8], to: SocketAddr) {
        let c = &self.shared.counters;
        match send_with_retry(&self.udp, pkt, to, c) {
            Ok(()) => {
                c.sent.fetch_add(1, Relaxed);
            }
            Err(_) => {
                c.send_drop.fetch_add(1, Relaxed);
            }
        }
    }

    /// Deliver a finished answer. UDP answers larger than the client accepts become an
    /// empty TC reply so the client retries over TCP.
    pub fn deliver(&self, client: &Client, query: &[u8], q: &dnscore::Query, mut reply: Vec<u8>) {
        match client {
            Client::Udp(peer) => {
                let limit = usize::from(q.udp_size.clamp(512, 1232));
                if reply.len() > limit {
                    reply = build_truncated(query, q);
                }
                self.send_udp(&reply, *peer);
            }
            Client::Tcp(slot) => slot.put(reply),
        }
    }
}

fn log_entry(now_ms: u64, key: ClientKey, q: &dnscore::Query, blocked: bool, reason: &Reason) -> LogEntry {
    LogEntry {
        ts: now_ms / 1000,
        client: key,
        name: q.name.clone(),
        qtype: q.qtype,
        blocked,
        reason: reason.to_string(),
    }
}

pub enum Outcome {
    Reply(Vec<u8>),
    /// Handed to an upstream; the answer is delivered later.
    Pending,
    Drop,
}

/// The per-query pipeline after the LAN and rate-limit checks:
/// parse -> decide -> block / local / cache -> forward.
pub fn handle(dns: &Dns, pkt: &[u8], key: ClientKey, client: Client) -> Outcome {
    let c = &dns.shared.counters;
    let q = match parse_query(pkt) {
        Ok(q) => q,
        Err(e) => {
            if c.malformed.fetch_add(1, Relaxed) % 64 == 0 {
                warn!("dns: malformed query ({} bytes): {e:?}", pkt.len());
            }
            return Outcome::Drop;
        }
    };
    let now = dns.shared.now_ms();
    let mut st = dns.shared.lock();
    let d = st.engine.decide(&q.name, key, now);
    match d.action {
        Action::Drop => {
            c.banned.fetch_add(1, Relaxed);
            return Outcome::Drop;
        }
        Action::Block => {
            st.stats.record(log_entry(now, key, &q, true, &d.reason));
            c.blocked.fetch_add(1, Relaxed);
            return Outcome::Reply(build_blocked(pkt, &q));
        }
        Action::Local => {
            let ips = st.engine.local_ips(&q.name).unwrap_or(&[]);
            let v4: Vec<_> = ips.iter().filter_map(|i| match i { IpAddr::V4(a) => Some(*a), _ => None }).collect();
            let v6: Vec<_> = ips.iter().filter_map(|i| match i { IpAddr::V6(a) => Some(*a), _ => None }).collect();
            st.stats.record(log_entry(now, key, &q, false, &d.reason));
            return Outcome::Reply(build_local(pkt, &q, &v4, &v6, LOCAL_TTL));
        }
        Action::Resolve => {}
    }
    let ck = CacheKey { name: q.name.clone(), qtype: q.qtype };
    let mut stale = None;
    // While paused, skip the cache: it may hold answers blocked by CNAME uncloaking.
    if d.reason != Reason::Paused {
        match st.cache.get(&ck, now / 1000) {
            Lookup::Fresh(mut r) => {
                // Cached answers carry the first asker's name case: give back this client's.
                restore_question(&mut r, pkt, &q);
                set_id(&mut r, q.id);
                st.stats.record(log_entry(now, key, &q, false, &d.reason));
                c.cache_hit.fetch_add(1, Relaxed);
                return Outcome::Reply(r);
            }
            Lookup::Stale(r) => stale = Some(r),
            Lookup::Miss => {}
        }
    }
    let ups = upstream::eligible(&st);
    drop(st);

    let p = upstream::Pending::new(pkt.to_vec(), q, key, client, ups, now);
    match dns.up.submit(dns, p) {
        Ok(()) => {
            c.forwarded.fetch_add(1, Relaxed);
            Outcome::Pending
        }
        // Pending table full (or no upstream): answer stale if we can, else drop.
        Err(p) => match stale {
            Some(mut r) => {
                set_ttls(&mut r, STALE_TTL);
                restore_question(&mut r, &p.query, &p.q);
                set_id(&mut r, p.q.id);
                c.stale.fetch_add(1, Relaxed);
                dns.shared.lock().stats.record(log_entry(now, key, &p.q, false, &Reason::Default));
                Outcome::Reply(r)
            }
            None if p.ups.is_empty() => {
                upstream::fail(dns, p);
                Outcome::Pending
            }
            None => {
                c.pending_full.fetch_add(1, Relaxed);
                Outcome::Drop
            }
        },
    }
}

/// Spawn a DNS task at `DNS_PRIO`.
pub fn spawn_dns<F: FnOnce() + Send + 'static>(name: &'static CStr, stack: usize, f: F) -> io::Result<()> {
    spawn_at(name, stack, DNS_PRIO, f)
}

fn spawn_at<F: FnOnce() + Send + 'static>(name: &'static CStr, stack: usize, prio: u8, f: F) -> io::Result<()> {
    let _ = ThreadSpawnConfiguration {
        name: Some(name),
        stack_size: stack,
        priority: prio,
        ..Default::default()
    }
    .set();
    let r = thread::Builder::new().stack_size(stack).spawn(f);
    let _ = ThreadSpawnConfiguration::default().set();
    r.map(|_| ())
}

/// Bind the sockets and start every DNS task.
pub fn run(shared: Arc<Shared>) -> anyhow::Result<()> {
    let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    let udp = UdpSocket::bind(SocketAddr::new(any6, 53))?;
    let tcp = TcpListener::bind(SocketAddr::new(any6, 53))?;
    let up = Upstream::bind()?;
    let jobs = JobQueue::new(QUEUE);
    let dns = Arc::new(Dns { shared, udp, up, jobs });

    for _ in 0..WORKERS {
        let d = dns.clone();
        spawn_dns(c"dns-work", STACK_WORKER, move || worker(d))?;
    }
    let d = dns.clone();
    spawn_at(c"dns-udp", STACK_UDP, RX_PRIO, move || udp_rx(d))?;
    let d = dns.clone();
    spawn_at(c"dns-up", STACK_UP, UP_PRIO, move || upstream::rx_loop(d))?;
    let d = dns.clone();
    spawn_dns(c"dns-tcp", STACK_TCP_ACCEPT, move || tcp_accept(d, tcp))?;
    info!("dns: serving udp+tcp [::]:53 (dual stack), {WORKERS} workers, queue {QUEUE}");
    Ok(())
}

fn worker(dns: Arc<Dns>) {
    let mut n = 0u32;
    loop {
        if n % 64 == 1 {
            note_stack(ROLE_WORKER);
        }
        n = n.wrapping_add(1);
        let job = dns.jobs.pop();
        match job {
            Job::Query { pkt, peer, key, at_ms } => {
                if (dns.shared.now_ms() as u32).wrapping_sub(at_ms) > MAX_JOB_AGE_MS {
                    dns.shared.counters.late.fetch_add(1, Relaxed);
                    continue;
                }
                // The guard again at dequeue: jobs queued before the heap ran low must not
                // start more upstream work.
                if low_heap() {
                    dns.shared.counters.lowmem.fetch_add(1, Relaxed);
                    continue;
                }
                let t0 = Instant::now();
                if let Outcome::Reply(r) = handle(&dns, &pkt, key, Client::Udp(peer)) {
                    dns.send_udp(&r, peer);
                }
                let c = &dns.shared.counters;
                c.busy_us.fetch_add(t0.elapsed().as_micros() as u32, Relaxed);
                c.jobs.fetch_add(1, Relaxed);
            }
            Job::TcpRetry(j) => upstream::tcp_retry(&dns, *j),
        }
    }
}

/// LAN check, then admission (the client's own rate, then the global rate for all clients),
/// under one short lock and before anything is allocated or queued. Returns false if the
/// packet is dropped.
fn admit(dns: &Dns, ip: IpAddr, key: ClientKey) -> bool {
    let now = dns.shared.now_ms();
    let verdict = {
        let mut st = dns.shared.lock();
        if st.lan.is_lan(ip) {
            Some(st.admission.check(key, now))
        } else {
            None
        }
    };
    match verdict {
        None => {
            dns.shared.nonlan(ip);
            false
        }
        Some(Verdict::Allow) => true,
        Some(Verdict::ClientLimited) => {
            dns.shared.counters.limited.fetch_add(1, Relaxed);
            false
        }
        Some(Verdict::GlobalLimited) => {
            dns.shared.global_drop();
            false
        }
    }
}

fn low_heap() -> bool {
    // SAFETY: plain read of allocator statistics.
    let free = unsafe { sys::esp_get_free_heap_size() };
    free < MIN_FREE_HEAP
}

fn udp_rx(dns: Arc<Dns>) {
    let c = &dns.shared.counters;
    let mut buf = [0u8; 512];
    let mut k = 0u32;
    loop {
        if k % 256 == 1 {
            note_stack(ROLE_UDP);
        }
        k = k.wrapping_add(1);
        let (n, peer) = match dns.udp.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                warn!("dns: udp recv: {e}");
                thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        c.rx.fetch_add(1, Relaxed);
        let ip = unmap(peer.ip());
        let key = ClientKey::from_ip(ip);
        if !admit(&dns, ip, key) {
            continue; // no reply to non-LAN, rate-limited or banned sources
        }
        if n < 12 {
            c.malformed.fetch_add(1, Relaxed);
            continue;
        }
        if low_heap() {
            c.lowmem.fetch_add(1, Relaxed);
            continue;
        }
        let job = Job::Query { pkt: buf[..n].to_vec(), peer, key, at_ms: dns.shared.now_ms() as u32 };
        if dns.jobs.push(job).is_err() {
            c.queue_full.fetch_add(1, Relaxed);
        }
    }
}

fn tcp_accept(dns: Arc<Dns>, listener: TcpListener) {
    let c = &dns.shared.counters;
    for s in listener.incoming() {
        let s = match s {
            Ok(s) => s,
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let Ok(peer) = s.peer_addr() else { continue };
        let ip = unmap(peer.ip());
        if !dns.shared.lock().lan.is_lan(ip) {
            dns.shared.nonlan(ip);
            continue; // dropping `s` closes it without a reply
        }
        if low_heap() {
            c.lowmem.fetch_add(1, Relaxed);
            continue; // no new TCP task while the heap is low
        }
        if dns.shared.counters.tcp_active.fetch_add(1, Relaxed) as usize >= MAX_TCP {
            dns.shared.counters.tcp_active.fetch_sub(1, Relaxed);
            c.tcp_refused.fetch_add(1, Relaxed);
            continue;
        }
        c.tcp_conns.fetch_add(1, Relaxed);
        let d = dns.clone();
        let spawned = spawn_dns(c"dns-tcpc", STACK_TCP_CONN, move || {
            tcp_conn(&d, s, ip);
            note_stack(ROLE_TCP);
            d.shared.counters.tcp_active.fetch_sub(1, Relaxed);
        });
        if spawned.is_err() {
            dns.shared.counters.tcp_active.fetch_sub(1, Relaxed);
            c.tcp_refused.fetch_add(1, Relaxed);
        }
    }
}

/// Serve framed queries on one connection: 2-byte length prefix, 3 s idle timeout,
/// at most `TCP_MAX_QUERIES` queries, answered one at a time.
/// Read exactly `buf.len()` bytes before `deadline`, with at most `TCP_IDLE` per read.
/// A client that trickles bytes cannot keep the connection beyond `deadline`.
fn read_by(s: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // Under 1 ms left counts as expired, and the timeout is whole ms >= 1: lwIP would turn
        // a sub-millisecond timeout into 0, which means "wait forever" (pinning a TCP slot).
        let left = deadline.saturating_duration_since(Instant::now());
        let Some(t) = read_timeout_for(left, TCP_IDLE) else {
            return Err(io::ErrorKind::TimedOut.into());
        };
        s.set_read_timeout(Some(t))?;
        match s.read(&mut buf[filled..])? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => filled += n,
        }
    }
    Ok(())
}

fn tcp_conn(dns: &Dns, mut s: TcpStream, ip: IpAddr) {
    let _ = s.set_write_timeout(read_timeout_for(TCP_IDLE, TCP_IDLE));
    let _ = s.set_nodelay(true);
    let key = ClientKey::from_ip(ip);
    let conn_deadline = Instant::now() + TCP_CONN_DEADLINE;
    for _ in 0..TCP_MAX_QUERIES {
        // Idle wait for the next query: up to TCP_IDLE, never past the connection deadline.
        let mut len = [0u8; 1];
        if read_by(&mut s, &mut len, conn_deadline).is_err() {
            return;
        }
        // From the first byte on, the whole frame must arrive within TCP_FRAME_DEADLINE.
        let frame_deadline = (Instant::now() + TCP_FRAME_DEADLINE).min(conn_deadline);
        let mut lo = [0u8; 1];
        if read_by(&mut s, &mut lo, frame_deadline).is_err() {
            return;
        }
        let len = usize::from(u16::from_be_bytes([len[0], lo[0]]));
        if !(12..=512).contains(&len) {
            dns.shared.counters.malformed.fetch_add(1, Relaxed);
            return;
        }
        let mut pkt = vec![0u8; len];
        if read_by(&mut s, &mut pkt, frame_deadline).is_err() {
            return;
        }
        dns.shared.counters.rx.fetch_add(1, Relaxed);
        if !admit(dns, ip, key) {
            return;
        }
        // Same guard as the UDP path, per query: no new work while the heap is low.
        if low_heap() {
            dns.shared.counters.lowmem.fetch_add(1, Relaxed);
            return;
        }
        let slot = Arc::new(ReplySlot::default());
        let reply = match handle(dns, &pkt, key, Client::Tcp(slot.clone())) {
            Outcome::Reply(r) => r,
            Outcome::Pending => match slot.take(TCP_WAIT) {
                Some(r) => r,
                None => return,
            },
            Outcome::Drop => return,
        };
        let Ok(n) = u16::try_from(reply.len()) else { return };
        let mut out = Vec::with_capacity(reply.len() + 2);
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&reply);
        if s.write_all(&out).is_err() {
            return;
        }
        dns.shared.counters.sent.fetch_add(1, Relaxed);
    }
}

/// Memory-map the `blocklist` partition read-only and return its used part (the records
/// before the erased tail). Empty if the partition is missing or cannot be mapped.
pub fn map_blocklist() -> List {
    // SAFETY: returns a pointer to a static partition descriptor or null.
    let part = unsafe {
        sys::esp_partition_find_first(
            sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
            sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
            c"blocklist".as_ptr(),
        )
    };
    if part.is_null() {
        warn!("blocklist: partition not found; common list disabled");
        return &[];
    }
    // SAFETY: non-null descriptor from the partition table, valid for the program's life.
    let size = unsafe { (*part).size } as usize;
    let mut ptr: *const core::ffi::c_void = core::ptr::null();
    let mut handle: sys::esp_partition_mmap_handle_t = 0;
    // SAFETY: maps the whole partition read-only; ptr/handle are valid out-params.
    let err = unsafe {
        sys::esp_partition_mmap(
            part,
            0,
            size,
            sys::esp_partition_mmap_memory_t_ESP_PARTITION_MMAP_DATA,
            &mut ptr,
            &mut handle,
        )
    };
    if err != sys::ESP_OK || ptr.is_null() {
        warn!("blocklist: mmap failed ({err}); common list disabled");
        return &[];
    }
    // SAFETY: the mapping covers `size` bytes and is never released (handle is dropped
    // without esp_partition_munmap), so the slice is valid for 'static.
    let data: &'static [u8] = unsafe { core::slice::from_raw_parts(ptr as *const u8, size) };
    let used = dnscore::blocklist::used_len(data);
    info!("blocklist: {} records mapped from a {size}-byte partition", used / 5);
    &data[..used]
}
