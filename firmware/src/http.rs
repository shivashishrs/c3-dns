//! The web UI and its JSON API (Task 9), on the esp-idf HTTP server: one task at priority 5,
//! below every DNS task (10, 11, 19), at most 2 open connections (the least recently used is
//! closed for a new one).
//!
//! - `GET /`: the UI shell (`ui/index.html`, gzipped at build time), static and without data,
//!   so it needs no authentication.
//! - `GET /api/{overview,top,log,clients,rules,lookup}` and
//!   `POST /api/{rules,records,ban,pause,settings,password}`: HTTP Basic Auth (user `admin`,
//!   the password from the setup portal) on every call; POSTs also need the header
//!   `X-Requested-With: c3-dns`, which a cross-site page cannot send without a CORS preflight
//!   that this server never answers. LAN sources only. No cookies, no CORS headers.
//! - No admin password set: every API call is refused (403) with a hint to use the setup
//!   portal (BOOT hold); there is no way to set one over the LAN.
//!
//! - DNS-rebinding defence: every request (the page included) must carry a `Host` naming the
//!   device (`adblock.local`, the configured `local_name`, or one of its own addresses, with
//!   or without a port); anything else gets 421 before authentication (`dnscore::host`).
//!
//! Password checks cost ~0.5 s (PBKDF2), so a verified Authorization header is remembered by
//! its SHA-256 for 10 idle minutes (4 at most; wiped when the password changes). Failed
//! checks lock a client out (5 failures: 60 s) and all clients together get at most 12 checks
//! a minute, one at a time (`dnscore::webauth`). Decoded passwords and request bodies are
//! wiped after use, best effort: httpd's own header and receive buffers are not ours to wipe.
//!
//! The server has one task, so a client that sends its request slowly holds every other client
//! up. Refusals sent before the body is read (401, 403, 421, 429, 411, 413) stop reading from a
//! client that announced a body, so httpd does not drain it. A watchdog (`watchdog`, run from
//! the main loop) notices when the server task has not come back to its loop for
//! `STALL_SECS` and shortens the receive timeout of every open session, which ends a
//! trickling client within a few seconds.
//!
//! Replies are streamed in chunks of at most `CHUNK` bytes. A handler copies one small item
//! at a time out of the shared state (a log line, a rule) and never holds the state lock
//! across a socket write. The persist lock (held across sector erases) is only `try_lock`ed.
//! Request bodies are at most `json::MAX_BODY` (2 KB), read into an exactly sized buffer.

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use dnscore::api::{self, ApiError, BanOp, RecordOp, RuleOp, TopKind};
use dnscore::budget::{self, AddError};
use dnscore::host::host_allowed;
use dnscore::json::{write_str, write_u64, Object, Sink, MAX_BODY};
use dnscore::persist::utc_string;
use dnscore::secret::{wipe_vec, Secret};
use dnscore::webauth::{parse_basic, Gate, Lockout, SessionCache, MAX_AUTH_HEADER};
use dnscore::{ClientKey, Reason, RuleError, RuleKind};
use esp_idf_svc::handle::RawHandle;
use esp_idf_svc::http::server::{EspHttpConnection, EspHttpServer, Request, Response};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use esp_idf_svc::sys;
use log::{info, warn};

use crate::clock::Clock;
use crate::dns::{unmap, Shared};
use crate::store_dev::SharedPersist;

mod ui {
    include!(concat!(env!("OUT_DIR"), "/ui.rs"));
}

/// Open HTTP connections at most (the least recently used is closed for a new one).
/// Hardening 2 measured three connections each streaming `/api/log` and `/api/overview` under
/// 30 q/s of unique names with the owner budget full: lowest free heap 47.2 KB, under the
/// 52 KB DNS guard (18 queries dropped). Two keep it above (see the hardening-2 report).
pub const MAX_CONNECTIONS: usize = 2;
/// The mDNS host name (`main`) and the name the UI is reached by.
pub const MDNS_HOSTNAME: &str = "adblock";
const MDNS_NAME: &str = "adblock.local";
/// Largest piece written to the socket at once (and the size of the reply buffer).
const CHUNK: usize = 512;
/// Estimated heap the owner's rules, local records and bans may take (`dnscore::budget`).
/// Measured on the spare: see the Task 9 report (heap with the budget full under load).
pub const OWNER_RAM_BUDGET: usize = 10 * 1024;
/// Default and maximum entries of `/api/top`.
const TOP_DEFAULT: usize = 20;
const TOP_MAX: usize = 50;
/// Default entries of `/api/log` (the maximum is the device's log capacity).
const LOG_DEFAULT: usize = 100;
/// The CSRF header a state-changing request must carry, and its value.
const CSRF_HEADER: &str = "X-Requested-With";
const CSRF_VALUE: &str = "c3-dns";
const NO_PASSWORD: &str = "No admin password is set on this device. Hold the BOOT button for 5 seconds: the device \
                           restarts into its setup portal (Wi-Fi C3-DNS-XXXX), where you set Wi-Fi and the admin password.";

type Req<'r, 'c> = Request<&'r mut EspHttpConnection<'c>>;
type Resp<'r, 'c> = Response<&'r mut EspHttpConnection<'c>>;

const SEC_HEADERS: [(&str, &str); 3] = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
];
const API_CSP: (&str, &str) = ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
const NO_STORE: (&str, &str) = ("Cache-Control", "no-store");
const JSON: (&str, &str) = ("Content-Type", "application/json");

/// One password check at a time (the server has one task, but this keeps the bound explicit
/// should that change).
static VERIFYING: AtomicBool = AtomicBool::new(false);
/// Lowest free stack (bytes) seen at the end of a handler, for the status line.
pub static STACK_FREE: AtomicU32 = AtomicU32::new(u32::MAX);

struct AuthState {
    sessions: SessionCache,
    lockout: Lockout,
}

pub struct Ctx {
    shared: Arc<Shared>,
    persist: SharedPersist,
    clock: Arc<Clock>,
    auth: Mutex<AuthState>,
}

impl Ctx {
    fn auth(&self) -> std::sync::MutexGuard<'_, AuthState> {
        self.auth.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn heap() -> (u32, u32) {
    // SAFETY: plain reads of allocator statistics.
    unsafe { (sys::esp_get_free_heap_size(), sys::heap_caps_get_minimum_free_size(sys::MALLOC_CAP_DEFAULT) as u32) }
}

fn note_stack() {
    // SAFETY: null means the calling task.
    let free = unsafe { sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) } as u32;
    STACK_FREE.fetch_min(free, Relaxed);
}

// ---- streamed JSON writer ----

/// A reply body: bytes collect in a `CHUNK`-byte buffer that is sent when full. After a
/// failed write everything else is dropped (`failed`), so loops can stop early.
struct Out<W: Write> {
    w: W,
    buf: [u8; CHUNK],
    len: usize,
    failed: bool,
    comma: bool,
}

impl<W: Write> Sink for Out<W> {
    fn put(&mut self, mut b: &[u8]) {
        while !b.is_empty() {
            if self.len == CHUNK {
                self.flush();
            }
            let n = (CHUNK - self.len).min(b.len());
            self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
            self.len += n;
            b = &b[n..];
        }
    }
}

impl<W: Write> Out<W> {
    fn new(w: W) -> Self {
        Out { w, buf: [0; CHUNK], len: 0, failed: false, comma: false }
    }

    fn flush(&mut self) {
        if self.len > 0 && !self.failed && self.w.write_all(&self.buf[..self.len]).is_err() {
            self.failed = true;
        }
        self.len = 0;
    }

    fn finish(mut self) -> anyhow::Result<()> {
        self.flush();
        if self.failed {
            anyhow::bail!("client went away");
        }
        Ok(())
    }

    fn sep(&mut self) {
        if self.comma {
            self.put(b",");
        }
    }

    fn open(&mut self, c: &str) {
        self.sep();
        self.put(c.as_bytes());
        self.comma = false;
    }

    fn close(&mut self, c: &str) {
        self.put(c.as_bytes());
        self.comma = true;
    }

    fn key(&mut self, k: &str) {
        self.sep();
        write_str(self, k);
        self.put(b":");
        self.comma = false;
    }

    fn s(&mut self, v: &str) {
        self.sep();
        write_str(self, v);
        self.comma = true;
    }

    fn n(&mut self, v: u64) {
        self.sep();
        write_u64(self, v);
        self.comma = true;
    }

    fn b(&mut self, v: bool) {
        self.sep();
        self.put(if v { b"true" } else { b"false" });
        self.comma = true;
    }

    fn null(&mut self) {
        self.sep();
        self.put(b"null");
        self.comma = true;
    }

    fn opt_s(&mut self, v: Option<&str>) {
        match v {
            Some(s) => self.s(s),
            None => self.null(),
        }
    }

    fn ip(&mut self, a: &IpAddr) {
        // An address is at most 45 characters: format into a stack buffer, no allocation.
        let mut buf = StackStr::<48>::new();
        let _ = std::fmt::Write::write_fmt(&mut buf, format_args!("{a}"));
        self.s(buf.as_str());
    }

    fn client(&mut self, c: &ClientKey) {
        self.ip(&key_ip(c));
    }
}

/// A small fixed-capacity string for formatting without the heap.
struct StackStr<const N: usize> {
    b: [u8; N],
    len: usize,
}

impl<const N: usize> StackStr<N> {
    fn new() -> Self {
        StackStr { b: [0; N], len: 0 }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.b[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> std::fmt::Write for StackStr<N> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let end = self.len + s.len();
        if end > N {
            return Err(std::fmt::Error);
        }
        self.b[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn key_ip(c: &ClientKey) -> IpAddr {
    match c {
        ClientKey::V4(a) => IpAddr::V4(*a),
        ClientKey::V6(a) => IpAddr::V6(*a),
    }
}

fn qtype_name(t: u16) -> Cow<'static, str> {
    Cow::Borrowed(match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        n => return Cow::Owned(format!("TYPE{n}")),
    })
}

// ---- responses ----

/// Start a JSON reply with the API headers.
fn start<'r, 'c>(req: Req<'r, 'c>, status: u16, extra: &[(&str, &str)]) -> anyhow::Result<Out<Resp<'r, 'c>>> {
    let mut h: Vec<(&str, &str)> = Vec::with_capacity(8);
    h.extend_from_slice(&SEC_HEADERS);
    h.extend_from_slice(&[API_CSP, NO_STORE, JSON]);
    h.extend_from_slice(extra);
    // httpd knows no reason phrase for 421.
    let reason = (status == 421).then_some("Misdirected Request");
    Ok(Out::new(req.into_response(status, reason, &h)?))
}

/// A refusal or error, sent as `{"error": message, "code": code}`.
struct Fail {
    status: u16,
    code: &'static str,
    msg: Cow<'static, str>,
    retry_after: Option<u32>,
    /// Add `WWW-Authenticate` (only for clients that are not the UI: the UI shows its own
    /// login form, while curl or a typed URL get the browser's prompt).
    challenge: bool,
    /// Stop reading from the client after the reply (an oversized body is not drained).
    close: bool,
}

impl Fail {
    fn new(status: u16, code: &'static str, msg: impl Into<Cow<'static, str>>) -> Self {
        Fail { status, code, msg: msg.into(), retry_after: None, challenge: false, close: false }
    }

    fn api(e: ApiError) -> Self {
        Fail::new(400, "invalid", e.0)
    }

    fn send(self, mut req: Req<'_, '_>) -> anyhow::Result<()> {
        let fd = if self.close { sockfd(&mut req) } else { None };
        let retry = self.retry_after.map(|s| s.to_string());
        let mut extra: Vec<(&str, &str)> = Vec::with_capacity(2);
        if let Some(r) = retry.as_deref() {
            extra.push(("Retry-After", r));
        }
        if self.challenge {
            extra.push(("WWW-Authenticate", "Basic realm=\"C3-DNS\", charset=\"UTF-8\""));
        }
        let mut o = start(req, self.status, &extra)?;
        o.open("{");
        o.key("error");
        o.s(&self.msg);
        o.key("code");
        o.s(self.code);
        o.close("}");
        let r = o.finish();
        stop_reading(fd);
        r
    }
}

/// This request's session socket.
pub fn sockfd(req: &mut Req<'_, '_>) -> Option<i32> {
    let h = req.connection().raw_connection().ok()?.handle();
    // SAFETY: the request handle is valid for the duration of the handler.
    let fd = unsafe { sys::httpd_req_to_sockfd(h) };
    (fd >= 0).then_some(fd)
}

/// Call after the reply: stop reading from the session, so httpd fails to drain a body it was
/// promised and closes the session instead of waiting for it.
pub fn stop_reading(fd: Option<i32>) {
    if let Some(fd) = fd {
        // SAFETY: shuts down reading on this session's own socket.
        unsafe { sys::lwip_shutdown(fd, sys::SHUT_RD as i32) };
    }
}

/// The request announces a body (that has not been read yet).
fn has_body(req: &Req<'_, '_>) -> bool {
    if req.header("Transfer-Encoding").is_some() {
        return true;
    }
    match req.header("Content-Length") {
        None => false,
        Some(v) => v.trim().parse::<u64>().map_or(true, |n| n > 0),
    }
}

/// The device address this connection arrived on.
fn local_ip(fd: i32) -> Option<IpAddr> {
    // lwIP's BSD-style sockaddr: len (u8), family (u8), port (u16), then the address.
    let mut sa = [0u32; 8];
    let mut len: sys::socklen_t = core::mem::size_of_val(&sa) as _;
    // SAFETY: `sa` is a writable, aligned 32-byte buffer and `len` its size.
    let r = unsafe { sys::lwip_getsockname(fd, sa.as_mut_ptr().cast(), &mut len) };
    if r != 0 {
        return None;
    }
    let b: Vec<u8> = sa.iter().flat_map(|w| w.to_ne_bytes()).collect();
    match b[1] as u32 {
        f if f == sys::AF_INET => Some(IpAddr::V4(Ipv4Addr::new(b[4], b[5], b[6], b[7]))),
        f if f == sys::AF_INET6 => {
            let a: [u8; 16] = b[8..24].try_into().ok()?;
            Some(unmap(IpAddr::V6(std::net::Ipv6Addr::from(a))))
        }
        _ => None,
    }
}

/// The `Host` header names this device (`dnscore::host`).
fn host_ok(ctx: &Ctx, req: &Req<'_, '_>, fd: Option<i32>) -> bool {
    let (name, mut addrs) = {
        let st = ctx.shared.lock();
        (st.settings.local_name.clone(), st.engine.own().map(|(_, a)| a.to_vec()).unwrap_or_default())
    };
    addrs.extend(fd.and_then(local_ip));
    host_allowed(req.header("Host"), &[MDNS_NAME, &name], &addrs)
}

fn wrong_host() -> Fail {
    Fail::new(
        421,
        "host",
        "This name does not belong to this device. Open the UI at http://adblock.local/ or at the device's address.",
    )
}

fn ok_reply(req: Req<'_, '_>, extra: impl FnOnce(&mut Out<Resp<'_, '_>>)) -> anyhow::Result<()> {
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("ok");
    o.b(true);
    extra(&mut o);
    o.close("}");
    o.finish()
}

// ---- authentication ----

fn now_ms(ctx: &Ctx) -> u64 {
    ctx.shared.now_ms()
}

/// LAN source, CSRF header (POST), password set, not locked out, valid Basic credentials.
/// Returns the client.
fn authorize(ctx: &Ctx, req: &mut Req<'_, '_>, post: bool) -> Result<ClientKey, Fail> {
    let peer = req
        .connection()
        .raw_connection()
        .and_then(|r| r.source_ipv6())
        .map_err(|_| Fail::new(500, "internal", "Cannot read the client address."))?;
    let ip = unmap(IpAddr::V6(peer));
    if !ctx.shared.lock().lan.is_lan(ip) {
        return Err(Fail::new(403, "lan_only", "The web UI answers only on the local network."));
    }
    let client = ClientKey::from_ip(ip);
    let from_ui = req.header(CSRF_HEADER) == Some(CSRF_VALUE);
    if post && !from_ui {
        return Err(Fail::new(
            403,
            "csrf",
            "Changes need the header X-Requested-With: c3-dns (the web UI sends it).",
        ));
    }
    if !crate::creds::admin_set() {
        return Err(Fail::new(403, "no_password", NO_PASSWORD));
    }
    let now = now_ms(ctx);
    if let Some(s) = ctx.auth().lockout.locked(client, now) {
        return Err(locked(s));
    }
    let unauthorized = |msg: &'static str| Fail { challenge: !from_ui, ..Fail::new(401, "auth", msg) };
    let Some(h) = req.header("Authorization") else {
        return Err(unauthorized("Log in with user admin and the admin password."));
    };
    if h.len() > MAX_AUTH_HEADER {
        ctx.auth().lockout.failed(client, now);
        return Err(unauthorized("Wrong user name or password."));
    }
    let digest = crate::creds::sha256(h.as_bytes());
    if ctx.auth().sessions.check(&digest, now) {
        return Ok(client);
    }
    let Ok(cred) = parse_basic(h) else {
        ctx.auth().lockout.failed(client, now);
        return Err(unauthorized("Wrong user name or password."));
    };
    let ok = verify(ctx, client, &cred.user, cred.password)?;
    if ok {
        ctx.auth().sessions.insert(digest, now_ms(ctx));
        Ok(client)
    } else {
        Err(unauthorized("Wrong user name or password."))
    }
}

fn locked(secs: u32) -> Fail {
    Fail {
        retry_after: Some(secs),
        ..Fail::new(429, "locked", format!("Too many failed logins from this device: try again in {secs} s."))
    }
}

/// One PBKDF2 check, through the lockout and the global budget. The password is wiped when
/// `password` is dropped (best effort). `Ok(false)`: wrong password (counted); `Err`: refused
/// without checking.
fn verify(ctx: &Ctx, client: ClientKey, user: &str, password: Secret) -> Result<bool, Fail> {
    let now = now_ms(ctx);
    let gate = ctx.auth().lockout.before_verify(client, now);
    let result = match gate {
        Gate::Locked { retry_after_secs } => Err(locked(retry_after_secs)),
        Gate::Busy { retry_after_secs } => Err(Fail {
            retry_after: Some(retry_after_secs),
            ..Fail::new(429, "busy", "Too many logins on this device just now: try again in a minute.")
        }),
        Gate::Ok if VERIFYING.swap(true, Relaxed) => Err(Fail {
            retry_after: Some(1),
            ..Fail::new(429, "busy", "Another login is being checked: try again.")
        }),
        Gate::Ok => {
            // The auth lock is not held during the ~0.5 s hash.
            let ok = crate::creds::verify_admin(user, password.as_str());
            VERIFYING.store(false, Relaxed);
            let mut a = ctx.auth();
            if ok {
                a.lockout.succeeded(client);
                Ok(true)
            } else {
                // This attempt still gets its plain refusal; the lockout applies from the next one.
                if a.lockout.failed(client, now_ms(ctx)) {
                    drop(a);
                    warn!("http: a client failed {} logins and is locked out", dnscore::webauth::MAX_FAILURES);
                }
                Ok(false)
            }
        }
    };
    drop(password);
    result
}

/// Read and parse a JSON body of at most `MAX_BODY` bytes (refused before reading if larger).
fn read_body(req: &mut Req<'_, '_>) -> Result<Object, Fail> {
    let len = req.header("Content-Length").and_then(|v| v.trim().parse::<usize>().ok());
    let len = match len {
        Some(n) if n <= MAX_BODY => n,
        Some(_) => {
            return Err(Fail {
                close: true,
                ..Fail::new(413, "too_large", format!("The request body is larger than {MAX_BODY} bytes."))
            })
        }
        // Possibly a chunked body: never drained.
        None => return Err(Fail { close: true, ..Fail::new(411, "length", "The request needs a Content-Length.") }),
    };
    let mut body: Vec<u8> = Vec::new();
    if body.try_reserve_exact(len).is_err() {
        return Err(Fail::new(503, "memory", "The device is short of memory: try again shortly."));
    }
    body.resize(len, 0);
    let mut got = 0;
    while got < len {
        match req.read(&mut body[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    if got != len {
        wipe_vec(&mut body);
        return Err(Fail::new(400, "incomplete", "The request body arrived incomplete."));
    }
    let r = api::body(&body).map_err(Fail::api);
    // The raw body may hold passwords (`/api/password`); the parsed object wipes its own copy.
    wipe_vec(&mut body);
    r
}

/// What an authorised handler gets.
struct Call {
    uri: String,
    body: Option<Object>,
}

fn serve(
    ctx: &Ctx,
    mut req: Req<'_, '_>,
    post: bool,
    h: impl FnOnce(&Ctx, Req<'_, '_>, Call) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let fd = sockfd(&mut req);
    let announced = has_body(&req);
    // A refusal before the body is read closes the connection instead of draining the body.
    let early = |f: Fail| Fail { close: f.close || announced, ..f };
    let checked = if host_ok(ctx, &req, fd) { authorize(ctx, &mut req, post) } else { Err(wrong_host()) };
    let r = match checked {
        Ok(_) => {
            let body = if post {
                match read_body(&mut req) {
                    Ok(o) => Some(o),
                    Err(f) => return f.send(req),
                }
            } else {
                None
            };
            let uri = req.uri().to_string();
            h(ctx, req, Call { uri, body })
        }
        Err(f) => early(f).send(req),
    };
    note_stack();
    r
}

// ---- GET handlers ----

fn overview(ctx: &Ctx, req: Req<'_, '_>) -> anyhow::Result<()> {
    let now = now_ms(ctx);
    let (free, min) = heap();
    struct Snap {
        totals: (u64, u64),
        paused_for: u32,
        warning: Option<String>,
        list: usize,
        usage: budget::Usage,
        clients: usize,
        settings: dnscore::store::Settings,
        log_cap: usize,
    }
    let snap = {
        let st = ctx.shared.lock();
        Snap {
            totals: st.stats.totals(),
            paused_for: st.engine.paused_for(now),
            warning: st.warning.clone(),
            list: st.engine.list_len(),
            usage: budget::usage(&st.engine),
            clients: st.stats.clients().len(),
            settings: st.settings.clone(),
            log_cap: crate::dns::log_cap(&st),
        }
    };
    // The persist lock is held across flash erases: never wait for it.
    let save = ctx.persist.try_lock().ok().map(|p| {
        (p.status.last_save_unix, p.read_only(), p.status.over_budget, p.status.skipped_low_heap)
    });
    let dirty = ctx.shared.lock().dirty.is_dirty();
    // Owner data over the budget (loaded at boot, or added by a debug hook): a warning for the UI.
    let warning = match (snap.warning, budget::over_budget_warning(&snap.usage, OWNER_RAM_BUDGET)) {
        (Some(a), Some(b)) => Some(format!("{a} {b}")),
        (a, b) => a.or(b),
    };
    let c = &ctx.shared.counters;
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("allowed");
    o.n(snap.totals.0);
    o.key("blocked");
    o.n(snap.totals.1);
    o.key("paused_for");
    o.n(u64::from(snap.paused_for));
    o.key("heap_free");
    o.n(u64::from(free));
    o.key("heap_min");
    o.n(u64::from(min));
    o.key("uptime");
    o.n(now / 1000);
    o.key("time");
    o.opt_s(ctx.clock.now().map(utc_string).as_deref());
    o.key("warning");
    o.opt_s(warning.as_deref());
    o.key("list_size");
    o.n(snap.list as u64);
    o.key("clients");
    o.n(snap.clients as u64);
    o.key("local_name");
    o.s(&snap.settings.local_name);
    o.key("settings");
    o.open("{");
    o.key("upstreams");
    o.open("[");
    for a in &snap.settings.upstreams {
        o.ip(a);
    }
    o.close("]");
    o.key("rate_burst");
    o.n(u64::from(snap.settings.rate_burst));
    o.key("rate_per_sec");
    o.n(u64::from(snap.settings.rate_per_sec));
    o.key("local_name");
    o.s(&snap.settings.local_name);
    o.close("}");
    o.key("log_cap");
    o.n(snap.log_cap as u64);
    o.key("owner");
    o.open("{");
    for (k, v) in [
        ("rules", snap.usage.rules),
        ("records", snap.usage.records),
        ("bans", snap.usage.bans),
        ("entries", snap.usage.entries()),
        ("used", snap.usage.ram),
        ("budget", OWNER_RAM_BUDGET),
        ("encoded", snap.usage.encoded),
    ] {
        o.key(k);
        o.n(v as u64);
    }
    o.close("}");
    o.key("save");
    o.open("{");
    o.key("dirty");
    o.b(dirty);
    if let Some((last, ro, over, low)) = save {
        o.key("last");
        o.opt_s(last.map(utc_string).as_deref());
        o.key("read_only");
        o.b(ro);
        o.key("over_budget");
        o.n(u64::from(over));
        o.key("skipped_low_heap");
        o.n(u64::from(low));
    }
    o.close("}");
    o.key("dns");
    o.open("{");
    let g = |a: &AtomicU32| u64::from(a.load(Relaxed));
    for (k, v) in [
        ("rx", g(&c.rx)),
        ("sent", g(&c.sent)),
        ("cache_hit", g(&c.cache_hit)),
        ("forwarded", g(&c.forwarded)),
        ("lowmem", g(&c.lowmem)),
        ("rate_limited", g(&c.limited) + g(&c.global_drop)),
        ("banned", g(&c.banned)),
        ("servfail", g(&c.servfail)),
        ("stale", g(&c.stale)),
    ] {
        o.key(k);
        o.n(v);
    }
    o.close("}");
    o.close("}");
    o.finish()
}

fn top(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let kind = match api::top_kind(api::query_param(&call.uri, "kind").as_deref()) {
        Ok(k) => k,
        Err(e) => return Fail::api(e).send(req),
    };
    let n = api::clamp_n(api::query_param(&call.uri, "n").as_deref(), TOP_DEFAULT, TOP_MAX);
    let blocked = kind == TopKind::Blocked;
    let order = ctx.shared.lock().stats.top_order(blocked);
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("kind");
    o.s(if blocked { "blocked" } else { "queried" });
    o.key("items");
    o.open("[");
    let mut name = String::with_capacity(256);
    for &i in order.iter().take(n) {
        let count = {
            let st = ctx.shared.lock();
            match st.stats.top_slot(blocked, i) {
                Some((nm, c)) => {
                    name.clear();
                    name.push_str(nm);
                    c
                }
                None => continue,
            }
        };
        o.open("{");
        o.key("name");
        o.s(&name);
        o.key("count");
        o.n(u64::from(count));
        o.close("}");
        if o.failed {
            break;
        }
    }
    o.close("]");
    o.close("}");
    o.finish()
}

fn log(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let (cap, mut seq) = {
        let st = ctx.shared.lock();
        (crate::dns::log_cap(&st), st.stats.log().end_seq())
    };
    let n = api::clamp_n(api::query_param(&call.uri, "n").as_deref(), LOG_DEFAULT.min(cap), cap);
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("cap");
    o.n(cap as u64);
    o.key("now");
    o.n(now_ms(ctx) / 1000);
    o.key("items");
    o.open("[");
    let (mut name, mut reason) = (String::with_capacity(256), String::with_capacity(256));
    for _ in 0..n {
        if seq == 0 {
            break;
        }
        seq -= 1;
        let (ts, client, qtype, blocked) = {
            let st = ctx.shared.lock();
            let Some(e) = st.stats.log().by_seq(seq) else { break };
            name.clear();
            name.push_str(&e.name);
            reason.clear();
            reason.push_str(&e.reason);
            (e.ts, e.client, e.qtype, e.blocked)
        };
        o.open("{");
        o.key("t");
        o.n(ts);
        o.key("client");
        o.client(&client);
        o.key("name");
        o.s(&name);
        o.key("type");
        o.s(&qtype_name(qtype));
        o.key("blocked");
        o.b(blocked);
        o.key("reason");
        o.s(&reason);
        o.close("}");
        if o.failed {
            break;
        }
    }
    o.close("]");
    o.close("}");
    o.finish()
}

fn clients(ctx: &Ctx, req: Req<'_, '_>) -> anyhow::Result<()> {
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("items");
    o.open("[");
    let mut i = 0;
    loop {
        let (row, banned) = {
            let st = ctx.shared.lock();
            let Some(r) = st.stats.clients().row(i) else { break };
            (r, st.engine.bans().contains(&r.client))
        };
        i += 1;
        o.open("{");
        o.key("client");
        o.client(&row.client);
        o.key("allowed");
        o.n(u64::from(row.allowed));
        o.key("blocked");
        o.n(u64::from(row.blocked));
        o.key("banned");
        o.b(banned);
        o.close("}");
        if o.failed {
            break;
        }
    }
    o.close("]");
    o.key("banned");
    write_bans(ctx, &mut o);
    o.close("}");
    o.finish()
}

fn write_bans<W: Write>(ctx: &Ctx, o: &mut Out<W>) {
    o.open("[");
    let mut i = 0;
    loop {
        let Some(b) = ctx.shared.lock().engine.bans().get(i).copied() else { break };
        i += 1;
        o.client(&b);
    }
    o.close("]");
}

fn rules(ctx: &Ctx, req: Req<'_, '_>) -> anyhow::Result<()> {
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("rules");
    o.open("[");
    let mut text = String::with_capacity(256);
    let mut i = 0;
    loop {
        let kind = {
            let st = ctx.shared.lock();
            let Some((k, p)) = st.engine.rules().entries().get(i) else { break };
            text.clear();
            text.push_str(p);
            *k
        };
        i += 1;
        o.open("{");
        o.key("kind");
        o.s(if kind == RuleKind::Allow { "allow" } else { "block" });
        o.key("pattern");
        o.s(&text);
        o.close("}");
        if o.failed {
            break;
        }
    }
    o.close("]");
    o.key("records");
    o.open("[");
    let mut ips: Vec<IpAddr> = Vec::with_capacity(dnscore::store::MAX_RECORD_IPS);
    let mut i = 0;
    loop {
        {
            // A map: walking to entry i is O(i), at most 100 entries.
            let st = ctx.shared.lock();
            let Some((n, a)) = st.engine.records().iter().nth(i) else { break };
            text.clear();
            text.push_str(n);
            ips.clear();
            ips.extend_from_slice(a);
        }
        i += 1;
        o.open("{");
        o.key("name");
        o.s(&text);
        o.key("ips");
        o.open("[");
        for a in &ips {
            o.ip(a);
        }
        o.close("]");
        o.close("}");
        if o.failed {
            break;
        }
    }
    o.close("]");
    o.key("bans");
    write_bans(ctx, &mut o);
    o.key("own");
    {
        let own = {
            let st = ctx.shared.lock();
            st.engine.own().map(|(n, a)| {
                text.clear();
                text.push_str(n);
                ips.clear();
                ips.extend_from_slice(a);
            })
        };
        match own {
            Some(()) => {
                o.open("{");
                o.key("name");
                o.s(&text);
                o.key("ips");
                o.open("[");
                for a in &ips {
                    o.ip(a);
                }
                o.close("]");
                o.close("}");
            }
            None => o.null(),
        }
    }
    o.key("budget");
    o.n(OWNER_RAM_BUDGET as u64);
    o.close("}");
    o.finish()
}

fn lookup(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let Some(name) = api::query_param(&call.uri, "d").and_then(|d| dnscore::normalize(d.trim())) else {
        return Fail::new(400, "invalid", "Enter a valid domain name.").send(req);
    };
    let (d, own, last) = {
        let st = ctx.shared.lock();
        let d = st.engine.explain(&name);
        let own = st.engine.own().is_some_and(|(n, _)| n == name);
        // The newest log line for this name: the only place a CNAME-uncloaked block shows.
        let log = st.stats.log();
        let mut last = None;
        let end = log.end_seq();
        for seq in (end.saturating_sub(log.len() as u64)..end).rev() {
            if let Some(e) = log.by_seq(seq).filter(|e| e.name == name) {
                last = Some((e.blocked, e.reason.clone(), e.ts));
                break;
            }
        }
        (d, own, last)
    };
    let (action, source, rule, matched): (&str, &str, Option<&str>, Option<&str>) = match &d.reason {
        Reason::CustomAllow(p) => ("allow", "rule", Some(p.as_str()), None),
        Reason::CustomBlock(p) => ("block", "rule", Some(p.as_str()), None),
        Reason::List(n) => ("block", "list", None, Some(n.as_str())),
        Reason::LocalRecord(_) if own => ("local", "own", None, None),
        Reason::LocalRecord(_) => ("local", "record", None, None),
        Reason::Cname { via, rule } => ("block", "cname", Some(rule.as_str()), Some(via.as_str())),
        Reason::Paused | Reason::Banned | Reason::Default => ("none", "none", None, None),
    };
    let mut o = start(req, 200, &[])?;
    o.open("{");
    o.key("name");
    o.s(&name);
    o.key("action");
    o.s(action);
    o.key("source");
    o.s(source);
    o.key("rule");
    o.opt_s(rule);
    o.key("matched");
    o.opt_s(matched);
    o.key("last");
    match &last {
        Some((blocked, reason, ts)) => {
            o.open("{");
            o.key("blocked");
            o.b(*blocked);
            o.key("reason");
            o.s(reason);
            o.key("t");
            o.n(*ts);
            o.key("cname");
            o.b(reason.starts_with("cname "));
            o.close("}");
        }
        None => o.null(),
    }
    o.key("now");
    o.n(now_ms(ctx) / 1000);
    o.close("}");
    o.finish()
}

// ---- POST handlers ----

/// Why an owner change was refused.
enum Refused {
    Add(AddError),
    Missing,
}

impl Refused {
    fn fail(self) -> Fail {
        match self {
            Refused::Add(AddError::Exists | AddError::Rule(RuleError::Duplicate)) => {
                Fail::new(409, "exists", api::rule_error_message(RuleError::Duplicate))
            }
            Refused::Add(AddError::Rule(e)) => Fail::new(400, "invalid", api::rule_error_message(e)),
            Refused::Add(AddError::Budget(b)) => Fail::new(409, "budget", b.message()),
            Refused::Missing => Fail::new(404, "missing", "No such entry."),
        }
    }
}

fn body_of(call: &Call) -> &Object {
    static EMPTY: std::sync::OnceLock<Object> = std::sync::OnceLock::new();
    call.body.as_ref().unwrap_or_else(|| EMPTY.get_or_init(Object::default))
}

fn post_rules(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let r = match api::rule_req(body_of(&call)) {
        Ok(r) => r,
        Err(e) => return Fail::api(e).send(req),
    };
    let res = match r.op {
        // A duplicate is "exists" even when the budget is full (checked first).
        RuleOp::Add => ctx
            .shared
            .mutate(|st| budget::add_rule(&mut st.engine, r.kind, &r.pattern, OWNER_RAM_BUDGET).map_err(Refused::Add)),
        RuleOp::Remove => ctx.shared.mutate(|st| {
            if st.engine.rules_mut().remove(r.kind, &r.pattern) {
                Ok(())
            } else {
                Err(Refused::Missing)
            }
        }),
    };
    match res {
        Ok(()) => {
            info!("http: rule {:?} {:?} ({} bytes)", r.op_name(), r.kind, r.pattern.len());
            ok_reply(req, |o| {
                o.key("pattern");
                o.s(&r.pattern);
            })
        }
        Err(e) => e.fail().send(req),
    }
}

trait OpName {
    fn op_name(&self) -> &'static str;
}

impl OpName for api::RuleReq {
    fn op_name(&self) -> &'static str {
        match self.op {
            RuleOp::Add => "add",
            RuleOp::Remove => "remove",
        }
    }
}

fn post_records(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let r = match api::record_req(body_of(&call)) {
        Ok(r) => r,
        Err(e) => return Fail::api(e).send(req),
    };
    let res = match r.op {
        // The same name and addresses again is "exists"; a replacement pays only the difference.
        RecordOp::Add => ctx.shared.mutate(|st| {
            budget::set_record(&mut st.engine, &r.name, r.ips.clone(), OWNER_RAM_BUDGET).map_err(Refused::Add)
        }),
        RecordOp::Remove => ctx.shared.mutate(|st| {
            if st.engine.records_mut().remove(&r.name) {
                Ok(())
            } else {
                Err(Refused::Missing)
            }
        }),
    };
    match res {
        Ok(()) => ok_reply(req, |o| {
            o.key("name");
            o.s(&r.name);
        }),
        Err(e) => e.fail().send(req),
    }
}

fn post_ban(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let r = match api::ban_req(body_of(&call)) {
        Ok(r) => r,
        Err(e) => return Fail::api(e).send(req),
    };
    let res = ctx.shared.mutate(|st| match r.op {
        BanOp::Ban => {
            if st.engine.bans().contains(&r.client) {
                return Err(Fail::new(409, "exists", "That client is already banned."));
            }
            budget::check(&budget::usage(&st.engine), budget::ban_cost(r.client), OWNER_RAM_BUDGET)
                .map_err(|b| Refused::Add(AddError::Budget(b)).fail())?;
            if st.engine.ban(r.client) {
                Ok(())
            } else {
                Err(Fail::new(409, "full", "The ban list is full (64 clients)."))
            }
        }
        BanOp::Unban => {
            if st.engine.unban(r.client) {
                Ok(())
            } else {
                Err(Refused::Missing.fail())
            }
        }
    });
    match res {
        Ok(()) => ok_reply(req, |o| {
            o.key("client");
            o.client(&r.client);
        }),
        Err(f) => f.send(req),
    }
}

fn post_pause(ctx: &Ctx, req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let secs = match api::pause_req(body_of(&call)) {
        Ok(s) => s,
        Err(e) => return Fail::api(e).send(req),
    };
    let now = now_ms(ctx);
    let left = {
        // Pause is not persisted: no `mutate`.
        let mut st = ctx.shared.lock();
        if secs == 0 {
            st.engine.resume();
        } else {
            st.engine.pause(secs, now);
        }
        st.engine.paused_for(now)
    };
    info!("http: {}", if secs == 0 { "blocking resumed".to_string() } else { format!("blocking paused for {secs} s") });
    ok_reply(req, |o| {
        o.key("paused_for");
        o.n(u64::from(left));
    })
}

fn post_settings(ctx: &Ctx, mut req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    // The device's own addresses: an upstream equal to one of them would loop.
    let local = sockfd(&mut req).and_then(local_ip);
    let (cur, mut own) = {
        let st = ctx.shared.lock();
        (st.settings.clone(), st.engine.own().map(|(_, a)| a.to_vec()).unwrap_or_default())
    };
    own.extend(local);
    let next = match api::settings_req(body_of(&call), &cur, &own) {
        Ok(s) => s,
        Err(e) => return Fail::api(e).send(req),
    };
    let rate_changed = (next.rate_burst, next.rate_per_sec) != (cur.rate_burst, cur.rate_per_sec);
    let applied = ctx.shared.mutate(|st| {
        // Validated against `cur`: refuse if the settings changed meanwhile or the result is
        // out of bounds, rather than overwrite them.
        if st.settings != cur {
            return Err(Fail::new(409, "changed", "The settings changed meanwhile: reload and try again."));
        }
        if !dnscore::store::settings_valid(&next) {
            return Err(Fail::new(400, "invalid", "Those settings are out of bounds."));
        }
        if rate_changed {
            st.admission.clients =
                dnscore::limit::RateLimiter::new(next.rate_burst, next.rate_per_sec, crate::dns::LIMITER_CLIENTS);
        }
        st.settings = next.clone();
        Ok(())
    });
    if let Err(f) = applied {
        return f.send(req);
    }
    info!(
        "http: settings changed: {} upstreams, rate {}/{} per s, local name {}",
        next.upstreams.len(),
        next.rate_burst,
        next.rate_per_sec,
        next.local_name
    );
    ok_reply(req, |o| {
        o.key("local_name");
        o.s(&next.local_name);
    })
}

fn post_password(ctx: &Ctx, mut req: Req<'_, '_>, call: Call) -> anyhow::Result<()> {
    let p = match api::password_req(body_of(&call)) {
        Ok(p) => p,
        Err(e) => return Fail::api(e).send(req),
    };
    drop(call);
    let client = match req.connection().raw_connection().and_then(|r| r.source_ipv6()) {
        Ok(a) => ClientKey::from_ip(unmap(IpAddr::V6(a))),
        Err(_) => ClientKey::V4(Ipv4Addr::UNSPECIFIED),
    };
    let api::PasswordReq { old, new } = p;
    // The current password again, even if the session cache let this request in.
    match verify(ctx, client, dnscore::auth::ADMIN_USER, old) {
        Ok(true) => {}
        Ok(false) => return Fail::new(403, "wrong_password", "The current password is wrong.").send(req),
        Err(f) => return f.send(req),
    }
    let r = crate::creds::set_admin(new.as_str());
    drop(new); // wiped on drop
    match r {
        Ok(()) => {
            ctx.auth().sessions.clear();
            ok_reply(req, |_| {})
        }
        Err(e) => {
            warn!("http: password change failed: {e}");
            Fail::new(500, "save_failed", "Saving the new password failed; the old one is still valid.").send(req)
        }
    }
}

// ---- static page and registration ----

fn page(ctx: &Ctx, mut req: Req<'_, '_>) -> anyhow::Result<()> {
    let fd = sockfd(&mut req);
    if !host_ok(ctx, &req, fd) {
        let close = has_body(&req);
        return Fail { close, ..wrong_host() }.send(req);
    }
    let fresh = req.header("If-None-Match") == Some(ui::ETAG);
    let mut h: Vec<(&str, &str)> = Vec::with_capacity(9);
    h.extend_from_slice(&SEC_HEADERS);
    h.extend_from_slice(&[
        ("Content-Security-Policy", ui::PAGE_CSP),
        ("Cache-Control", "no-cache"),
        ("ETag", ui::ETAG),
    ]);
    if fresh {
        req.into_response(304, None, &h)?;
        return Ok(());
    }
    h.extend_from_slice(&[("Content-Type", "text/html; charset=utf-8"), ("Content-Encoding", "gzip")]);
    let mut resp = req.into_response(200, None, &h)?;
    // Straight from flash, in small pieces.
    for c in ui::INDEX_GZ.chunks(CHUNK) {
        resp.write_all(c)?;
    }
    note_stack();
    Ok(())
}

fn not_found(req: Req<'_, '_>) -> anyhow::Result<()> {
    Fail::new(404, "not_found", "No such page.").send(req)
}

/// Register the UI and API handlers.
pub fn register(
    http: &mut EspHttpServer<'static>,
    shared: Arc<Shared>,
    persist: SharedPersist,
    clock: Arc<Clock>,
) -> anyhow::Result<()> {
    let ctx = Arc::new(Ctx {
        shared,
        persist,
        clock,
        auth: Mutex::new(AuthState { sessions: SessionCache::default(), lockout: Lockout::default() }),
    });
    let c = ctx.clone();
    http.fn_handler::<anyhow::Error, _>("/", Method::Get, move |req| page(&c, req))?;
    macro_rules! get {
        ($path:expr, $f:expr) => {{
            let c = ctx.clone();
            http.fn_handler::<anyhow::Error, _>($path, Method::Get, move |req| serve(&c, req, false, $f))?;
        }};
    }
    macro_rules! post {
        ($path:expr, $f:expr) => {{
            let c = ctx.clone();
            http.fn_handler::<anyhow::Error, _>($path, Method::Post, move |req| serve(&c, req, true, $f))?;
        }};
    }
    get!("/api/overview", |c, r, _| overview(c, r));
    get!("/api/top", top);
    get!("/api/log", log);
    get!("/api/clients", |c, r, _| clients(c, r));
    get!("/api/rules", |c, r, _| rules(c, r));
    get!("/api/lookup", lookup);
    post!("/api/rules", post_rules);
    post!("/api/records", post_records);
    post!("/api/ban", post_ban);
    post!("/api/pause", post_pause);
    post!("/api/settings", post_settings);
    post!("/api/password", post_password);
    info!(
        "http: web UI at / ({} bytes gzipped), API under /api (Basic auth), owner budget {} bytes",
        ui::INDEX_GZ.len(),
        OWNER_RAM_BUDGET
    );
    Ok(())
}

// ---- stall watchdog ----

/// Seconds the server task may stay away from its loop (one request being received or sent)
/// before every open session's socket timeouts are cut. One loop pass serves at most
/// `MAX_CONNECTIONS` requests, each well under a second (a password check is ~0.5 s). Kept
/// short because a session the task is not reading keeps its received segments queued, and
/// each pins one of the 8 Wi-Fi RX buffers that DNS needs too.
const STALL_SECS: u32 = 3;
/// Receive/send timeout given to every open session while the server is stalled (ms).
const STALL_TIMEOUT_MS: u32 = 300;
/// httpd's own per-call socket timeout (esp-idf-svc's fixed `recv_wait_timeout`/`send_wait_timeout`).
const NORMAL_TIMEOUT_MS: u32 = 5000;

static SERVER: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());
/// Uptime second (+1, so 0 means "none") at which the pending liveness probe was queued.
static PROBE_AT: AtomicU32 = AtomicU32::new(0);
/// Session timeouts are cut (restored by the next probe).
static CUT: AtomicBool = AtomicBool::new(false);
/// Stalls cut short since boot (status line).
pub static STALLS: AtomicU32 = AtomicU32::new(0);

fn set_timeouts(fd: i32, ms: u32) {
    let tv = sys::timeval { tv_sec: (ms / 1000) as _, tv_usec: ((ms % 1000) * 1000) as _ };
    let size = core::mem::size_of::<sys::timeval>() as sys::socklen_t;
    for opt in [sys::SO_RCVTIMEO, sys::SO_SNDTIMEO] {
        // SAFETY: valid option buffer and size; an fd closed meanwhile only returns an error.
        unsafe { sys::lwip_setsockopt(fd, sys::SOL_SOCKET as i32, opt as i32, (&tv as *const sys::timeval).cast(), size) };
    }
}

fn each_session(h: sys::httpd_handle_t, f: impl Fn(i32)) {
    let mut fds = [-1i32; MAX_CONNECTIONS + 1];
    let mut n = fds.len();
    // SAFETY: `fds` holds `n` entries; httpd fills at most that many.
    if unsafe { sys::httpd_get_client_list(h, &mut n, fds.as_mut_ptr()) } == sys::ESP_OK {
        fds.iter().take(n).filter(|fd| **fd >= 0).for_each(|fd| f(*fd));
    }
}

/// Runs in the server task when it is back in its loop (no session is mid-request then).
extern "C" fn probe(_: *mut core::ffi::c_void) {
    PROBE_AT.store(0, Relaxed);
    if CUT.swap(false, Relaxed) {
        let h = SERVER.load(Relaxed);
        if !h.is_null() {
            each_session(h, |fd| set_timeouts(fd, NORMAL_TIMEOUT_MS));
        }
    }
}

/// Watch the web server (`server` is its handle).
pub fn watchdog_start(server: sys::httpd_handle_t) {
    SERVER.store(server, Relaxed);
}

/// Once a second from the main loop: queue a no-op probe into the server task; if it has not
/// run after `STALL_SECS`, the task is stuck in one session (a client trickling its request or
/// reading the reply very slowly), so every session's socket timeouts are cut to
/// `STALL_TIMEOUT_MS`. The stuck one then fails at its next receive or send and httpd closes it;
/// the probe restores the normal timeouts once the task is back. Uses only public esp_http_server
/// calls (`httpd_queue_work`, `httpd_get_client_list`) and `setsockopt`, which are safe from
/// another task.
pub fn watchdog(uptime_s: u32) {
    let h = SERVER.load(Relaxed);
    if h.is_null() {
        return;
    }
    let at = PROBE_AT.load(Relaxed);
    if at == 0 {
        PROBE_AT.store(uptime_s.wrapping_add(1).max(1), Relaxed);
        // SAFETY: valid server handle; the work function takes no argument.
        if unsafe { sys::httpd_queue_work(h, Some(probe), core::ptr::null_mut()) } != sys::ESP_OK {
            PROBE_AT.store(0, Relaxed);
        }
        return;
    }
    let waited = uptime_s.wrapping_add(1).wrapping_sub(at);
    if waited >= STALL_SECS && !CUT.swap(true, Relaxed) {
        let n = STALLS.fetch_add(1, Relaxed) + 1;
        each_session(h, |fd| set_timeouts(fd, STALL_TIMEOUT_MS));
        warn!("http: server stuck on one client for {waited} s: cutting session timeouts to {STALL_TIMEOUT_MS} ms (stall {n})");
    }
}

/// Every other path (registered last, after any debug hooks): 404 with the usual headers.
pub fn register_fallback(http: &mut EspHttpServer<'static>) -> anyhow::Result<()> {
    http.fn_handler::<anyhow::Error, _>("/*", Method::Get, not_found)?;
    http.fn_handler::<anyhow::Error, _>("/*", Method::Post, not_found)?;
    Ok(())
}
