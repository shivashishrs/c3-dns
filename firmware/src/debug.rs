//! DEBUG ONLY (feature `debug-hooks`, never in the default build): unauthenticated,
//! LAN-restricted HTTP hooks used to verify Task 6 on the spare board.
//!
//! - `GET /debug/upstream?ip=<addr>` sets a single upstream (`ip=default` restores the
//!   defaults), e.g. an unroutable address to test serve-stale and SERVFAIL.
//! - `GET /debug/rate?burst=<n>&per_sec=<n>` replaces the per-client rate limiter, for burst
//!   tests from a single client (persisted like a setting). Optional `global_burst=<n>&
//!   global_per_sec=<n>` replace the global bucket, in memory only (bounded, never persisted).
//! - `GET /debug/pause?secs=<n>` pauses blocking (`secs=0` resumes).
//! - `GET /debug/stats`: heap and the DNS counters, read without waiting for the serial log.
//! - `GET /debug/rule` lists the custom rules; `GET /debug/rule?kind=block|allow&pattern=<p>`
//!   adds one (validated as the UI will); `GET /debug/rule/remove?kind=..&pattern=..` removes.
//! - `GET /debug/save` forces a save now (skips the 10-minute interval, but never saves without
//!   synced time or when storage is read-only).
//! - `GET /debug/storage`: writes since boot, last save, seq, warning, read-only flag.
//! - `GET /debug/summaries?days=<n>[&raw=1]` replaces the daily summaries with `n` (<= 7) full
//!   days of 253-byte names (10 queried + 10 blocked each), for the save-budget test. Without
//!   `raw` they go through `push_summary` (clipped as in normal use); with `raw=1` they are
//!   stored unclipped, the worst a summary list could hold, to test the encoder's own bounds.
//!
//! - Task 8: `GET /debug/portal[?fake_ssid=<name>][&ap=0]` activates the setup-portal handlers
//!   on the LAN (`GET /debug/portal/form`, `POST /debug/portal/save`: the real handlers, so a
//!   valid save stores the credentials and restarts), injects a fake scan entry, and (unless
//!   `ap=0`) starts the setup AP next to the station (AP+STA) and adds a real scan. No captive
//!   DNS here: the LAN DNS server owns port 53.
//! - `GET /debug/creds`: "wifi: set|unset, admin: set|unset" only; `?kdf=1` adds an mbedtls
//!   known-answer check and the time of one admin-password hash.
//! - `POST /debug/creds/verify` (body `user=..&password=..`): runs `creds::verify_admin`.
//! - `GET /debug/creds/clear`: what a 5 s BOOT hold does (clear Wi-Fi + admin, restart).
//! - Hardening 2: `GET /debug/creds/damage` stores a damaged Wi-Fi blob and restarts, to show
//!   that an unreadable setting does NOT open the portal (the spare then stays off the LAN:
//!   recover with `tools/erase-nvs.sh` and a `dev-wifi` build).
//! - `GET /debug/name?local=<name>`: sets `Settings.local_name` (persisted).
//! - `GET /debug/wifi/reconnect`: drops the station link (backoff reconnects it).
//! - Task 9: `GET /debug/heapmon` restarts the heap-minimum window
//!   (`heap_caps_monitor_local_minimum_free_size_start`): `min_free` in `/debug/stats`, the
//!   status line and `/api/overview` then reports the lowest free heap since this call, so
//!   each test phase gets its own dip figure.
//!
//! Settings and rule changes go through `Shared::mutate`, so they are persisted like real ones.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dnscore::limit::RateLimiter;
use dnscore::persist::{push_summary, utc_string};
use dnscore::stats::{DailySummary, SUMMARY_TOP};
use dnscore::store::Settings;
use dnscore::RuleKind;
use esp_idf_svc::http::server::{EspHttpConnection, EspHttpServer, Request};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use log::warn;

use crate::clock::Clock;
use crate::dns::Shared;
use crate::net::Net;
use crate::portal::{Portal, SharedPortal};
use crate::store_dev::SharedPersist;

/// Requests from handlers to the main loop (which owns the Wi-Fi driver).
static REQ_AP: AtomicBool = AtomicBool::new(false);
static REQ_DISCONNECT: AtomicBool = AtomicBool::new(false);
static REQ_CLEAR: AtomicBool = AtomicBool::new(false);
static REQ_RESTART: AtomicBool = AtomicBool::new(false);

fn is_lan(req: &mut Request<&mut EspHttpConnection<'_>>, s: &Shared) -> anyhow::Result<bool> {
    let peer = req.connection().raw_connection()?.source_ipv6()?;
    Ok(s.lock().lan.is_lan(IpAddr::V6(peer)))
}

/// Called once a second from the main loop.
pub fn poll(net: &mut Net, portal: &SharedPortal) {
    if REQ_CLEAR.swap(false, Relaxed) {
        crate::button::clear_and_restart();
    }
    if REQ_RESTART.swap(false, Relaxed) {
        // SAFETY: plain restart.
        unsafe { esp_idf_svc::sys::esp_restart() }
    }
    if REQ_DISCONNECT.swap(false, Relaxed) {
        net.debug_disconnect();
    }
    if REQ_AP.swap(false, Relaxed) {
        match net.debug_ap() {
            Ok(names) => {
                warn!("debug: portal scan: {} networks", names.len());
                if let Some(p) = portal.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                    p.add_scan(names);
                }
            }
            Err(e) => warn!("debug: AP+STA failed: {e}"),
        }
    }
}

fn param<'a>(uri: &'a str, key: &str) -> Option<&'a str> {
    uri.split_once('?')?.1.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// `%XX` decoding of a query value (patterns such as `||ads.example^` arrive encoded).
fn pct_decode(v: &str) -> Option<String> {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn kind_of(uri: &str) -> Option<RuleKind> {
    match param(uri, "kind")? {
        "block" => Some(RuleKind::Block),
        "allow" => Some(RuleKind::Allow),
        _ => None,
    }
}

pub fn register(
    http: &mut EspHttpServer<'static>,
    shared: Arc<Shared>,
    persist: SharedPersist,
    clock: Arc<Clock>,
) -> anyhow::Result<SharedPortal> {
    warn!(
        "DEBUG HOOKS ENABLED: /debug/{{upstream,rate,pause,stats,rule,rule/remove,save,storage,summaries,\
         portal,portal/form,portal/save,creds,creds/verify,creds/clear,creds/damage,name,wifi/reconnect,heapmon}} (debug build only)"
    );
    let portal = register_task8(http, shared.clone())?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/upstream", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let msg = match param(&uri, "ip") {
            Some("default") => {
                let _ = s.mutate(|st| {
                    st.settings.upstreams = Settings::default().upstreams;
                    Ok::<_, ()>(())
                });
                "upstreams: defaults\n".to_string()
            }
            Some(v) => match v.parse::<IpAddr>() {
                Ok(ip) => {
                    let _ = s.mutate(|st| {
                        st.settings.upstreams = vec![ip];
                        Ok::<_, ()>(())
                    });
                    format!("upstreams: [{ip}]\n")
                }
                Err(_) => "bad ip\n".to_string(),
            },
            None => "missing ip\n".to_string(),
        };
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/stats", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        // SAFETY: plain reads of allocator statistics.
        let (free, min) = unsafe {
            (
                esp_idf_svc::sys::esp_get_free_heap_size(),
                esp_idf_svc::sys::heap_caps_get_minimum_free_size(esp_idf_svc::sys::MALLOC_CAP_DEFAULT),
            )
        };
        let out = format!("heap free={free} min_free={min}\n{}\n", s.status_line());
        req.into_ok_response()?.write_all(out.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/pause", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let msg = match param(&uri, "secs").and_then(|v| v.parse::<u32>().ok()) {
            Some(0) => {
                s.lock().engine.resume();
                "resumed\n".to_string()
            }
            Some(n) => {
                let now = s.now_ms();
                s.lock().engine.pause(n, now);
                format!("paused for {n} s\n")
            }
            None => "need secs\n".to_string(),
        };
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/rate", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let num = |k| param(&uri, k).and_then(|v| v.parse::<u32>().ok()).filter(|v| *v > 0);
        let mut msg = match (num("burst"), num("per_sec")) {
            (Some(b), Some(p)) => {
                let _ = s.mutate(|st| {
                    st.settings.rate_burst = b;
                    st.settings.rate_per_sec = p;
                    st.admission.clients = RateLimiter::new(b, p, 64);
                    Ok::<_, ()>(())
                });
                format!("rate: burst {b}, {p}/s\n")
            }
            (None, None) => String::new(),
            _ => "need burst and per_sec > 0\n".to_string(),
        };
        if let (Some(b), Some(p)) = (num("global_burst"), num("global_per_sec")) {
            if s.lock().admission.set_global(b, p) {
                msg.push_str(&format!("global: burst {b}, {p}/s (in memory)\n"));
            } else {
                msg.push_str("global: out of bounds\n");
            }
        }
        let (gb, gp) = s.lock().admission.global_rate();
        msg.push_str(&format!("global now: burst {gb}, {gp}/s\n"));
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/rule", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let msg = match (kind_of(&uri), param(&uri, "pattern").map(pct_decode)) {
            (None, None) => {
                let mut out = String::new();
                for (k, p) in s.lock().engine.rules().list() {
                    out.push_str(&format!("{k:?} {p}\n"));
                }
                if out.is_empty() {
                    out.push_str("(no rules)\n");
                }
                req.into_ok_response()?.write_all(out.as_bytes())?;
                return Ok(());
            }
            (Some(k), Some(Some(p))) => match s.add_rule(k, &p) {
                Ok(c) => format!("added {k:?} {c}\n"),
                Err(e) => format!("rejected {k:?} {p:?}: {e:?}\n"),
            },
            _ => "need kind=block|allow and pattern\n".to_string(),
        };
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/rule/remove", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let msg = match (kind_of(&uri), param(&uri, "pattern").and_then(pct_decode)) {
            (Some(k), Some(p)) if s.remove_rule(k, &p) => format!("removed {k:?} {p}\n"),
            (Some(k), Some(p)) => format!("no such rule {k:?} {p}\n"),
            _ => "need kind=block|allow and pattern\n".to_string(),
        };
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let (s, ps, c) = (shared.clone(), persist.clone(), clock.clone());
    http.fn_handler::<anyhow::Error, _>("/debug/save", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let r = ps.lock().unwrap_or_else(|e| e.into_inner()).save(&s, c.now(), true, "debug-force");
        let msg = match r {
            Ok(()) => "saved\n".to_string(),
            Err(e) => format!("{e}\n"),
        };
        warn!("debug: save: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/summaries", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let days = param(&uri, "days").and_then(|v| v.parse::<u32>().ok()).unwrap_or(7).min(7);
        let raw = param(&uri, "raw") == Some("1");
        // 253 bytes: 3-digit tag + 60 + '.' + 63 + '.' + 63 + '.' + 61.
        let name = |i: usize| {
            format!("{i:03}{}.{}.{}.{}", "a".repeat(60), "b".repeat(63), "c".repeat(63), "d".repeat(61))
        };
        let day0 = 20_000u32;
        let mut held = 0usize;
        let _ = s.mutate(|st| {
            st.summaries.clear();
            for d in 0..days {
                let top = |base: usize| (0..SUMMARY_TOP).map(|i| (name(base + i), 100 - i as u32)).collect();
                let sum = DailySummary {
                    day: day0 + d,
                    allowed: 1000 + d,
                    blocked: 100 + d,
                    top_queried: top(d as usize * 100),
                    top_blocked: top(d as usize * 100 + 50),
                };
                if raw {
                    st.summaries.push(sum);
                } else {
                    push_summary(&mut st.summaries, sum);
                }
            }
            held = st
                .summaries
                .iter()
                .flat_map(|d| d.top_queried.iter().chain(&d.top_blocked))
                .map(|(n, _)| n.len())
                .sum();
            Ok::<_, ()>(())
        });
        // SAFETY: plain read of allocator statistics.
        let free = unsafe { esp_idf_svc::sys::esp_get_free_heap_size() };
        let msg = format!("summaries: {days} days, raw={raw}, name bytes held {held}, heap free {free}\n");
        warn!("debug: {}", msg.trim_end());
        req.into_ok_response()?.write_all(msg.as_bytes())?;
        Ok(())
    })?;
    let s = shared;
    http.fn_handler::<anyhow::Error, _>("/debug/storage", Method::Get, move |mut req| {
        let peer = req.connection().raw_connection()?.source_ipv6()?;
        if !s.lock().lan.is_lan(IpAddr::V6(peer)) {
            req.into_status_response(403)?;
            return Ok(());
        }
        let (rules, dirty, warning, dropped, sums) = {
            let st = s.lock();
            (st.engine.rules().len(), st.dirty.is_dirty(), st.warning.clone(), st.load_dropped, st.summaries.len())
        };
        let out = {
            let p = persist.lock().unwrap_or_else(|e| e.into_inner());
            format!(
                "writes={} failures={} sectors_erased={} erase_failed={} last_save={} last_bytes={} seq={:?} \
                 loaded_seq={:?} read_only={} dirty={dirty} rules={rules} summaries={sums} load_dropped={dropped} \
                 heap_before_during_after={:?} dropped_summaries={} skipped_low_heap={} over_budget={} time={}\n\
                 warning={}\n",
                p.status.writes,
                p.status.failures,
                p.sectors_erased(),
                p.erase_failures(),
                p.status.last_save_unix.map_or("never".to_string(), utc_string),
                p.status.last_bytes,
                p.seq(),
                p.status.loaded_seq,
                p.read_only(),
                p.status.last_heap,
                p.status.last_dropped_summaries,
                p.status.skipped_low_heap,
                p.status.over_budget,
                clock.describe(),
                warning.as_deref().unwrap_or("none"),
            )
        };
        req.into_ok_response()?.write_all(out.as_bytes())?;
        Ok(())
    })?;
    Ok(portal)
}

fn reply(req: Request<&mut EspHttpConnection<'_>>, msg: &str) -> anyhow::Result<()> {
    req.into_ok_response()?.write_all(msg.as_bytes())?;
    Ok(())
}

fn register_task8(http: &mut EspHttpServer<'static>, shared: Arc<Shared>) -> anyhow::Result<SharedPortal> {
    let portal: SharedPortal = Arc::new(Mutex::new(None));

    let (s, p) = (shared.clone(), portal.clone());
    http.fn_handler::<anyhow::Error, _>("/debug/portal", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let fake = param(&uri, "fake_ssid").and_then(pct_decode);
        let ap = param(&uri, "ap") != Some("0");
        let n = {
            let mut g = p.lock().unwrap_or_else(|e| e.into_inner());
            let portal = g.get_or_insert_with(|| Portal::new(Vec::new()));
            portal.add_scan(fake);
            portal.scan_len()
        };
        if ap {
            REQ_AP.store(true, Relaxed);
        }
        let msg = format!(
            "portal: active (form at /debug/portal/form, posts to /debug/portal/save); scan entries {n}; ap+sta {}\n",
            if ap { "requested" } else { "skipped" }
        );
        warn!("debug: {}", msg.trim_end());
        reply(req, &msg)
    })?;
    let (s, p) = (shared.clone(), portal.clone());
    http.fn_handler::<anyhow::Error, _>("/debug/portal/form", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        crate::portal::serve_form(req, &p, "/debug/portal/save")
    })?;
    let (s, p) = (shared.clone(), portal.clone());
    http.fn_handler::<anyhow::Error, _>("/debug/portal/save", Method::Post, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        crate::portal::serve_save(req, &p, "/debug/portal/save")
    })?;

    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/creds", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        let set = |b: bool| if b { "set" } else { "unset" };
        let mut msg = format!(
            "wifi: {}, admin: {}\n",
            crate::creds::wifi_state().name(),
            set(crate::creds::admin_set())
        );
        if param(req.uri(), "kdf") == Some("1") {
            // RFC 7914 section 11: PBKDF2-HMAC-SHA256("passwd", "salt", 1), first 32 bytes.
            const KAT: [u8; 32] = [
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
                0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
            ];
            let mut out = [0u8; 32];
            let ok = crate::creds::kdf(b"passwd", b"salt", 1, &mut out) && out == KAT;
            let t = Instant::now();
            let ran = crate::creds::kdf(b"timing password", &[0u8; 16], dnscore::auth::ITERATIONS, &mut out);
            msg.push_str(&format!(
                "kdf: rfc7914 vector {}, {} iterations in {} ms ({})\n",
                if ok { "ok" } else { "MISMATCH" },
                dnscore::auth::ITERATIONS,
                t.elapsed().as_millis(),
                if ran { "ran" } else { "failed" }
            ));
        }
        reply(req, &msg)
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/creds/verify", Method::Post, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        let mut buf = [0u8; 600];
        let mut got = 0;
        while got < buf.len() {
            match req.read(&mut buf[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        let form = dnscore::setup::parse_form(&buf[..got]);
        dnscore::secret::wipe(&mut buf);
        let msg = match form {
            Ok(f) => {
                let t = Instant::now();
                let ok = crate::creds::verify_admin(f.get("user").unwrap_or(""), f.get("password").unwrap_or(""));
                format!("{} ({} ms)\n", if ok { "match" } else { "no match" }, t.elapsed().as_millis())
            }
            Err(e) => format!("bad form: {e:?}\n"),
        };
        reply(req, &msg)
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/creds/clear", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        warn!("debug: creds/clear requested (same as a BOOT hold)");
        REQ_CLEAR.store(true, Relaxed);
        reply(req, "clearing wifi and admin password, restarting into the portal\n")
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/creds/damage", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        let msg = match crate::creds::debug_damage_wifi() {
            Ok(()) => {
                warn!("debug: stored a damaged wifi blob; restarting");
                REQ_RESTART.store(true, Relaxed);
                "stored a damaged wifi blob; restarting (expect: wifi UNREADABLE, no portal)\n".to_string()
            }
            Err(e) => format!("failed: {e}\n"),
        };
        reply(req, &msg)
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/name", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        let uri = req.uri().to_string();
        let msg = match param(&uri, "local").and_then(pct_decode) {
            Some(n) => {
                let r = s.mutate(|st| {
                    let mut next = st.settings.clone();
                    next.local_name = n.clone();
                    if dnscore::store::settings_valid(&next) {
                        st.settings.local_name = n.clone();
                        Ok(())
                    } else {
                        Err(())
                    }
                });
                match r {
                    Ok(()) => format!("local_name: {n} (applied at the next network poll)\n"),
                    Err(()) => format!("local_name: {n:?} refused\n"),
                }
            }
            None => format!("local_name: {}\n", s.lock().settings.local_name),
        };
        warn!("debug: {}", msg.trim_end());
        reply(req, &msg)
    })?;
    let s = shared.clone();
    http.fn_handler::<anyhow::Error, _>("/debug/heapmon", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        // SAFETY: plain allocator bookkeeping calls; stop then start restarts the window.
        let (free, r) = unsafe {
            esp_idf_svc::sys::heap_caps_monitor_local_minimum_free_size_stop();
            let r = esp_idf_svc::sys::heap_caps_monitor_local_minimum_free_size_start();
            (esp_idf_svc::sys::esp_get_free_heap_size(), r)
        };
        reply(req, &format!("heapmon: window restarted ({r}), heap free {free}\n"))
    })?;
    let s = shared;
    http.fn_handler::<anyhow::Error, _>("/debug/wifi/reconnect", Method::Get, move |mut req| {
        if !is_lan(&mut req, &s)? {
            req.into_status_response(403)?;
            return Ok(());
        }
        REQ_DISCONNECT.store(true, Relaxed);
        reply(req, "wifi: disconnect requested\n")
    })?;
    Ok(portal)
}
