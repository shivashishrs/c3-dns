//! First-boot setup portal, used only when NVS holds no Wi-Fi setting (first boot, or after a
//! BOOT hold). Stored Wi-Fi that is merely unreachable never comes here: `net` keeps
//! reconnecting with backoff instead.
//!
//! - Access point `C3-DNS-XXXX` (last two MAC bytes), **open**, at 192.168.4.1/24, its DHCP
//!   server handing out 192.168.4.1 as DNS. Open because any WPA2 key would have to be a
//!   default password or printed somewhere the owner cannot see; the risk (the Wi-Fi
//!   password crosses an open link once, within radio range) is bounded by the timeout below.
//! - A setup page (`dnscore::setup`): network (with a scanned list), Wi-Fi password and a new
//!   admin password (>= 12 characters, entered twice). POST only, with a per-boot random
//!   token in a hidden field, bodies <= 4 KB, at most 10 attempts a minute.
//! - A catch-all DNS answering every name with 192.168.4.1, bound to the AP address and
//!   answering only 192.168.4.0/24, so phones open the page by themselves. It exists only in
//!   portal mode (there is no LAN DNS then).
//! - After 15 minutes without a completed setup the access point and the server shut down and
//!   the radio stays off until a 5 s BOOT hold (or a power cycle) starts setup again.
//! - A completed setup is saved to NVS (`creds`), the portal state is dropped at once (no
//!   further POST is accepted during the ~1.5 s before the restart) and the device restarts
//!   into normal mode.
//! - Refusals sent before the body is read (429, 413) stop reading from the client, so the
//!   server does not drain a body it never wanted. The form body and its fields are wiped
//!   after use (best effort: the HTTP server's own buffers are not ours to wipe).
//!
//! Everything here (Wi-Fi AP, HTTP server, scan list, DNS task) exists only in portal mode.
//! Under `debug-hooks` the same form handlers are also served on the LAN (see `debug.rs`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnscore::secret::wipe_vec;
use dnscore::setup::{
    ap_name, html_escape, parse_form, render_form, token_hex, validate, Attempts, SetupError, MAX_BODY,
    PORTAL_TIMEOUT_MS,
};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpConnection, EspHttpServer, Request};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use esp_idf_svc::ipv4::{self, Mask, RouterConfiguration, Subnet};
use esp_idf_svc::netif::{EspNetif, NetifConfiguration};
use esp_idf_svc::sys;
use esp_idf_svc::wifi::{AccessPointConfiguration, AuthMethod, ClientConfiguration, Configuration, EspWifi, WifiDriver};
use log::{info, warn};

use crate::button::Button;

pub const AP_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
/// Stations allowed on the setup AP at once.
const AP_MAX_STA: u16 = 2;
/// Delay between the "saved" page and the restart, so the reply reaches the browser.
const RESTART_DELAY_MS: u32 = 1500;
const STACK_DNS: usize = 4096;

/// The portal's per-boot state.
pub struct Portal {
    token: String,
    scan: Vec<String>,
    attempts: Attempts,
    boot: Instant,
}

pub type SharedPortal = Arc<Mutex<Option<Portal>>>;

impl Portal {
    pub fn new(scan: Vec<String>) -> Self {
        Self { token: token_hex(&crate::creds::random::<16>()), scan, attempts: Attempts::default(), boot: Instant::now() }
    }

    #[cfg(feature = "debug-hooks")]
    pub fn scan_len(&self) -> usize {
        self.scan.len()
    }

    #[cfg(feature = "debug-hooks")]
    pub fn add_scan(&mut self, names: impl IntoIterator<Item = String>) {
        for n in names {
            if !self.scan.contains(&n) {
                self.scan.push(n);
            }
        }
    }
}

fn lock(p: &SharedPortal) -> std::sync::MutexGuard<'_, Option<Portal>> {
    p.lock().unwrap_or_else(|e| e.into_inner())
}

/// Milliseconds since boot at which to restart (0: none).
static RESTART_AT_MS: AtomicU32 = AtomicU32::new(0);

fn uptime_ms() -> u32 {
    // SAFETY: plain read of the system timer.
    (unsafe { sys::esp_timer_get_time() } / 1000) as u32
}

fn schedule_restart() {
    RESTART_AT_MS.store(uptime_ms().wrapping_add(RESTART_DELAY_MS).max(1), Relaxed);
}

/// Called from the main loop (both modes): restart once a completed setup has been answered.
pub fn restart_if_due() {
    let at = RESTART_AT_MS.load(Relaxed);
    if at != 0 && uptime_ms() >= at {
        info!("setup complete: restarting into normal mode");
        // SAFETY: plain restart.
        unsafe { sys::esp_restart() }
    }
}

const HTML: (&str, &str) = ("Content-Type", "text/html; charset=utf-8");
const NO_STORE: (&str, &str) = ("Cache-Control", "no-store");
const NO_FRAME: (&str, &str) = ("X-Frame-Options", "DENY");

fn page(req: Request<&mut EspHttpConnection<'_>>, status: u16, body: &str) -> anyhow::Result<()> {
    req.into_response(status, None, &[HTML, NO_STORE, NO_FRAME])?.write_all(body.as_bytes())?;
    Ok(())
}

/// GET: the setup form (404 while the portal is not active).
pub fn serve_form(req: Request<&mut EspHttpConnection<'_>>, portal: &SharedPortal, action: &str) -> anyhow::Result<()> {
    let html = match lock(portal).as_ref() {
        Some(p) => render_form(&p.token, &p.scan, None, None, action),
        None => {
            req.into_status_response(404)?;
            return Ok(());
        }
    };
    page(req, 200, &html)
}

/// POST: check and save a setup; on success the device restarts shortly after the reply.
pub fn serve_save(
    mut req: Request<&mut EspHttpConnection<'_>>,
    portal: &SharedPortal,
    action: &str,
) -> anyhow::Result<()> {
    let allowed = match lock(portal).as_mut() {
        Some(p) => {
            let now = p.boot.elapsed().as_millis() as u64;
            p.attempts.allow(now)
        }
        None => {
            req.into_status_response(404)?;
            return Ok(());
        }
    };
    let len = req.header("Content-Length").and_then(|v| v.parse::<usize>().ok());
    if !allowed {
        warn!("portal: too many attempts; refusing for the rest of the minute");
        let fd = crate::http::sockfd(&mut req);
        let r = page(req, 429, "Too many attempts. Wait a minute, then reload the page.");
        crate::http::stop_reading(fd.filter(|_| len.unwrap_or(1) > 0));
        return r;
    }
    let len = match len {
        Some(n) if (1..=MAX_BODY).contains(&n) => n,
        Some(n) if n > MAX_BODY => {
            let fd = crate::http::sockfd(&mut req);
            let r = page(req, 413, "The form is too large.");
            crate::http::stop_reading(fd);
            return r;
        }
        _ => return page(req, 411, "The form is empty or has no length."),
    };
    let mut body = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match req.read(&mut body[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    if got != len {
        wipe_vec(&mut body);
        return page(req, 400, "The form arrived incomplete.");
    }
    let form = parse_form(&body);
    wipe_vec(&mut body);
    let form = match form {
        Ok(f) => f,
        Err(e) => return refuse(req, portal, 400, e.message(), None, action),
    };
    let token = match lock(portal).as_ref() {
        Some(p) => p.token.clone(),
        None => String::new(),
    };
    let setup = match validate(&form, &token) {
        Ok(s) => s,
        Err(e) => {
            let status = if e == SetupError::BadToken { 403 } else { 400 };
            warn!("portal: setup refused: {e:?}");
            return refuse(req, portal, status, e.message(), form.get("ssid"), action);
        }
    };
    drop(form);
    if let Err(e) = crate::creds::save_setup(&setup.ssid, setup.psk.as_str(), setup.admin.as_str()) {
        warn!("portal: saving failed: {e}");
        return refuse(req, portal, 500, "Saving failed. Try again.", Some(&setup.ssid), action);
    }
    // Saved: close the portal now. Every later GET or POST gets 404 until the restart.
    *lock(portal) = None;
    info!("portal: setup saved; portal closed, restarting shortly");
    let msg = format!(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>C3-DNS setup</title><p>Saved. The device restarts and joins <b>{}</b>. Reconnect this device \
         to your normal Wi-Fi; the blocker is then at <b>http://adblock.local/</b>.</p>",
        html_escape(&setup.ssid)
    );
    page(req, 200, &msg)?;
    schedule_restart();
    Ok(())
}

fn refuse(
    req: Request<&mut EspHttpConnection<'_>>,
    portal: &SharedPortal,
    status: u16,
    msg: &str,
    ssid: Option<&str>,
    action: &str,
) -> anyhow::Result<()> {
    let html = match lock(portal).as_ref() {
        Some(p) => render_form(&p.token, &p.scan, Some(msg), ssid, action),
        None => html_escape(msg),
    };
    page(req, status, &html)
}

/// The AP network interface: 192.168.4.1/24, DHCP server offering 192.168.4.1 as DNS.
pub fn ap_netif() -> anyhow::Result<EspNetif> {
    let mut conf = NetifConfiguration::wifi_default_router();
    conf.ip_configuration = Some(ipv4::Configuration::Router(RouterConfiguration {
        subnet: Subnet { gateway: AP_IP, mask: Mask(24) },
        dhcp_enabled: true,
        dns: Some(AP_IP),
        secondary_dns: None,
    }));
    Ok(EspNetif::new_with_conf(&conf)?)
}

/// `C3-DNS-XXXX` for this board.
pub fn this_ap_name() -> String {
    let mut mac = [0u8; 6];
    // SAFETY: writes 6 bytes.
    unsafe { sys::esp_read_mac(mac.as_mut_ptr(), sys::esp_mac_type_t_ESP_MAC_WIFI_STA) };
    ap_name(mac)
}

pub fn ap_config(name: &str) -> anyhow::Result<AccessPointConfiguration> {
    Ok(AccessPointConfiguration {
        ssid: name.try_into().map_err(|_| anyhow::anyhow!("ap name too long"))?,
        auth_method: AuthMethod::None,
        channel: 1,
        max_connections: AP_MAX_STA,
        ..Default::default()
    })
}

/// Visible network names, strongest first, without duplicates or hidden networks.
pub fn scan_names(wifi: &mut EspWifi<'static>) -> Vec<String> {
    match wifi.scan() {
        Ok(mut aps) => {
            aps.sort_by_key(|a| std::cmp::Reverse(a.signal_strength));
            let mut names: Vec<String> = Vec::new();
            for a in aps {
                let n = a.ssid.as_str();
                if !n.is_empty() && !names.iter().any(|x| x == n) && names.len() < dnscore::setup::MAX_SCAN {
                    names.push(n.to_string());
                }
            }
            names
        }
        Err(e) => {
            warn!("portal: scan failed ({e}); the form still accepts a typed name");
            Vec::new()
        }
    }
}

/// Catch-all DNS for the portal: every A query gets 192.168.4.1, others an empty NOERROR.
/// Bound to the AP address and answering only the AP subnet.
fn captive_dns() {
    let sock = match UdpSocket::bind(SocketAddrV4::new(AP_IP, 53)) {
        Ok(s) => s,
        Err(e) => {
            warn!("portal: captive DNS bind failed ({e}); open http://{AP_IP}/ by hand");
            return;
        }
    };
    let mut buf = [0u8; 512];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            std::thread::sleep(Duration::from_millis(100)); // never spin on a socket error
            continue;
        };
        let SocketAddr::V4(f) = from else { continue };
        if u32::from(*f.ip()) & 0xffff_ff00 != u32::from(AP_IP) & 0xffff_ff00 {
            continue;
        }
        let pkt = &buf[..n];
        let Ok(q) = dnscore::parse_query(pkt) else { continue };
        let reply = dnscore::build_local(pkt, &q, &[AP_IP], &[], 10);
        let _ = sock.send_to(&reply, from);
    }
}

fn free_heap() -> u32 {
    // SAFETY: plain read of allocator statistics.
    unsafe { sys::esp_get_free_heap_size() }
}

/// Portal mode. Never returns: ends in a restart (setup saved, or a BOOT hold).
pub fn run(modem: Modem<'static>, sysloop: EspSystemEventLoop, mut button: Button) -> ! {
    match start(modem, sysloop) {
        Ok((wifi, http)) => idle(wifi, Some(http), &mut button),
        Err(e) => {
            warn!("portal: could not start ({e}); hold BOOT 5 s or power-cycle to retry");
            loop {
                std::thread::sleep(Duration::from_millis(100));
                button.poll();
            }
        }
    }
}

fn start(modem: Modem<'static>, sysloop: EspSystemEventLoop) -> anyhow::Result<(EspWifi<'static>, EspHttpServer<'static>)> {
    info!("portal: no wifi setting stored; starting setup, heap {}", free_heap());
    // No NVS for the driver: it must not keep its own copy of any credentials.
    let mut wifi = EspWifi::wrap_all(
        WifiDriver::new(modem, sysloop, None)?,
        EspNetif::new_with_conf(&NetifConfiguration::wifi_default_client())?,
        ap_netif()?,
    )?;
    // Scan first (station mode), then switch to the access point alone.
    wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;
    wifi.start()?;
    let scan = scan_names(&mut wifi);
    info!("portal: scan found {} networks", scan.len());
    wifi.stop()?;
    let name = this_ap_name();
    wifi.set_configuration(&Configuration::AccessPoint(ap_config(&name)?))?;
    wifi.start()?;
    crate::net::set_tx_power();

    let portal: SharedPortal = Arc::new(Mutex::new(Some(Portal::new(scan))));
    let mut http = EspHttpServer::new(&HttpConfig { uri_match_wildcard: true, ..Default::default() })?;
    let p = portal.clone();
    http.fn_handler::<anyhow::Error, _>("/", Method::Get, move |req| serve_form(req, &p, "/save"))?;
    let p = portal.clone();
    http.fn_handler::<anyhow::Error, _>("/save", Method::Post, move |req| serve_save(req, &p, "/save"))?;
    // Captive-portal probes (any other path) go to the form.
    http.fn_handler::<anyhow::Error, _>("/*", Method::Get, |req| {
        req.into_response(302, None, &[("Location", "http://192.168.4.1/"), NO_STORE])?;
        Ok(())
    })?;
    crate::dns::spawn_dns(c"captive", STACK_DNS, captive_dns)?;
    warn!(
        "portal: open setup network \"{name}\" is up at http://{AP_IP}/ (shuts down after {} min without setup), heap {}",
        PORTAL_TIMEOUT_MS / 60_000,
        free_heap()
    );
    Ok((wifi, http))
}

fn idle(mut wifi: EspWifi<'static>, mut http: Option<EspHttpServer<'static>>, button: &mut Button) -> ! {
    let started = Instant::now();
    let mut tick = 0u32;
    loop {
        std::thread::sleep(Duration::from_millis(100));
        tick = tick.wrapping_add(1);
        button.poll();
        restart_if_due();
        if http.is_some() && started.elapsed() >= Duration::from_millis(PORTAL_TIMEOUT_MS) && RESTART_AT_MS.load(Relaxed) == 0 {
            http = None;
            if let Err(e) = wifi.stop() {
                warn!("portal: stopping wifi failed ({e})");
            }
            warn!("portal: no setup within 15 minutes: access point off; hold BOOT 5 s or power-cycle to start setup again");
        }
        if tick % 300 == 0 {
            // SAFETY: plain reads of allocator statistics.
            let min = unsafe { sys::heap_caps_get_minimum_free_size(sys::MALLOC_CAP_DEFAULT) };
            info!("portal: heap free={} min_free={min} ap={}", free_heap(), if http.is_some() { "on" } else { "off" });
        }
    }
}
