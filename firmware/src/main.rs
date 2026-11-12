//! C3-DNS firmware: a LAN-only DNS blocker/resolver for the ESP32-C3.
//! The logic lives in `dnscore` (host-tested); this crate wires it to Wi-Fi and sockets.

mod button;
mod clock;
mod creds;
mod dns;
mod http;
mod names;
mod net;
mod portal;
mod store_dev;
mod upstream;
#[cfg(feature = "debug-hooks")]
mod debug;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnscore::setup::Provisioning;

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::http::server::{Configuration as HttpConfig, EspHttpServer};
use esp_idf_svc::http::Method;
use esp_idf_svc::io::Write;
use esp_idf_svc::mdns::EspMdns;
use esp_idf_svc::sys;
use log::{info, warn};

/// Main loop period: the BOOT button is sampled at this rate.
const LOOP_MS: u64 = 100;
const NET_POLL_SECS: u32 = 2;
const STATUS_SECS: u32 = 5;
/// Day roll and save check (the save itself is limited by `store_dev`'s budget).
const PERSIST_SECS: u32 = 60;
/// Retry period while the stored credentials cannot be read (doubling up to the maximum).
const UNREADABLE_FIRST: Duration = Duration::from_secs(2);
const UNREADABLE_MAX: Duration = Duration::from_secs(60);

fn free_heap() -> u32 {
    // SAFETY: plain read of allocator statistics.
    unsafe { sys::esp_get_free_heap_size() }
}

fn set(b: bool) -> &'static str {
    if b {
        "set"
    } else {
        "not set"
    }
}

fn main() -> anyhow::Result<()> {
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    // The Wi-Fi driver logs the network name at INFO when it connects; keep it to warnings.
    // SAFETY: static C string tag; plain log-level setting.
    unsafe { sys::esp_log_level_set(c"wifi".as_ptr(), sys::esp_log_level_t_ESP_LOG_WARN) };
    info!("c3-dns starting, heap {}", free_heap());

    creds::init();
    #[cfg(feature = "dev-wifi")]
    creds::seed_dev_wifi();
    let peripherals = Peripherals::take()?;
    let mut button = button::Button::new(peripherals.pins.gpio9)?;
    let sysloop = EspSystemEventLoop::take()?;
    // Only a Wi-Fi entry that is definitively absent (first boot, or after a BOOT hold) starts
    // the setup portal, which ends in a restart. Stored Wi-Fi that is down never comes here (net
    // retries with backoff), and neither does an unreadable one: that is retried here, with
    // backoff, until it reads or the owner holds BOOT for 5 s.
    let mut backoff = UNREADABLE_FIRST;
    let wifi = loop {
        let state = creds::wifi_state();
        info!("credentials: wifi {}, admin password {}", state.name(), set(creds::admin_set()));
        match state {
            Provisioning::Present(w) => break w,
            Provisioning::Absent => portal::run(peripherals.modem, sysloop, button),
            Provisioning::Unreadable => {
                warn!(
                    "credentials: the stored wifi setting cannot be read; NOT starting the setup portal (it would \
                     replace the admin password). Retrying in {} s. Hold BOOT 5 s to clear the credentials and start setup.",
                    backoff.as_secs()
                );
                let until = Instant::now() + backoff;
                while Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(LOOP_MS));
                    button.poll();
                }
                backoff = (backoff * 2).min(UNREADABLE_MAX);
                creds::init();
            }
        }
    };

    // Storage problems never stop the boot: they become defaults plus a warning.
    let (persist, stored, warning) = store_dev::open();
    let shared = Arc::new(dns::Shared::new(dns::map_blocklist(), &stored, warning));
    drop(stored);
    let persist: store_dev::SharedPersist = Arc::new(Mutex::new(persist));
    info!("state ready, heap {}", free_heap());

    let mut net = net::start(peripherals.modem, sysloop, &wifi)?;
    drop(wifi);

    // No SNTP means no saves and no day roll, but DNS still runs.
    let (clock, _sntp) = match clock::Clock::start() {
        Ok((c, s)) => (c, Some(s)),
        Err(e) => {
            warn!("time: SNTP start failed ({e}); nothing will be saved this boot");
            (Arc::new(clock::Clock::default()), None)
        }
    };

    let mut mdns = EspMdns::take()?;
    mdns.set_hostname(http::MDNS_HOSTNAME)?;
    mdns.set_instance_name("c3-dns")?;

    // The web UI server: priority 5 (below every DNS task), at most 2 open connections (the
    // least recently used one is closed for a new one), exact paths plus a 404 fallback.
    let mut http = EspHttpServer::new(&HttpConfig {
        max_open_sockets: http::MAX_CONNECTIONS,
        lru_purge_enable: true,
        uri_match_wildcard: true,
        max_uri_handlers: 48,
        max_resp_headers: 12,
        // Measured high-water marks with the 6144 default: 1.7-2.5 KB left (PBKDF2, the streamed
        // replies' 512-byte buffer); one more KB of margin, since an overflow restarts the device.
        stack_size: 7168,
        ..Default::default()
    })?;
    http.fn_handler::<anyhow::Error, _>("/ok", Method::Get, |req| {
        req.into_ok_response()?.write_all(b"ok\n")?;
        Ok(())
    })?;
    http::register(&mut http, shared.clone(), persist.clone(), clock.clone())?;
    #[cfg(feature = "debug-hooks")]
    let debug_portal = debug::register(&mut http, shared.clone(), persist.clone(), clock.clone())?;
    http::register_fallback(&mut http)?;
    {
        use esp_idf_svc::handle::RawHandle;
        http::watchdog_start(http.handle());
    }

    info!("wifi/mdns/http up, heap {}", free_heap());
    dns::run(shared.clone())?;
    info!("dns tasks up, heap {}", free_heap());

    let mut ms = 0u64;
    let mut tick = 0u32;
    loop {
        std::thread::sleep(Duration::from_millis(LOOP_MS));
        button.poll();
        portal::restart_if_due();
        ms += LOOP_MS;
        if ms % 1000 != 0 {
            continue;
        }
        tick = tick.wrapping_add(1);
        http::watchdog(tick);
        #[cfg(feature = "debug-hooks")]
        debug::poll(&mut net, &debug_portal);
        if tick % NET_POLL_SECS == 0 {
            net.poll(&shared);
        }
        clock.poll();
        if tick % PERSIST_SECS == 0 {
            persist.lock().unwrap_or_else(|e| e.into_inner()).tick(&shared, &clock);
        }
        if tick % STATUS_SECS == 0 {
            // SAFETY: plain reads of allocator statistics.
            let (free, min) = unsafe {
                (sys::esp_get_free_heap_size(), sys::heap_caps_get_minimum_free_size(sys::MALLOC_CAP_DEFAULT))
            };
            let link = net.link().map_or("rssi=- ch=-".to_string(), |(r, c)| format!("rssi={r} ch={c}"));
            info!(
                "heap free={free} min_free={min} {link} utc={} httpd_stack_free={} httpd_stalls={} | {}",
                clock.describe(),
                http::STACK_FREE.load(std::sync::atomic::Ordering::Relaxed),
                http::STALLS.load(std::sync::atomic::Ordering::Relaxed),
                shared.status_line()
            );
        }
        let _ = (&mdns, &http);
    }
}
