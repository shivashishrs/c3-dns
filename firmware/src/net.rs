//! Wi-Fi station: connect, keep reconnecting with backoff, IPv6 (link-local + SLAAC), and
//! keep the `LanPolicy` (own IPv4 subnet, own global IPv6 /64 prefixes) and the IPv6-uplink
//! flag up to date, plus the own-name record (`names`). Credentials come from NVS (`creds`)
//! and are never logged; stored Wi-Fi that is merely down is retried with backoff forever
//! (it never starts the setup portal).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::handle::RawHandle;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::netif::{EspNetif, NetifConfiguration};
use esp_idf_svc::sys;
use esp_idf_svc::wifi::{AuthMethod, ClientConfiguration, Configuration, EspWifi, PowerSaveMode, WifiDriver};
use log::{info, warn};

use crate::creds::Wifi;
use crate::dns::Shared;

const FIRST_TRY: Duration = Duration::from_secs(10);
/// Max Wi-Fi TX power in 0.25 dBm units: 15 dBm. Measured on the spare (2026-10-27, AP on
/// channel 4, RSSI about -72 dBm): 20 dBm (chip default) never associated; 15 dBm 0% loss;
/// 11 dBm 1.7%; 8.5 dBm (the previous firmware's value) 27% ping loss.
///
/// The 15 dBm value is board- and placement-specific: it was measured on the spare at about
/// -71 to -76 dBm RSSI and must be re-measured where the board is finally placed.
const TX_POWER_QDBM: i8 = 60;
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub struct Net {
    wifi: EspWifi<'static>,
    next_try: Instant,
    backoff: Duration,
    connected: bool,
}

/// Apply `TX_POWER_QDBM` (call after `start`).
pub fn set_tx_power() {
    // SAFETY: plain driver setting after esp_wifi_start.
    let err = unsafe { sys::esp_wifi_set_max_tx_power(TX_POWER_QDBM) };
    if err != sys::ESP_OK {
        warn!("wifi: set tx power failed ({err})");
    }
}

pub fn start(modem: Modem<'static>, sysloop: EspSystemEventLoop, creds: &Wifi) -> anyhow::Result<Net> {
    // esp-idf-svc's default station netif lacks two flags that ESP-IDF's own default has:
    // without IPV6_AUTOCONFIG lwIP ignores the router's prefix (no SLAAC global address;
    // seen on the spare), and MLDV6_REPORT keeps multicast group reports going.
    let mut sta_conf = NetifConfiguration::wifi_default_client();
    sta_conf.flags |= sys::esp_netif_flags_ESP_NETIF_FLAG_IPV6_AUTOCONFIG_ENABLED
        | sys::esp_netif_flags_ESP_NETIF_FLAG_MLDV6_REPORT;
    // No NVS for the driver: the credentials live in our own namespace (`creds`) only, and the
    // driver must not keep a second copy. The AP interface is used only by the debug portal.
    let mut wifi = EspWifi::wrap_all(
        WifiDriver::new(modem, sysloop, None)?,
        EspNetif::new_with_conf(&sta_conf)?,
        crate::portal::ap_netif()?,
    )?;
    let (ssid, psk) = (creds.ssid.as_str(), creds.psk.as_str());
    let auth_method = if psk.is_empty() { AuthMethod::None } else { AuthMethod::WPA2Personal };
    wifi.set_configuration(&Configuration::Client(ClientConfiguration {
        ssid: ssid.try_into().map_err(|_| anyhow::anyhow!("ssid too long"))?,
        password: psk.try_into().map_err(|_| anyhow::anyhow!("password too long"))?,
        auth_method,
        ..Default::default()
    }))?;
    wifi.start()?;
    // A DNS server must hear queries at once: no modem sleep between beacons.
    wifi.set_power_save(PowerSaveMode::None)?;
    // ESP32-C3 SuperMini boards are flaky at full TX power (the owner's previous firmware
    // lowers it for that reason); on the spare, association failed repeatedly at the default
    // 20 dBm. See TX_POWER_QDBM for the measured choice (placement-specific: re-measure
    // where the board finally sits).
    set_tx_power();
    info!(
        "wifi: started, connecting with the setting stored in NVS (ssid {} bytes, password {})",
        ssid.len(),
        if psk.is_empty() { "empty" } else { "set" }
    );
    if let Err(e) = wifi.connect() {
        warn!("wifi: connect: {e}");
    }
    Ok(Net { wifi, next_try: Instant::now() + FIRST_TRY, backoff: MIN_BACKOFF, connected: false })
}

fn prefix64(a: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(a) & !((1u128 << 64) - 1))
}

impl Net {
    /// Signal strength (dBm) and channel of the associated AP, for the status line.
    /// The record also holds the network name, which is never printed.
    pub fn link(&self) -> Option<(i8, u8)> {
        let mut rec = sys::wifi_ap_record_t::default();
        // SAFETY: valid out-param; returns an error when not associated.
        let err = unsafe { sys::esp_wifi_sta_get_ap_info(&mut rec) };
        (err == sys::ESP_OK).then_some((rec.rssi, rec.primary))
    }

    /// Call every couple of seconds: reconnect with backoff when down, and re-learn the LAN.
    pub fn poll(&mut self, shared: &Shared) {
        let connected = self.wifi.is_connected().unwrap_or(false);
        let now = Instant::now();
        if !connected {
            if self.connected {
                warn!("wifi: disconnected");
                self.connected = false;
            }
            if now >= self.next_try {
                info!("wifi: reconnecting (next try in {} s)", self.backoff.as_secs());
                let _ = self.wifi.connect();
                self.next_try = now + self.backoff;
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            }
            return;
        }
        if !self.connected {
            self.connected = true;
            self.backoff = MIN_BACKOFF;
            // Link-local address; with LWIP_IPV6_AUTOCONFIG this also starts SLAAC.
            // SAFETY: valid netif handle owned by `self.wifi`.
            let err = unsafe { sys::esp_netif_create_ip6_linklocal(self.wifi.sta_netif().handle()) };
            info!("wifi: connected; ipv6 link-local requested ({err})");
        }
        self.learn(shared);
    }

    fn learn(&self, shared: &Shared) {
        let netif = self.wifi.sta_netif();
        let v4 = netif.get_ip_info().ok().and_then(|i| {
            let ip: Ipv4Addr = i.ip;
            (!ip.is_unspecified()).then_some((ip, i.subnet.mask.0))
        });
        let mut addrs = [sys::esp_ip6_addr_t::default(); sys::CONFIG_LWIP_IPV6_NUM_ADDRESSES as usize];
        // SAFETY: the array holds CONFIG_LWIP_IPV6_NUM_ADDRESSES entries, as the API requires.
        let n = unsafe { sys::esp_netif_get_all_ip6(netif.handle(), addrs.as_mut_ptr()) };
        let n = usize::try_from(n).unwrap_or(0).min(addrs.len());
        let mut globals: Vec<Ipv6Addr> = Vec::new();
        let mut all: Vec<Ipv6Addr> = Vec::new();
        for a in addrs.iter_mut().take(n) {
            // lwIP keeps the four words in network byte order.
            let mut b = [0u8; 16];
            for (i, w) in a.addr.iter().enumerate() {
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            let ip = Ipv6Addr::from(b);
            all.push(ip);
            // SAFETY: plain classification of an address we own.
            let ty = unsafe { sys::esp_netif_ip6_get_addr_type(a) };
            if ty == sys::esp_ip6_addr_type_t_ESP_IP6_ADDR_IS_GLOBAL {
                globals.push(ip);
            }
        }
        let mut prefixes: Vec<(Ipv6Addr, u8)> = globals.iter().map(|a| (prefix64(*a), 64)).collect();
        prefixes.sort();
        prefixes.dedup();
        let v6_uplink = !globals.is_empty();
        crate::names::refresh(shared, v4.map(|(ip, _)| ip), &all);

        let changed = {
            let mut st = shared.lock();
            let changed = st.lan.v4 != v4 || st.lan.v6 != prefixes || st.v6_uplink != v6_uplink;
            if changed {
                st.lan.v4 = v4;
                st.lan.v6 = prefixes.clone();
                st.v6_uplink = v6_uplink;
            }
            changed
        };
        if changed {
            match v4 {
                Some((ip, p)) => info!("net: ipv4 {ip}/{p}"),
                None => info!("net: no ipv4 address"),
            }
            for a in &all {
                info!("net: ipv6 {a}");
            }
            info!("net: lan v6 prefixes {}, ipv6 uplink {}", prefixes.len(), if v6_uplink { "yes" } else { "no" });
        }
    }

    /// DEBUG ONLY: start the setup AP next to the station (AP+STA, the AP follows the
    /// station's channel) and scan; returns the visible network names.
    #[cfg(feature = "debug-hooks")]
    pub fn debug_ap(&mut self) -> anyhow::Result<Vec<String>> {
        let client = match self.wifi.get_configuration()? {
            Configuration::Client(c) | Configuration::Mixed(c, _) => c,
            _ => anyhow::bail!("not in station mode"),
        };
        let name = crate::portal::this_ap_name();
        self.wifi.set_configuration(&Configuration::Mixed(client, crate::portal::ap_config(&name)?))?;
        warn!("debug: AP+STA: open setup network \"{name}\" up next to the station");
        Ok(crate::portal::scan_names(&mut self.wifi))
    }

    /// DEBUG ONLY: drop the station link (the normal backoff reconnects it).
    #[cfg(feature = "debug-hooks")]
    pub fn debug_disconnect(&mut self) {
        warn!("debug: wifi disconnect requested");
        let _ = self.wifi.disconnect();
    }
}
