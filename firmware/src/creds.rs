//! Credentials in the default NVS partition (0x9000, namespace `c3dns`), never in the storage
//! ring and never in `dnscore`'s persisted state:
//!
//! - `wifi`: one blob (SSID + Wi-Fi password, `dnscore::setup::encode_wifi`), written in one
//!   NVS operation so a power cut cannot leave half of it.
//! - `admin`: the admin password as a salted PBKDF2-HMAC-SHA256 record (`dnscore::auth`),
//!   computed by mbedtls (the C3's SHA accelerator); the plaintext is never stored.
//!
//! Nothing here logs a secret: only "set"/"not set" and lengths. Buffers that held a password
//! (the encoded Wi-Fi blob, the NVS read buffer) are wiped after use, best effort
//! (`dnscore::secret`).
//!
//! Provisioning (`wifi_state`): only a Wi-Fi entry that is definitively absent (NVS
//! `NOT_FOUND`, or the namespace never written) counts as "not provisioned" and opens the setup
//! portal. A read error or a damaged blob is `Unreadable`: `main` keeps retrying and never opens
//! the portal (whose next valid POST would overwrite the owner's admin password); a 5 s BOOT
//! hold is the way to start over (`button::clear_and_restart`).

use std::sync::OnceLock;

use dnscore::auth::{AdminHash, HASH_LEN, ITERATIONS, RECORD_LEN, SALT_LEN};
use dnscore::secret::{wipe, wipe_vec};
use dnscore::setup::{encode_wifi, provisioning_state, NvsRead, Provisioning};
use esp_idf_svc::nvs::{EspDefaultNvs, EspDefaultNvsPartition};
use esp_idf_svc::sys;
use log::{info, warn};

const NS: &str = "c3dns";
const KEY_WIFI: &str = "wifi";
const KEY_ADMIN: &str = "admin";
/// The Wi-Fi driver's own NVS namespace. This firmware runs the driver without NVS, but
/// earlier builds let it keep a copy of the network credentials there: it is erased with ours.
const NS_DRIVER: &str = "nvs.net80211";

static NVS: OnceLock<EspDefaultNvsPartition> = OnceLock::new();

/// Take the default NVS partition (once it succeeds; `main` retries while it fails). It is
/// never erased automatically: esp-idf-svc's `take()` would erase a partition that reports
/// "no free pages" or "new version", wiping the admin password and opening the portal.
pub fn init() -> bool {
    if NVS.get().is_some() {
        return true;
    }
    match EspDefaultNvsPartition::take_with(false) {
        Ok(p) => {
            let _ = NVS.set(p);
            true
        }
        Err(e) => {
            warn!("creds: NVS init failed ({e}); credentials cannot be read");
            false
        }
    }
}

fn open(ns: &str, rw: bool) -> anyhow::Result<EspDefaultNvs> {
    let p = NVS.get().ok_or_else(|| anyhow::anyhow!("creds: NVS not initialised"))?.clone();
    Ok(EspDefaultNvs::new(p, ns, rw)?)
}

/// Stored Wi-Fi settings (no `Debug`; the password is wiped on drop).
pub type Wifi = dnscore::setup::WifiSetting;

/// Whether Wi-Fi is provisioned (`dnscore::setup::provisioning_state` decides).
pub fn wifi_state() -> Provisioning {
    let Some(p) = NVS.get().cloned() else {
        return provisioning_state(NvsRead::Failed);
    };
    let nvs = match EspDefaultNvs::new(p, NS, false) {
        Ok(n) => n,
        // A namespace that was never written cannot be opened read-only: not provisioned.
        Err(e) if e.code() == sys::ESP_ERR_NVS_NOT_FOUND => return provisioning_state(NvsRead::Missing),
        Err(e) => {
            warn!("creds: opening the credentials namespace failed ({e})");
            return provisioning_state(NvsRead::Failed);
        }
    };
    let mut buf = [0u8; 2 + 32 + 64];
    let state = match nvs.get_blob(KEY_WIFI, &mut buf) {
        Ok(Some(b)) => {
            let s = provisioning_state(NvsRead::Data(b));
            if matches!(s, Provisioning::Unreadable) {
                warn!("creds: the stored wifi setting is damaged ({} bytes)", b.len());
            }
            s
        }
        Ok(None) => provisioning_state(NvsRead::Missing),
        Err(e) => {
            warn!("creds: reading the wifi setting failed ({e})");
            provisioning_state(NvsRead::Failed)
        }
    };
    wipe(&mut buf);
    state
}

fn admin_hash() -> Option<AdminHash> {
    let nvs = open(NS, false).ok()?;
    let mut buf = [0u8; RECORD_LEN + 1];
    let b = nvs.get_blob(KEY_ADMIN, &mut buf).ok()??;
    AdminHash::decode(b)
}

pub fn admin_set() -> bool {
    admin_hash().is_some()
}

/// mbedtls PBKDF2-HMAC-SHA256.
pub fn kdf(pw: &[u8], salt: &[u8], iterations: u32, out: &mut [u8; HASH_LEN]) -> bool {
    // SAFETY: valid pointers and lengths for the duration of the call; `out` holds HASH_LEN.
    let r = unsafe {
        sys::mbedtls_pkcs5_pbkdf2_hmac_ext(
            sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
            pw.as_ptr(),
            pw.len(),
            salt.as_ptr(),
            salt.len(),
            iterations,
            HASH_LEN as u32,
            out.as_mut_ptr(),
        )
    };
    r == 0
}

/// Random bytes from the hardware RNG (true random while the radio is on, which it is
/// whenever a password is set: in the portal and in normal mode).
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // SAFETY: writes exactly N bytes into `b`.
    unsafe { sys::esp_fill_random(b.as_mut_ptr().cast(), N) };
    b
}

/// SHA-256 (mbedtls, hardware-accelerated): the web UI's session cache keys verified
/// Authorization headers by this digest instead of keeping them.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: valid input pointer/length and a 32-byte output; is224 = 0 selects SHA-256.
    let r = unsafe { sys::mbedtls_sha256(data.as_ptr(), data.len(), out.as_mut_ptr(), 0) };
    if r != 0 {
        // Never expected; an all-zero digest would only make every cache lookup miss.
        warn!("creds: sha256 failed ({r})");
        return [0u8; 32];
    }
    out
}

/// Replace the admin password (web UI password change; the caller has verified the old one).
/// The salt is fresh; the plaintext is never stored or logged.
pub fn set_admin(new_password: &str) -> anyhow::Result<()> {
    let salt: [u8; SALT_LEN] = random();
    let hash = AdminHash::create(new_password, salt, ITERATIONS, &kdf)
        .ok_or_else(|| anyhow::anyhow!("admin password refused or hashing failed"))?;
    open(NS, true)?.set_blob(KEY_ADMIN, &hash.encode())?;
    info!("creds: admin password changed (salted hash stored)");
    Ok(())
}

/// The admin check for the web UI: user `admin` and the stored password. False when no
/// password is set. Slow on purpose (PBKDF2, `ITERATIONS`): callers must rate-limit (see
/// `http.rs`: session cache, lockout, one check at a time).
pub fn verify_admin(user: &str, password: &str) -> bool {
    match admin_hash() {
        Some(h) => h.verify(user, password, &kdf),
        None => false,
    }
}

/// Store a completed setup: the admin password first, then the Wi-Fi setting (whose presence
/// means "provisioned"), so a power cut in between only brings the portal back.
pub fn save_setup(ssid: &str, psk: &str, admin_password: &str) -> anyhow::Result<()> {
    let mut wifi = encode_wifi(ssid, psk).ok_or_else(|| anyhow::anyhow!("invalid wifi setting"))?;
    let r = store_setup(&wifi, admin_password);
    wipe_vec(&mut wifi);
    r?;
    info!("creds: saved wifi (ssid {} bytes) and admin password (salted hash)", ssid.len());
    Ok(())
}

fn store_setup(wifi: &[u8], admin_password: &str) -> anyhow::Result<()> {
    let salt: [u8; SALT_LEN] = random();
    let hash = AdminHash::create(admin_password, salt, ITERATIONS, &kdf)
        .ok_or_else(|| anyhow::anyhow!("admin password refused or hashing failed"))?;
    let nvs = open(NS, true)?;
    nvs.set_blob(KEY_ADMIN, &hash.encode())?;
    nvs.set_blob(KEY_WIFI, wifi)?;
    Ok(())
}

/// Store only the Wi-Fi setting (development seeding).
#[cfg(feature = "dev-wifi")]
fn save_wifi(ssid: &str, psk: &str) -> anyhow::Result<()> {
    let mut wifi = encode_wifi(ssid, psk).ok_or_else(|| anyhow::anyhow!("invalid wifi setting"))?;
    let r = open(NS, true).and_then(|n| Ok(n.set_blob(KEY_WIFI, &wifi)?));
    wipe_vec(&mut wifi);
    r
}

/// DEBUG ONLY: store a damaged Wi-Fi blob (a length byte past the end), to show on the spare
/// that an unreadable setting does not open the portal. Recovery: `tools/erase-nvs.sh`.
#[cfg(feature = "debug-hooks")]
pub fn debug_damage_wifi() -> anyhow::Result<()> {
    open(NS, true)?.set_blob(KEY_WIFI, &[0xff, 0x00])?;
    Ok(())
}

/// Last resort of a BOOT hold when the credentials cannot be removed one by one (NVS cannot be
/// opened): erase the whole default NVS partition (credentials, the driver's data, PHY
/// calibration, which is redone at boot). Only ever on the owner's explicit 5 s hold.
pub fn erase_partition() -> anyhow::Result<()> {
    // SAFETY: plain ESP-IDF call; it de-initialises the default partition first if needed.
    esp_idf_svc::sys::esp!(unsafe { sys::nvs_flash_erase() })?;
    Ok(())
}

/// Forget the Wi-Fi setting and the admin password (BOOT hold). Rules, records and settings
/// live in the storage ring and are untouched. Wi-Fi goes first: whatever happens after it,
/// the next boot is the portal, which sets a new admin password.
pub fn clear() -> anyhow::Result<()> {
    let nvs = open(NS, true)?;
    nvs.remove(KEY_WIFI)?;
    nvs.remove(KEY_ADMIN)?;
    drop(nvs);
    if let Ok(d) = open(NS_DRIVER, true) {
        d.erase_all()?;
    }
    Ok(())
}

#[cfg(feature = "dev-wifi")]
#[toml_cfg::toml_config]
pub struct Config {
    #[default("")]
    wifi_ssid: &'static str,
    #[default("")]
    wifi_psk: &'static str,
}

/// DEVELOPMENT ONLY (feature `dev-wifi`, never in the default build): when NVS holds no Wi-Fi
/// setting, seed it from the gitignored `firmware/cfg.toml` compiled into this build. A stored
/// setting is never overwritten. The admin password is never seeded (no default password).
#[cfg(feature = "dev-wifi")]
pub fn seed_dev_wifi() {
    match wifi_state() {
        Provisioning::Absent => {}
        s => {
            info!("creds: dev-wifi: stored wifi setting is {}; not seeding", s.name());
            return;
        }
    }
    if CONFIG.wifi_ssid.is_empty() {
        warn!("creds: dev-wifi: cfg.toml has no wifi_ssid; nothing to seed");
        return;
    }
    match save_wifi(CONFIG.wifi_ssid, CONFIG.wifi_psk) {
        Ok(()) => warn!("creds: dev-wifi: seeded the wifi setting into NVS from cfg.toml (development build)"),
        Err(e) => warn!("creds: dev-wifi: seeding failed ({e})"),
    }
}
