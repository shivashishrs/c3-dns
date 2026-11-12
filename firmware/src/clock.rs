//! Wall-clock time from SNTP (UTC). Until SNTP has synced at least once this boot, there is
//! no time: the RTC may still hold a reading from before a reset, or 1970 after power-on, and
//! neither is trusted. Saves and day rolls wait for `now()` (see `dnscore::persist`).

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dnscore::persist::{plausible, utc_string};
use esp_idf_svc::sntp::{EspSntp, SntpConf};
use log::{info, warn};

#[derive(Default)]
pub struct Clock {
    synced: AtomicBool,
    logged: AtomicBool,
}

impl Clock {
    /// Start SNTP (default pool servers, UTC). Keep the returned service alive.
    pub fn start() -> anyhow::Result<(Arc<Clock>, EspSntp<'static>)> {
        let clock = Arc::new(Clock::default());
        let c = clock.clone();
        // Runs in the lwIP task on every sync: only flip the flag.
        let sntp = EspSntp::new_with_callback(&SntpConf::default(), move |_| c.synced.store(true, Relaxed))?;
        Ok((clock, sntp))
    }

    fn raw_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }

    /// Unix seconds, only once SNTP has synced this boot and the reading is plausible.
    pub fn now(&self) -> Option<u64> {
        if !self.synced.load(Relaxed) {
            return None;
        }
        let t = Self::raw_secs();
        plausible(t).then_some(t)
    }

    /// For logs: the UTC time, or why there is none.
    pub fn describe(&self) -> String {
        match self.now() {
            Some(t) => utc_string(t),
            None if self.synced.load(Relaxed) => format!("implausible({})", Self::raw_secs()),
            None => "unsynced".to_string(),
        }
    }

    /// Call from the main loop: logs the first sync once.
    pub fn poll(&self) {
        if self.synced.load(Relaxed) && !self.logged.swap(true, Relaxed) {
            match self.now() {
                Some(t) => info!("time: SNTP synced, UTC {}", utc_string(t)),
                None => warn!("time: SNTP synced but the time is implausible ({} s); not used", Self::raw_secs()),
            }
        }
    }
}
