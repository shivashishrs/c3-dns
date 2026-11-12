//! The BOOT button (GPIO9, active low, internal pull-up). Holding it for 5 s clears the stored
//! Wi-Fi setting and the admin password (not rules, records or settings) and restarts into
//! the setup portal. Polled from the main task (priority 1, below DNS) every 100 ms: no task
//! or stack of its own, so it costs no heap. The debounce and timing logic is
//! `dnscore::button::Hold` (host-tested).

use std::time::Instant;

use dnscore::button::Hold;
use esp_idf_svc::hal::gpio::{Gpio9, Input, PinDriver, Pull};
use log::{error, warn};

pub struct Button {
    pin: PinDriver<'static, Input>,
    hold: Hold,
    boot: Instant,
}

impl Button {
    pub fn new(pin: Gpio9<'static>) -> anyhow::Result<Self> {
        Ok(Self { pin: PinDriver::input(pin, Pull::Up)?, hold: Hold::default(), boot: Instant::now() })
    }

    /// Sample the button; on a completed 5 s hold, clear the credentials and restart.
    pub fn poll(&mut self) {
        let now = self.boot.elapsed().as_millis() as u64;
        if self.hold.sample(self.pin.is_low(), now) {
            warn!("boot button hold: clearing credentials");
            clear_and_restart();
        }
    }
}

/// Clear the credentials and restart (into the portal). Shared with `/debug/creds/clear`.
pub fn clear_and_restart() -> ! {
    if let Err(e) = crate::creds::clear() {
        // NVS cannot be opened (or a key cannot be removed): the owner asked to start over, so
        // erase the whole NVS partition rather than leave the device stuck.
        error!("clearing credentials failed: {e}; erasing the NVS partition");
        if let Err(e) = crate::creds::erase_partition() {
            error!("erasing NVS failed: {e}");
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(200)); // let the log line out
    // SAFETY: plain restart.
    unsafe { esp_idf_svc::sys::esp_restart() }
}
