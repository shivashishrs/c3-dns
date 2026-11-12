//! BOOT-button hold detection (pure): debounced, fires once when held for `HOLD_MS`.

/// How long the button must be held.
pub const HOLD_MS: u64 = 5000;
/// A level must stay this long before it counts (contact bounce is shorter).
pub const DEBOUNCE_MS: u64 = 50;

#[derive(Debug, Default)]
pub struct Hold {
    /// Debounced level.
    pressed: bool,
    /// Raw level and when it last changed.
    raw: bool,
    raw_since: u64,
    /// When the debounced press began.
    pressed_since: u64,
    fired: bool,
}

impl Hold {
    /// Feed one sample (`pressed` = the button is down) at `now_ms` (monotonic). Returns true
    /// exactly once per hold, when it has been held for `HOLD_MS`.
    pub fn sample(&mut self, pressed: bool, now_ms: u64) -> bool {
        if pressed != self.raw {
            self.raw = pressed;
            self.raw_since = now_ms;
        }
        if self.raw != self.pressed && now_ms.saturating_sub(self.raw_since) >= DEBOUNCE_MS {
            self.pressed = self.raw;
            if self.pressed {
                self.pressed_since = self.raw_since;
            } else {
                self.fired = false;
            }
        }
        if self.pressed && !self.fired && now_ms.saturating_sub(self.pressed_since) >= HOLD_MS {
            self.fired = true;
            return true;
        }
        false
    }
}
