//! Best-effort wiping of plaintext secrets (passwords) once they are no longer needed.
//!
//! "Best effort" means: the buffers this crate and the firmware own are overwritten with zeros
//! before they are freed (`wipe`, `Secret`'s `Drop`), and `std::hint::black_box` keeps the
//! compiler from dropping those writes as dead stores. It does not reach copies outside our
//! control: the HTTP server's own request and header buffers, lwIP's packet buffers, or
//! anything the browser sends again. No `unsafe` (this crate forbids it).

/// Overwrite `b` with zeros.
pub fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        *x = 0;
    }
    std::hint::black_box(&*b);
}

/// Overwrite a vector's whole allocation (length and spare capacity) with zeros, then empty it.
pub fn wipe_vec(v: &mut Vec<u8>) {
    let cap = v.capacity();
    // Within the capacity: `resize` never reallocates, so this zeroes the one allocation.
    v.resize(cap, 0);
    wipe(v);
    v.clear();
}

/// Overwrite a string's allocation with zeros and leave it empty.
pub fn wipe_string(s: &mut String) {
    // `into_bytes` keeps the same allocation.
    let mut v = std::mem::take(s).into_bytes();
    wipe_vec(&mut v);
}

/// A plaintext secret (a password) that is wiped when dropped (best effort, see above). No
/// `Debug`, `Display` or `Clone`: it cannot end up in a log line or be copied by accident.
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Self {
        Secret(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe_string(&mut self.0);
    }
}
