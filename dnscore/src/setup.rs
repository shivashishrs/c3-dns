//! The setup portal's logic (pure, host-tested): HTML escaping, `application/x-www-form-
//! urlencoded` parsing with hard limits, validation of the setup form, its rendering, the
//! per-boot token check and the attempt limiter. The firmware only moves bytes.

use crate::auth::{check_password, ct_eq, PasswordError};
use crate::secret::{wipe_string, wipe_vec, Secret};
use std::fmt::Write as _;

/// Largest accepted request body (bytes, still encoded).
pub const MAX_BODY: usize = 4096;
/// Largest key or value after decoding (bytes): fits 128 four-byte characters.
pub const MAX_FIELD: usize = 512;
/// Most fields in one body.
pub const MAX_FIELDS: usize = 8;
/// Most scanned networks offered in the list.
pub const MAX_SCAN: usize = 15;
/// POSTs accepted per minute (valid or not), for the whole portal.
pub const ATTEMPTS_PER_MIN: u32 = 10;
/// The portal (an open AP) shuts down after this long without a completed setup.
pub const PORTAL_TIMEOUT_MS: u64 = 15 * 60 * 1000;
pub const SSID_MAX: usize = 32;

/// Escape for HTML text and quoted attribute values.
pub fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    push_escaped(&mut o, s);
    o
}

pub fn push_escaped(o: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormError {
    TooLarge,
    TooManyFields,
    FieldTooLong,
    /// Bad `%XX`, invalid UTF-8 or a control character.
    BadEncoding,
    /// The same field twice (ambiguous: refused rather than guessed).
    Repeated,
}

impl FormError {
    pub fn message(self) -> &'static str {
        match self {
            FormError::TooLarge => "The form is too large.",
            FormError::TooManyFields => "The form has too many fields.",
            FormError::FieldTooLong => "A field is too long.",
            FormError::BadEncoding => "The form contains invalid characters.",
            FormError::Repeated => "A field appears twice.",
        }
    }
}

/// A parsed form. No `Debug`: the setup form carries passwords. Every key and value is wiped
/// when the form is dropped (best effort, see `secret`).
#[derive(Default)]
pub struct Form {
    fields: Vec<(String, String)>,
}

impl Form {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        for (k, v) in &mut self.fields {
            wipe_string(k);
            wipe_string(v);
        }
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode one key or value. The output is allocated once (never regrown, so no stray copy of a
/// password is left behind) and wiped on every refusal.
fn decode(part: &[u8]) -> Result<String, FormError> {
    let mut out = Vec::with_capacity(part.len().min(MAX_FIELD));
    if let Err(e) = decode_into(part, &mut out) {
        wipe_vec(&mut out);
        return Err(e);
    }
    let mut s = match String::from_utf8(out) {
        Ok(s) => s,
        Err(e) => {
            wipe_vec(&mut e.into_bytes());
            return Err(FormError::BadEncoding);
        }
    };
    if s.chars().any(char::is_control) {
        wipe_string(&mut s);
        return Err(FormError::BadEncoding);
    }
    Ok(s)
}

fn decode_into(part: &[u8], out: &mut Vec<u8>) -> Result<(), FormError> {
    let mut i = 0;
    while i < part.len() {
        let b = match part[i] {
            b'+' => b' ',
            b'%' => {
                let h = part.get(i + 1).copied().and_then(hex).ok_or(FormError::BadEncoding)?;
                let l = part.get(i + 2).copied().and_then(hex).ok_or(FormError::BadEncoding)?;
                i += 2;
                (h << 4) | l
            }
            b => b,
        };
        if out.len() >= MAX_FIELD {
            return Err(FormError::FieldTooLong);
        }
        out.push(b);
        i += 1;
    }
    Ok(())
}

/// Parse an urlencoded body. Every limit is checked before anything grows past it.
pub fn parse_form(body: &[u8]) -> Result<Form, FormError> {
    if body.len() > MAX_BODY {
        return Err(FormError::TooLarge);
    }
    let mut form = Form::default();
    for pair in body.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        if form.fields.len() >= MAX_FIELDS {
            return Err(FormError::TooManyFields);
        }
        let (k, v) = match pair.iter().position(|b| *b == b'=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        let mut k = decode(k)?;
        let mut v = decode(v)?;
        if form.get(&k).is_some() {
            wipe_string(&mut k);
            wipe_string(&mut v);
            return Err(FormError::Repeated);
        }
        form.fields.push((k, v));
    }
    Ok(form)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    BadToken,
    SsidMissing,
    SsidTooLong,
    PskLength,
    AdminMissing,
    AdminTooShort,
    AdminTooLong,
    AdminMismatch,
}

impl SetupError {
    pub fn message(self) -> &'static str {
        match self {
            SetupError::BadToken => "This form has expired. Reload the page and try again.",
            SetupError::SsidMissing => "Enter the Wi-Fi network name.",
            SetupError::SsidTooLong => "The Wi-Fi network name is longer than 32 bytes.",
            SetupError::PskLength => {
                "The Wi-Fi password must be empty (open network), 8 to 63 characters, or 64 hex digits."
            }
            SetupError::AdminMissing => "Choose an admin password.",
            SetupError::AdminTooShort => PasswordError::TooShort.message(),
            SetupError::AdminTooLong => PasswordError::TooLong.message(),
            SetupError::AdminMismatch => "The two admin passwords do not match.",
        }
    }
}

/// What a valid setup form carries. No `Debug`: it holds the Wi-Fi and admin passwords, which
/// are wiped when it is dropped.
pub struct SetupRequest {
    pub ssid: String,
    pub psk: Secret,
    pub admin: Secret,
}

fn psk_ok(p: &str) -> bool {
    p.is_empty() || (8..=63).contains(&p.len()) || (p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Check the form: the per-boot token first (an empty expected token never matches), then
/// the network name, the Wi-Fi password and the admin password (entered twice).
pub fn validate(form: &Form, token: &str) -> Result<SetupRequest, SetupError> {
    let t = form.get("t").unwrap_or("");
    if token.is_empty() || !ct_eq(t.as_bytes(), token.as_bytes()) {
        return Err(SetupError::BadToken);
    }
    let ssid = form.get("ssid").unwrap_or("");
    if ssid.is_empty() {
        return Err(SetupError::SsidMissing);
    }
    if ssid.len() > SSID_MAX {
        return Err(SetupError::SsidTooLong);
    }
    let psk = form.get("psk").unwrap_or("");
    if !psk_ok(psk) {
        return Err(SetupError::PskLength);
    }
    let admin = form.get("admin").unwrap_or("");
    if admin.is_empty() {
        return Err(SetupError::AdminMissing);
    }
    check_password(admin).map_err(|e| match e {
        PasswordError::TooShort => SetupError::AdminTooShort,
        PasswordError::TooLong => SetupError::AdminTooLong,
    })?;
    if !ct_eq(admin.as_bytes(), form.get("admin2").unwrap_or("").as_bytes()) {
        return Err(SetupError::AdminMismatch);
    }
    Ok(SetupRequest { ssid: ssid.to_string(), psk: Secret::from(psk), admin: Secret::from(admin) })
}

/// The setup page. `scan` names come from the air (attacker-controlled) and `ssid` from a
/// previous post: both are escaped, as is `message`. Passwords are never put back.
pub fn render_form(token: &str, scan: &[String], message: Option<&str>, ssid: Option<&str>, action: &str) -> String {
    let mut h = String::with_capacity(2048 + scan.len().min(MAX_SCAN) * 48);
    h.push_str(
        "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>C3-DNS setup</title><style>body{font:16px system-ui,sans-serif;max-width:420px;margin:24px auto;\
         padding:0 16px}input,button{width:100%;box-sizing:border-box;padding:10px;margin:4px 0 12px}\
         .m{padding:10px;border:1px solid #c33;color:#900}</style><h2>C3-DNS setup</h2>",
    );
    if let Some(m) = message {
        h.push_str("<p class=m>");
        push_escaped(&mut h, m);
        h.push_str("</p>");
    }
    h.push_str("<form method=post action=\"");
    push_escaped(&mut h, action);
    h.push_str("\"><input type=hidden name=t value=\"");
    push_escaped(&mut h, token);
    h.push_str("\"><label>Wi-Fi network<input name=ssid list=nets required maxlength=32 value=\"");
    push_escaped(&mut h, ssid.unwrap_or(""));
    h.push_str("\"></label><datalist id=nets>");
    for s in scan.iter().take(MAX_SCAN) {
        h.push_str("<option value=\"");
        push_escaped(&mut h, s);
        h.push_str("\">");
    }
    h.push_str(
        "</datalist><label>Wi-Fi password<input name=psk type=password autocomplete=off maxlength=64></label>\
         <label>New admin password (12 or more characters)<input name=admin type=password autocomplete=new-password \
         required minlength=12 maxlength=128></label><label>Admin password again<input name=admin2 type=password \
         autocomplete=new-password required minlength=12 maxlength=128></label><button>Save and restart</button>\
         </form><p>The admin user name is <b>admin</b>. This setup network is open: finish setup promptly. \
         It shuts down after 15 minutes.</p>",
    );
    h
}

/// A fixed one-minute window of `ATTEMPTS_PER_MIN` POSTs.
#[derive(Debug, Default)]
pub struct Attempts {
    start: u64,
    count: u32,
}

impl Attempts {
    pub fn allow(&mut self, now_ms: u64) -> bool {
        if self.count == 0 || now_ms.saturating_sub(self.start) >= 60_000 {
            self.start = now_ms;
            self.count = 0;
        }
        if self.count >= ATTEMPTS_PER_MIN {
            return false;
        }
        self.count += 1;
        true
    }
}

/// The per-boot form token: 16 random bytes as lowercase hex.
pub fn token_hex(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// `C3-DNS-XXXX` from the last two bytes of the MAC.
pub fn ap_name(mac: [u8; 6]) -> String {
    format!("C3-DNS-{:02X}{:02X}", mac[4], mac[5])
}

/// The stored Wi-Fi setting, one NVS blob so that it is written atomically:
/// ssid length (u8) | ssid | psk length (u8) | psk.
fn wifi_ok(ssid: &str, psk: &str) -> bool {
    !ssid.is_empty() && ssid.len() <= SSID_MAX && psk_ok(psk)
}

/// The caller wipes the returned bytes once stored (they hold the Wi-Fi password).
pub fn encode_wifi(ssid: &str, psk: &str) -> Option<Vec<u8>> {
    if !wifi_ok(ssid, psk) {
        return None;
    }
    let mut v = Vec::with_capacity(2 + ssid.len() + psk.len());
    v.push(ssid.len() as u8);
    v.extend_from_slice(ssid.as_bytes());
    v.push(psk.len() as u8);
    v.extend_from_slice(psk.as_bytes());
    Some(v)
}

/// The inverse of `encode_wifi`; `None` for anything damaged or out of bounds.
pub fn decode_wifi(b: &[u8]) -> Option<(String, String)> {
    let (&sl, rest) = b.split_first()?;
    let ssid = rest.get(..usize::from(sl))?;
    let (&pl, rest) = rest.get(usize::from(sl)..)?.split_first()?;
    let psk = rest.get(..usize::from(pl))?;
    if rest.len() != usize::from(pl) {
        return None;
    }
    let (ssid, psk) = (std::str::from_utf8(ssid).ok()?, std::str::from_utf8(psk).ok()?);
    if !wifi_ok(ssid, psk) {
        return None;
    }
    Some((ssid.to_string(), psk.to_string()))
}

/// A stored Wi-Fi setting. No `Debug`: the password is wiped when it is dropped.
pub struct WifiSetting {
    pub ssid: String,
    pub psk: Secret,
}

/// What reading the stored Wi-Fi entry gave (the firmware maps NVS results onto this).
pub enum NvsRead<'a> {
    /// The entry (or its whole namespace) does not exist: a first boot, or after a BOOT hold.
    Missing,
    /// The entry's bytes.
    Data(&'a [u8]),
    /// Any other failure: NVS not initialised, a read error, a wrong size.
    Failed,
}

/// Whether the device is provisioned. No `Debug`: `Present` holds the Wi-Fi password.
pub enum Provisioning {
    /// Definitively not provisioned: the only state that opens the setup portal.
    Absent,
    Present(WifiSetting),
    /// Something is stored but cannot be read or decoded. The portal must NOT open (its next
    /// valid POST would overwrite the owner's admin password): the firmware keeps retrying, and
    /// a 5 s BOOT hold is the owner's way to start over.
    Unreadable,
}

impl Provisioning {
    pub fn opens_portal(&self) -> bool {
        matches!(self, Provisioning::Absent)
    }

    /// For log lines (never the setting itself).
    pub fn name(&self) -> &'static str {
        match self {
            Provisioning::Absent => "not set",
            Provisioning::Present(_) => "set",
            Provisioning::Unreadable => "UNREADABLE",
        }
    }
}

/// The provisioning decision: only `Missing` is `Absent`; a damaged blob is `Unreadable`.
pub fn provisioning_state(r: NvsRead<'_>) -> Provisioning {
    match r {
        NvsRead::Missing => Provisioning::Absent,
        NvsRead::Failed => Provisioning::Unreadable,
        NvsRead::Data(b) => match decode_wifi(b) {
            Some((ssid, psk)) => Provisioning::Present(WifiSetting { ssid, psk: Secret::new(psk) }),
            None => Provisioning::Unreadable,
        },
    }
}
