//! Web API request parsing and validation (pure, host-tested): query parameters and the JSON
//! bodies of the state-changing endpoints. Every function returns either a validated request
//! or an `ApiError` whose text is shown to the owner as is. The firmware only moves bytes and
//! applies the result through `Shared::mutate`.

use std::net::IpAddr;

use crate::auth::check_password;
use crate::engine::ClientKey;
use crate::json::{parse_object, Object, Value};
use crate::persist::{check_record, check_rule};
use crate::rules::{RuleError, RuleKind};
use crate::secret::Secret;
use crate::store::{check_local_name, settings_valid, Settings, MAX_RATE_BURST, MAX_RATE_PER_SEC, MAX_UPSTREAMS};

/// Pause durations the UI offers (seconds); 0 means resume.
pub const PAUSE_CHOICES: [u32; 3] = [30, 300, 1800];

/// A message for the owner (JSON-escaped when sent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError(pub String);

impl ApiError {
    fn new(m: &str) -> Self {
        ApiError(m.to_string())
    }
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Value of `key` in the URI's query string, `%XX` and `+` decoded. `None` if absent, badly
/// encoded, not UTF-8 or containing control characters.
pub fn query_param(uri: &str, key: &str) -> Option<String> {
    let q = uri.split_once('?')?.1;
    let raw = q.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (k == key).then_some(v)
    })?;
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = hex(*b.get(i + 1)?)?;
                let l = hex(*b.get(i + 2)?)?;
                out.push(h << 4 | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    let s = String::from_utf8(out).ok()?;
    (!s.chars().any(char::is_control)).then_some(s)
}

/// A count parameter: `default` if absent or not a number, at most `max`.
pub fn clamp_n(v: Option<&str>, default: usize, max: usize) -> usize {
    match v {
        Some(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse::<usize>().unwrap_or(max).min(max),
        _ => default.min(max),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopKind {
    /// Allowed names (the UI calls the list "Top allowed").
    Queried,
    Blocked,
}

pub fn top_kind(v: Option<&str>) -> Result<TopKind, ApiError> {
    match v {
        None | Some("queried") => Ok(TopKind::Queried),
        Some("blocked") => Ok(TopKind::Blocked),
        Some(_) => Err(ApiError::new("kind must be queried or blocked.")),
    }
}

/// Parse a request body (see `json::parse_object` for the limits).
pub fn body(b: &[u8]) -> Result<Object, ApiError> {
    parse_object(b).map_err(|e| ApiError::new(e.message()))
}

fn only(o: &Object, allowed: &[&str]) -> Result<(), ApiError> {
    match o.keys().find(|k| !allowed.contains(k)) {
        Some(_) => Err(ApiError(format!("Unexpected field in the request; expected only: {}.", allowed.join(", ")))),
        None => Ok(()),
    }
}

fn text<'a>(o: &'a Object, key: &str) -> Result<&'a str, ApiError> {
    match o.get(key) {
        Some(Value::Str(s)) => Ok(s),
        Some(_) => Err(ApiError(format!("{key} must be text."))),
        None => Err(ApiError(format!("{key} is missing."))),
    }
}

fn num(o: &Object, key: &str) -> Result<Option<u64>, ApiError> {
    match o.get(key) {
        None => Ok(None),
        Some(Value::Num(n)) => Ok(Some(*n)),
        Some(_) => Err(ApiError(format!("{key} must be a whole number."))),
    }
}

fn ip(s: &str) -> Result<IpAddr, ApiError> {
    s.trim().parse::<IpAddr>().map_err(|_| ApiError(format!("{s:?} is not an IP address.")))
}

/// What the owner sees for a refused rule.
pub fn rule_error_message(e: RuleError) -> &'static str {
    match e {
        RuleError::Empty => "Enter a domain.",
        RuleError::Invalid => {
            "Not a valid domain or pattern. Use example.com (that name only), ||example.com^ (the domain and \
             its subdomains) or a wildcard such as *.ads.*."
        }
        RuleError::TooMany => "The list is full: remove an entry first.",
        RuleError::Duplicate => "That entry already exists.",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleOp {
    Add,
    Remove,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RuleReq {
    pub op: RuleOp,
    pub kind: RuleKind,
    /// Canonical pattern text (as `Rules` stores it).
    pub pattern: String,
}

/// `{"op":"add"|"remove","kind":"block"|"allow","pattern":"..."}`
pub fn rule_req(o: &Object) -> Result<RuleReq, ApiError> {
    only(o, &["op", "kind", "pattern"])?;
    let op = match text(o, "op")? {
        "add" => RuleOp::Add,
        "remove" => RuleOp::Remove,
        _ => return Err(ApiError::new("op must be add or remove.")),
    };
    let kind = match text(o, "kind")? {
        "block" => RuleKind::Block,
        "allow" => RuleKind::Allow,
        _ => return Err(ApiError::new("kind must be block or allow.")),
    };
    let pattern = check_rule(kind, text(o, "pattern")?).map_err(|e| ApiError::new(rule_error_message(e)))?;
    Ok(RuleReq { op, kind, pattern })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOp {
    Add,
    Remove,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RecordReq {
    pub op: RecordOp,
    /// Normalised name.
    pub name: String,
    /// Addresses (add only; empty for remove).
    pub ips: Vec<IpAddr>,
}

/// `{"op":"add","name":"nas.home","ips":["192.0.2.5","fd00::5"]}` or
/// `{"op":"remove","name":"nas.home"}`. Adding an existing name replaces its addresses.
pub fn record_req(o: &Object) -> Result<RecordReq, ApiError> {
    let op = match text(o, "op")? {
        "add" => RecordOp::Add,
        "remove" => RecordOp::Remove,
        _ => return Err(ApiError::new("op must be add or remove.")),
    };
    let name = text(o, "name")?;
    if op == RecordOp::Remove {
        only(o, &["op", "name"])?;
        let n = crate::normalize(name).ok_or_else(|| ApiError::new("Not a valid name."))?;
        return Ok(RecordReq { op, name: n, ips: Vec::new() });
    }
    only(o, &["op", "name", "ips"])?;
    let list = match o.get("ips") {
        Some(Value::Arr(v)) => v,
        Some(_) => return Err(ApiError::new("ips must be a list of addresses.")),
        None => return Err(ApiError::new("Enter at least one address.")),
    };
    let mut ips: Vec<IpAddr> = Vec::with_capacity(list.len());
    for s in list {
        let a = ip(s)?;
        if a.is_unspecified() || a.is_multicast() {
            return Err(ApiError(format!("{a} cannot be a record's address.")));
        }
        if ips.contains(&a) {
            return Err(ApiError(format!("{a} is listed twice.")));
        }
        ips.push(a);
    }
    let name = check_record(name, &ips).map_err(|e| {
        ApiError::new(match e {
            RuleError::Empty => "Enter at least one address.",
            RuleError::TooMany => "At most 8 addresses per name.",
            _ => "Not a valid name.",
        })
    })?;
    Ok(RecordReq { op, name, ips })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanOp {
    Ban,
    Unban,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BanReq {
    pub op: BanOp,
    pub client: ClientKey,
}

/// `{"op":"ban"|"unban","client":"192.0.2.7"}`
pub fn ban_req(o: &Object) -> Result<BanReq, ApiError> {
    only(o, &["op", "client"])?;
    let op = match text(o, "op")? {
        "ban" => BanOp::Ban,
        "unban" => BanOp::Unban,
        _ => return Err(ApiError::new("op must be ban or unban.")),
    };
    Ok(BanReq { op, client: ClientKey::from_ip(ip(text(o, "client")?)?) })
}

/// `{"secs":30|300|1800}` pauses blocking; `{"secs":0}` resumes. Returns the seconds.
pub fn pause_req(o: &Object) -> Result<u32, ApiError> {
    only(o, &["secs"])?;
    match num(o, "secs")? {
        Some(0) => Ok(0),
        Some(s) if PAUSE_CHOICES.iter().any(|&c| u64::from(c) == s) => Ok(s as u32),
        _ => Err(ApiError::new("secs must be 30, 300 or 1800 (or 0 to resume).")),
    }
}

fn upstream_ok(a: &IpAddr) -> bool {
    let link_local_v6 = matches!(a, IpAddr::V6(v) if v.segments()[0] & 0xffc0 == 0xfe80);
    let broadcast = matches!(a, IpAddr::V4(v) if v.is_broadcast());
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || link_local_v6 || broadcast)
}

fn unmapped(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(a, IpAddr::V4),
        v4 => v4,
    }
}

/// Any subset of `{"upstreams":[...],"rate_burst":n,"rate_per_sec":n,"local_name":"..."}`
/// (at least one), applied to `cur`. Returns the complete new settings, already validated.
/// `own` holds the device's own addresses: an upstream equal to one of them would forward
/// queries to itself in a loop and is refused.
pub fn settings_req(o: &Object, cur: &Settings, own: &[IpAddr]) -> Result<Settings, ApiError> {
    only(o, &["upstreams", "rate_burst", "rate_per_sec", "local_name"])?;
    if o.keys().next().is_none() {
        return Err(ApiError::new("Nothing to change."));
    }
    let mut s = cur.clone();
    match o.get("upstreams") {
        None => {}
        Some(Value::Arr(list)) => {
            if list.is_empty() || list.len() > MAX_UPSTREAMS {
                return Err(ApiError(format!("Give 1 to {MAX_UPSTREAMS} upstream servers.")));
            }
            let mut ups: Vec<IpAddr> = Vec::with_capacity(list.len());
            for t in list {
                let a = ip(t)?;
                if !upstream_ok(&a) {
                    return Err(ApiError(format!("{a} cannot be an upstream server.")));
                }
                if own.iter().any(|x| unmapped(*x) == unmapped(a)) {
                    return Err(ApiError(format!(
                        "{a} is this device itself: queries would loop. Use your router or a public DNS server."
                    )));
                }
                if ups.contains(&a) {
                    return Err(ApiError(format!("{a} is listed twice.")));
                }
                ups.push(a);
            }
            if !ups.iter().any(IpAddr::is_ipv4) {
                return Err(ApiError::new(
                    "Include at least one IPv4 upstream: IPv6 upstreams are only used while the network has IPv6.",
                ));
            }
            s.upstreams = ups;
        }
        Some(_) => return Err(ApiError::new("upstreams must be a list of addresses.")),
    }
    if let Some(b) = num(o, "rate_burst")? {
        if !(1..=u64::from(MAX_RATE_BURST)).contains(&b) {
            return Err(ApiError(format!("rate_burst must be 1 to {MAX_RATE_BURST}.")));
        }
        s.rate_burst = b as u32;
    }
    if let Some(p) = num(o, "rate_per_sec")? {
        if !(1..=u64::from(MAX_RATE_PER_SEC)).contains(&p) {
            return Err(ApiError(format!("rate_per_sec must be 1 to {MAX_RATE_PER_SEC}.")));
        }
        s.rate_per_sec = p as u32;
    }
    if o.get("local_name").is_some() {
        s.local_name = check_local_name(text(o, "local_name")?).map_err(|e| ApiError::new(e.message()))?;
    }
    if !settings_valid(&s) {
        return Err(ApiError::new("Those settings are out of bounds."));
    }
    Ok(s)
}

/// A password change. No `Debug`: it holds passwords (wiped when dropped, best effort).
pub struct PasswordReq {
    pub old: Secret,
    pub new: Secret,
}

/// `{"old":"...","new":"..."}`: the new password must pass the policy (12 to 128 characters).
pub fn password_req(o: &Object) -> Result<PasswordReq, ApiError> {
    only(o, &["old", "new"])?;
    let old = text(o, "old")?;
    if old.is_empty() {
        return Err(ApiError::new("Enter the current password."));
    }
    let new = text(o, "new")?;
    check_password(new).map_err(|e| ApiError::new(e.message()))?;
    Ok(PasswordReq { old: Secret::from(old), new: Secret::from(new) })
}
