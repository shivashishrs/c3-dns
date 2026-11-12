//! Domain name normalisation.

/// Lowercase, strip one trailing dot, validate label (<= 63) and total (<= 253) lengths.
/// Only printable ASCII (no spaces) is accepted.
pub fn normalize(name: &str) -> Option<String> {
    let n = name.strip_suffix('.').unwrap_or(name);
    if n.is_empty() || n.len() > 253 {
        return None;
    }
    for label in n.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return None;
        }
    }
    Some(n.to_ascii_lowercase())
}
