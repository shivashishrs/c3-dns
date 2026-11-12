//! Types that hold a plaintext password (or a Basic Authorization value) must not derive or
//! implement `Debug`, so that no `{:?}` can ever put a secret in a log line. Checked by
//! reading the sources: a type gaining `Debug` fails here. (The firmware's stored Wi-Fi type is
//! `dnscore::setup::WifiSetting`, checked below; `Secret` has no `Debug`, so a struct holding
//! one cannot derive it at all.)

const SOURCES: [(&str, &str); 5] = [
    ("dnscore/src/setup.rs", include_str!("../src/setup.rs")),
    ("dnscore/src/webauth.rs", include_str!("../src/webauth.rs")),
    ("dnscore/src/api.rs", include_str!("../src/api.rs")),
    ("dnscore/src/secret.rs", include_str!("../src/secret.rs")),
    ("dnscore/src/json.rs", include_str!("../src/json.rs")),
];

/// (file, type) pairs that hold secrets.
const SECRET_TYPES: [(&str, &str); 7] = [
    ("dnscore/src/setup.rs", "Form"),
    ("dnscore/src/setup.rs", "SetupRequest"),
    ("dnscore/src/setup.rs", "WifiSetting"),
    ("dnscore/src/setup.rs", "Provisioning"),
    ("dnscore/src/webauth.rs", "Credentials"),
    ("dnscore/src/api.rs", "PasswordReq"),
    ("dnscore/src/secret.rs", "Secret"),
];

fn source(file: &str) -> &'static str {
    SOURCES.iter().find(|(f, _)| *f == file).map(|(_, s)| *s).unwrap()
}

/// The attribute lines directly above `pub struct|enum NAME`.
fn attrs_of<'a>(src: &'a str, name: &str) -> Vec<&'a str> {
    let lines: Vec<&str> = src.lines().collect();
    let decl = lines
        .iter()
        .position(|l| {
            let t = l.trim_start();
            [format!("pub struct {name} "), format!("pub struct {name}("), format!("pub enum {name} ")]
                .iter()
                .any(|p| t.starts_with(p.as_str()))
        })
        .unwrap_or_else(|| panic!("declaration of {name} not found"));
    let mut out = Vec::new();
    for l in lines[..decl].iter().rev() {
        let t = l.trim_start();
        if t.starts_with("#[") || t.starts_with("///") {
            out.push(t);
        } else {
            break;
        }
    }
    out
}

#[test]
fn secret_holding_types_have_no_debug() {
    for (file, name) in SECRET_TYPES {
        let src = source(file);
        for a in attrs_of(src, name) {
            if a.starts_with("#[") {
                assert!(!a.contains("Debug"), "{file}: {name} derives Debug: {a}");
            }
        }
        for imp in [format!("impl std::fmt::Debug for {name}"), format!("impl Debug for {name}"), format!("impl fmt::Debug for {name}")] {
            assert!(!src.contains(&imp), "{file}: {name} implements Debug");
        }
    }
}

#[test]
fn the_check_itself_sees_derives() {
    // A type known to derive Debug is reported, so the check above is not vacuous.
    let a = attrs_of(source("dnscore/src/setup.rs"), "SetupError");
    assert!(a.iter().any(|l| l.contains("Debug")), "{a:?}");
}
