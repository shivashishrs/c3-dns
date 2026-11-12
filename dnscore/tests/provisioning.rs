//! Item: only a definitively absent Wi-Fi entry opens the setup portal. A read error or a
//! damaged blob must never be treated as "not provisioned" (the portal would then accept a
//! new admin password and overwrite the owner's).

use dnscore::setup::{encode_wifi, provisioning_state, NvsRead, Provisioning};

#[test]
fn not_found_means_absent_and_opens_the_portal() {
    assert!(matches!(provisioning_state(NvsRead::Missing), Provisioning::Absent));
}

#[test]
fn a_valid_blob_is_present() {
    let b = encode_wifi("Home Net", "secret pw").unwrap();
    match provisioning_state(NvsRead::Data(&b)) {
        Provisioning::Present(w) => {
            assert_eq!(w.ssid, "Home Net");
            assert_eq!(w.psk.as_str(), "secret pw");
        }
        _ => panic!("expected Present"),
    }
    let open = encode_wifi("Cafe", "").unwrap();
    assert!(matches!(provisioning_state(NvsRead::Data(&open)), Provisioning::Present(_)));
}

#[test]
fn a_read_error_is_unreadable_not_absent() {
    assert!(matches!(provisioning_state(NvsRead::Failed), Provisioning::Unreadable));
}

#[test]
fn a_damaged_blob_is_unreadable_not_absent() {
    let good = encode_wifi("Home Net", "secret pw").unwrap();
    let damaged: [&[u8]; 6] = [
        &[],                       // empty
        &good[..good.len() - 1],   // truncated
        &[0xff, 0x00],             // length byte past the end
        &[0, 0],                   // empty ssid
        &[2, 0xff, 0xfe, 0],       // invalid UTF-8
        &[4, b'a', b'b', b'c', b'd', 3, b'x', b'y', b'z'], // psk too short for WPA2
    ];
    for d in damaged {
        assert!(matches!(provisioning_state(NvsRead::Data(d)), Provisioning::Unreadable), "{d:?}");
    }
    let mut longer = good.clone();
    longer.push(b'x');
    assert!(matches!(provisioning_state(NvsRead::Data(&longer)), Provisioning::Unreadable));
}

#[test]
fn only_absent_opens_the_portal() {
    let good = encode_wifi("Home Net", "secret pw").unwrap();
    let cases = [
        (NvsRead::Missing, true),
        (NvsRead::Failed, false),
        (NvsRead::Data(&good), false),
        (NvsRead::Data(&[0xff]), false),
    ];
    for (r, portal) in cases {
        assert_eq!(provisioning_state(r).opens_portal(), portal);
    }
}
