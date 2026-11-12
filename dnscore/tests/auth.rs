use dnscore::auth::{
    check_password, ct_eq, AdminHash, PasswordError, ADMIN_USER, HASH_LEN, ITERATIONS, MIN_ITERATIONS, RECORD_LEN,
    SALT_LEN,
};

/// The host stand-in for the device's mbedtls PBKDF2-HMAC-SHA256.
fn kdf(pw: &[u8], salt: &[u8], iter: u32, out: &mut [u8; HASH_LEN]) -> bool {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, iter, out);
    true
}

const SALT: [u8; SALT_LEN] = [7; SALT_LEN];
const PW: &str = "correct horse battery";

#[test]
fn kdf_matches_the_rfc7914_vector() {
    // RFC 7914 section 11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1 (first 32 bytes).
    let mut out = [0u8; HASH_LEN];
    assert!(kdf(b"passwd", b"salt", 1, &mut out));
    assert_eq!(
        out,
        [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05, 0xf9, 0x41,
            0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc
        ]
    );
}

#[test]
fn policy_is_12_to_128_characters() {
    assert_eq!(check_password(""), Err(PasswordError::TooShort));
    assert_eq!(check_password("elevenchars"), Err(PasswordError::TooShort));
    assert_eq!(check_password("twelve chars"), Ok(()));
    // characters, not bytes: 12 two-byte characters pass, 11 do not
    assert_eq!(check_password(&"é".repeat(12)), Ok(()));
    assert_eq!(check_password(&"é".repeat(11)), Err(PasswordError::TooShort));
    assert_eq!(check_password(&"x".repeat(128)), Ok(()));
    assert_eq!(check_password(&"x".repeat(129)), Err(PasswordError::TooLong));
    assert!(PasswordError::TooShort.message().contains("12"));
    const { assert!(ITERATIONS >= MIN_ITERATIONS && MIN_ITERATIONS >= 4000) };
}

#[test]
fn stored_value_is_a_salted_hash_not_the_password() {
    let h = AdminHash::create(PW, SALT, ITERATIONS, &kdf).unwrap();
    let rec = h.encode();
    assert_eq!(rec.len(), RECORD_LEN);
    let pwb = PW.as_bytes();
    assert!(!rec.windows(pwb.len()).any(|w| w == pwb), "plaintext must not be in the record");
    assert_eq!(&rec[5..5 + SALT_LEN], &SALT, "salt stored next to the hash");
    let mut expect = [0u8; HASH_LEN];
    kdf(pwb, &SALT, ITERATIONS, &mut expect);
    assert_eq!(&rec[5 + SALT_LEN..], &expect);
    // another salt gives another record for the same password
    let other = AdminHash::create(PW, [8; SALT_LEN], ITERATIONS, &kdf).unwrap().encode();
    assert_ne!(rec[5 + SALT_LEN..], other[5 + SALT_LEN..]);
    assert_eq!(AdminHash::decode(&rec), Some(h));
}

#[test]
fn verify_accepts_only_the_right_user_and_password() {
    let h = AdminHash::create(PW, SALT, ITERATIONS, &kdf).unwrap();
    assert!(h.verify(ADMIN_USER, PW, &kdf));
    assert!(!h.verify(ADMIN_USER, "wrong password here", &kdf));
    assert!(!h.verify(ADMIN_USER, "", &kdf));
    let mut last = PW.to_string();
    last.pop();
    last.push('x');
    assert!(!h.verify(ADMIN_USER, &last, &kdf), "differs only in the last character");
    assert!(!h.verify(ADMIN_USER, &format!("{PW} "), &kdf));
    assert!(!h.verify("root", PW, &kdf));
    assert!(!h.verify("", PW, &kdf));
    assert!(!h.verify("admin ", PW, &kdf));
    // a failing KDF never verifies
    assert!(!h.verify(ADMIN_USER, PW, &|_: &[u8], _: &[u8], _: u32, _: &mut [u8; HASH_LEN]| false));
    assert!(!h.verify(ADMIN_USER, &"y".repeat(10_000), &kdf));
}

#[test]
fn create_refuses_bad_input() {
    assert!(AdminHash::create("short", SALT, ITERATIONS, &kdf).is_none(), "policy applies");
    assert!(AdminHash::create(PW, SALT, MIN_ITERATIONS - 1, &kdf).is_none());
    assert!(AdminHash::create(PW, SALT, ITERATIONS, &|_: &[u8], _: &[u8], _: u32, _: &mut [u8; HASH_LEN]| false).is_none());
}

#[test]
fn decode_rejects_damaged_records() {
    let rec = AdminHash::create(PW, SALT, ITERATIONS, &kdf).unwrap().encode();
    assert!(AdminHash::decode(&rec[..RECORD_LEN - 1]).is_none());
    assert!(AdminHash::decode(&[rec.as_slice(), &[0]].concat()).is_none());
    assert!(AdminHash::decode(&[]).is_none());
    let mut v = rec;
    v[0] = 99;
    assert!(AdminHash::decode(&v).is_none(), "unknown version");
    let mut low = rec;
    low[1..5].copy_from_slice(&1u32.to_le_bytes());
    assert!(AdminHash::decode(&low).is_none(), "too few iterations");
    let mut high = rec;
    high[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(AdminHash::decode(&high).is_none(), "absurd iteration count");
}

#[test]
fn ct_eq_basics() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    assert!(ct_eq(b"", b""));
}
