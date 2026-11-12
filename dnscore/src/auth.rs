//! The admin credential: password policy and a salted slow hash (PBKDF2-HMAC-SHA256).
//!
//! The KDF itself is passed in (`Kdf`): mbedtls on the device, a reference implementation in
//! the host tests. Everything else (policy, record format, constant-time comparison) is here.
//!
//! Stored record (`RECORD_LEN` = 53 bytes): version 1 | iterations (u32 LE) | salt (16) |
//! PBKDF2-HMAC-SHA256(password, salt, iterations) (32). The password itself is never stored.

/// The only user name.
pub const ADMIN_USER: &str = "admin";
pub const SALT_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
pub const RECORD_LEN: usize = 1 + 4 + SALT_LEN + HASH_LEN;
const VERSION: u8 = 1;
/// Iterations for new hashes. Measured on the spare (mbedtls with the C3's SHA accelerator):
/// see `ITERATIONS_NOTE` in the firmware's creds.rs.
pub const ITERATIONS: u32 = 10_000;
/// Records with fewer iterations are refused (the floor of the project's policy).
pub const MIN_ITERATIONS: u32 = 4000;
/// Records with more are refused too: a damaged count must not stall the device for minutes.
pub const MAX_ITERATIONS: u32 = 200_000;
/// Password length in characters.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 128;
/// Inputs longer than this (bytes) are rejected by `verify` without hashing.
const MAX_INPUT_BYTES: usize = 4 * MAX_PASSWORD_CHARS;

/// `kdf(password, salt, iterations, out) -> ok`.
pub type Kdf<'a> = &'a dyn Fn(&[u8], &[u8], u32, &mut [u8; HASH_LEN]) -> bool;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    TooShort,
    TooLong,
}

impl PasswordError {
    pub fn message(self) -> &'static str {
        match self {
            PasswordError::TooShort => "The admin password must be at least 12 characters long.",
            PasswordError::TooLong => "The admin password must be at most 128 characters long.",
        }
    }
}

/// The admin password policy: 12 to 128 characters (Unicode scalar values).
pub fn check_password(pw: &str) -> Result<(), PasswordError> {
    let n = pw.chars().count();
    if n < MIN_PASSWORD_CHARS {
        Err(PasswordError::TooShort)
    } else if n > MAX_PASSWORD_CHARS {
        Err(PasswordError::TooLong)
    } else {
        Ok(())
    }
}

/// Equality whose time depends only on the lengths, not on where the inputs differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // black_box keeps the optimiser from turning the loop into an early-exit compare.
    std::hint::black_box(d) == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminHash {
    pub iterations: u32,
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; HASH_LEN],
}

impl AdminHash {
    /// Hash a new password (which must pass `check_password`) with a fresh random `salt`.
    pub fn create(password: &str, salt: [u8; SALT_LEN], iterations: u32, kdf: Kdf) -> Option<Self> {
        check_password(password).ok()?;
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return None;
        }
        let mut hash = [0u8; HASH_LEN];
        kdf(password.as_bytes(), &salt, iterations, &mut hash).then_some(Self { iterations, salt, hash })
    }

    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut r = [0u8; RECORD_LEN];
        r[0] = VERSION;
        r[1..5].copy_from_slice(&self.iterations.to_le_bytes());
        r[5..5 + SALT_LEN].copy_from_slice(&self.salt);
        r[5 + SALT_LEN..].copy_from_slice(&self.hash);
        r
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != RECORD_LEN || b[0] != VERSION {
            return None;
        }
        let iterations = u32::from_le_bytes(b[1..5].try_into().ok()?);
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return None;
        }
        Some(Self {
            iterations,
            salt: b[5..5 + SALT_LEN].try_into().ok()?,
            hash: b[5 + SALT_LEN..].try_into().ok()?,
        })
    }

    /// True only for user `admin` and the right password. The hash comparison is
    /// constant-time; the user check is too (it runs before the KDF either way).
    pub fn verify(&self, user: &str, password: &str, kdf: Kdf) -> bool {
        let user_ok = ct_eq(user.as_bytes(), ADMIN_USER.as_bytes());
        if password.is_empty() || password.len() > MAX_INPUT_BYTES {
            return false;
        }
        let mut got = [0u8; HASH_LEN];
        if !kdf(password.as_bytes(), &self.salt, self.iterations, &mut got) {
            return false;
        }
        let hash_ok = ct_eq(&got, &self.hash);
        user_ok & hash_ok
    }
}
