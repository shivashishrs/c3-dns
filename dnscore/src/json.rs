//! Minimal JSON for the web API (no serde): a bounded parser for the flat request bodies the
//! UI sends, and an escaping writer for the streamed replies.
//!
//! Accepted input: one object whose values are strings, non-negative integers, `true`,
//! `false`, `null` or arrays of strings. Nothing nests deeper, so the parser never recurses.
//! Every limit (`MAX_BODY`, `MAX_KEYS`, `MAX_STR`, `MAX_ARRAY`) is checked before anything
//! grows past it. Decoded strings are valid UTF-8 without control characters.

use crate::secret::{wipe_string, wipe_vec};

/// Largest accepted body (bytes).
pub const MAX_BODY: usize = 2048;
/// Most keys in one object.
pub const MAX_KEYS: usize = 8;
/// Longest string after decoding (bytes).
pub const MAX_STR: usize = 512;
/// Most strings in one array.
pub const MAX_ARRAY: usize = 8;
/// Longest integer (digits): 15 digits always fit a u64 and stay exact in JavaScript.
const MAX_DIGITS: usize = 15;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Num(u64),
    Bool(bool),
    Null,
    Arr(Vec<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    TooLarge,
    Syntax,
    Depth,
    TooManyKeys,
    StringTooLong,
    ArrayTooLong,
    BadNumber,
    BadString,
    DuplicateKey,
    Trailing,
}

impl JsonError {
    pub fn message(self) -> &'static str {
        match self {
            JsonError::TooLarge => "The request body is too large.",
            JsonError::Syntax => "The request body is not valid JSON of the expected shape.",
            JsonError::Depth => "The request body nests too deeply.",
            JsonError::TooManyKeys => "The request body has too many fields.",
            JsonError::StringTooLong => "A text field is too long.",
            JsonError::ArrayTooLong => "A list in the request has too many entries.",
            JsonError::BadNumber => "Numbers must be whole and not negative.",
            JsonError::BadString => "A text field contains invalid characters.",
            JsonError::DuplicateKey => "A field appears twice.",
            JsonError::Trailing => "Unexpected data after the JSON object.",
        }
    }
}

/// A parsed object, keys in input order. Its `Debug` shows the keys only (a request body can
/// carry passwords), and every string in it is wiped when it is dropped (best effort, see
/// `secret`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Object {
    fields: Vec<(String, Value)>,
}

impl std::fmt::Debug for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Object").field("keys", &self.keys().collect::<Vec<_>>()).finish_non_exhaustive()
    }
}

fn wipe_value(v: &mut Value) {
    match v {
        Value::Str(s) => wipe_string(s),
        Value::Arr(a) => a.iter_mut().for_each(wipe_string),
        _ => {}
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        for (k, v) in &mut self.fields {
            wipe_string(k);
            wipe_value(v);
        }
    }
}

impl Object {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The value of `key` if it is a string.
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|(k, _)| k.as_str())
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn lit(&mut self, word: &[u8]) -> Result<(), JsonError> {
        if self.b.get(self.i..self.i + word.len()) == Some(word) {
            self.i += word.len();
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let h = self.b.get(self.i..self.i + 4).ok_or(JsonError::BadString)?;
        let mut v = 0u32;
        for &c in h {
            let d = (c as char).to_digit(16).ok_or(JsonError::BadString)?;
            v = v * 16 + d;
        }
        self.i += 4;
        Ok(v)
    }

    /// Bytes up to the closing quote (escapes skipped): an upper bound of the decoded length,
    /// since every escape decodes to fewer bytes than it takes.
    fn raw_len(&self) -> usize {
        let mut j = self.i + 1;
        while let Some(&c) = self.b.get(j) {
            match c {
                b'"' => break,
                b'\\' => j += 2,
                _ => j += 1,
            }
        }
        j.saturating_sub(self.i + 1)
    }

    /// A string starting at the opening quote. Its buffer is allocated once (never regrown, so
    /// no stray copy is left behind) and wiped if the string is refused.
    fn string(&mut self) -> Result<String, JsonError> {
        let mut out: Vec<u8> = Vec::with_capacity(self.raw_len().min(MAX_STR + 4));
        if let Err(e) = self.string_into(&mut out) {
            wipe_vec(&mut out);
            return Err(e);
        }
        let mut s = match String::from_utf8(out) {
            Ok(s) => s,
            Err(e) => {
                wipe_vec(&mut e.into_bytes());
                return Err(JsonError::BadString);
            }
        };
        if s.chars().any(char::is_control) {
            wipe_string(&mut s);
            return Err(JsonError::BadString);
        }
        Ok(s)
    }

    fn string_into(&mut self, out: &mut Vec<u8>) -> Result<(), JsonError> {
        self.eat(b'"')?;
        loop {
            let c = self.peek().ok_or(JsonError::Syntax)?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or(JsonError::Syntax)?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return Err(JsonError::BadString);
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(JsonError::BadString);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or(JsonError::BadString)?
                        }
                        _ => return Err(JsonError::BadString),
                    };
                    let mut tmp = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                }
                c if c < 0x20 => return Err(JsonError::BadString),
                c => out.push(c),
            }
            if out.len() > MAX_STR {
                return Err(JsonError::StringTooLong);
            }
        }
        Ok(())
    }

    fn number(&mut self) -> Result<u64, JsonError> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = &self.b[start..self.i];
        let leading_zero = digits.len() > 1 && digits[0] == b'0';
        let fraction = matches!(self.peek(), Some(b'.' | b'e' | b'E'));
        if digits.is_empty() || leading_zero || fraction || digits.len() > MAX_DIGITS {
            return Err(JsonError::BadNumber);
        }
        Ok(digits.iter().fold(0u64, |v, d| v * 10 + u64::from(d - b'0')))
    }

    fn array(&mut self) -> Result<Vec<String>, JsonError> {
        self.eat(b'[')?;
        let mut v = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(v);
        }
        loop {
            self.ws();
            match self.peek() {
                Some(b'"') => {}
                Some(b'[' | b'{') => return Err(JsonError::Depth),
                _ => return Err(JsonError::Syntax),
            }
            if v.len() >= MAX_ARRAY {
                return Err(JsonError::ArrayTooLong);
            }
            v.push(self.string()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(v);
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn value(&mut self) -> Result<Value, JsonError> {
        match self.peek() {
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => self.array().map(Value::Arr),
            Some(b'{') => Err(JsonError::Depth),
            Some(b't') => self.lit(b"true").map(|_| Value::Bool(true)),
            Some(b'f') => self.lit(b"false").map(|_| Value::Bool(false)),
            Some(b'n') => self.lit(b"null").map(|_| Value::Null),
            Some(b'0'..=b'9') => self.number().map(Value::Num),
            Some(b'-' | b'+' | b'.') => Err(JsonError::BadNumber),
            _ => Err(JsonError::Syntax),
        }
    }
}

/// Parse one flat JSON object (see the module docs for what is accepted).
pub fn parse_object(b: &[u8]) -> Result<Object, JsonError> {
    if b.len() > MAX_BODY {
        return Err(JsonError::TooLarge);
    }
    let mut p = P { b, i: 0 };
    let mut o = Object::default();
    p.ws();
    p.eat(b'{')?;
    p.ws();
    if p.peek() == Some(b'}') {
        p.i += 1;
    } else {
        loop {
            p.ws();
            if p.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            if o.fields.len() >= MAX_KEYS {
                return Err(JsonError::TooManyKeys);
            }
            let mut k = p.string()?;
            p.ws();
            if let Err(e) = p.eat(b':') {
                wipe_string(&mut k);
                return Err(e);
            }
            p.ws();
            let mut v = match p.value() {
                Ok(v) => v,
                Err(e) => {
                    wipe_string(&mut k);
                    return Err(e);
                }
            };
            if o.get(&k).is_some() {
                wipe_string(&mut k);
                wipe_value(&mut v);
                return Err(JsonError::DuplicateKey);
            }
            o.fields.push((k, v));
            p.ws();
            match p.peek() {
                Some(b',') => p.i += 1,
                Some(b'}') => {
                    p.i += 1;
                    break;
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }
    p.ws();
    if p.i != b.len() {
        return Err(JsonError::Trailing);
    }
    Ok(o)
}

// ---- writing ----

/// Where reply bytes go: a `Vec` on the host, a small chunk buffer on the device.
pub trait Sink {
    fn put(&mut self, b: &[u8]);
}

impl Sink for Vec<u8> {
    fn put(&mut self, b: &[u8]) {
        self.extend_from_slice(b);
    }
}

/// `s` as a quoted JSON string. Quotes, backslashes and control characters are escaped, and
/// so are `<`, `>`, `&`, U+2028 and U+2029 (harmless in JSON, risky if a reply is ever
/// embedded in HTML or a script). The input is a `&str`, so the output is always valid UTF-8.
pub fn write_str(o: &mut (impl Sink + ?Sized), s: &str) {
    o.put(b"\"");
    let mut run = 0; // start of the pending run of bytes that need no escaping
    for (i, c) in s.char_indices() {
        let esc: Option<&[u8]> = match c {
            '"' => Some(b"\\\""),
            '\\' => Some(b"\\\\"),
            '\n' => Some(b"\\n"),
            '\r' => Some(b"\\r"),
            '\t' => Some(b"\\t"),
            '\u{8}' => Some(b"\\b"),
            '\u{c}' => Some(b"\\f"),
            _ => None,
        };
        let hex = matches!(c, '\0'..='\u{1f}' | '\u{7f}' | '<' | '>' | '&' | '\u{2028}' | '\u{2029}');
        if esc.is_none() && !hex {
            continue;
        }
        o.put(&s.as_bytes()[run..i]);
        run = i + c.len_utf8();
        match esc {
            Some(e) => o.put(e),
            None => {
                const H: &[u8; 16] = b"0123456789abcdef";
                let v = c as u32;
                o.put(&[
                    b'\\',
                    b'u',
                    H[(v >> 12 & 15) as usize],
                    H[(v >> 8 & 15) as usize],
                    H[(v >> 4 & 15) as usize],
                    H[(v & 15) as usize],
                ]);
            }
        }
    }
    o.put(&s.as_bytes()[run..]);
    o.put(b"\"");
}

/// `v` in decimal.
pub fn write_u64(o: &mut (impl Sink + ?Sized), mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    o.put(&buf[i..]);
}
