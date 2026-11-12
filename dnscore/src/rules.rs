//! Custom allow/block rules: exact names, `||domain^` subtrees and `*` globs.

use crate::name::normalize;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
    Empty,
    Invalid,
    TooMany,
    Duplicate,
}

/// The String is the canonical pattern text that matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    Allow(String),
    Block(String),
    None,
}

/// Longest glob pattern accepted, and most `*` it may contain (bounds match cost).
const MAX_GLOB: usize = 128;
const MAX_STARS: usize = 8;

enum Pattern {
    Exact(String),
    Subtree(String),
    Glob(String),
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, RuleError> {
        let t = text.trim();
        if t.is_empty() {
            return Err(RuleError::Empty);
        }
        if let Some(rest) = t.strip_prefix("||") {
            let rest = rest.strip_suffix('^').unwrap_or(rest);
            return normalize(rest).map(Pattern::Subtree).ok_or(RuleError::Invalid);
        }
        if t.contains('*') {
            let g = t.strip_suffix('.').unwrap_or(t).to_ascii_lowercase();
            let ok = g.len() <= MAX_GLOB
                && g.bytes().filter(|&b| b == b'*').count() <= MAX_STARS
                && g.bytes().all(|b| (0x21..=0x7e).contains(&b))
                && g.bytes().any(|b| b != b'*');
            return if ok { Ok(Pattern::Glob(g)) } else { Err(RuleError::Invalid) };
        }
        normalize(t).map(Pattern::Exact).ok_or(RuleError::Invalid)
    }

    fn canonical(&self) -> String {
        match self {
            Pattern::Exact(s) | Pattern::Glob(s) => s.clone(),
            Pattern::Subtree(s) => format!("||{s}^"),
        }
    }
}

/// Anchored glob match where `*` matches any run of bytes (including dots).
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while i < s.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = i;
            p += 1;
        } else if p < pat.len() && pat[p] == s[i] {
            p += 1;
            i += 1;
        } else if let Some(sp) = star {
            mark += 1;
            i = mark;
            p = sp + 1;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[derive(Default)]
struct Side {
    exact: HashSet<String>,
    subtree: HashSet<String>,
    globs: Vec<String>,
}

impl Side {
    fn contains(&self, p: &Pattern) -> bool {
        match p {
            Pattern::Exact(s) => self.exact.contains(s),
            Pattern::Subtree(s) => self.subtree.contains(s),
            Pattern::Glob(s) => self.globs.contains(s),
        }
    }

    fn insert(&mut self, p: Pattern) {
        match p {
            Pattern::Exact(s) => {
                self.exact.insert(s);
            }
            Pattern::Subtree(s) => {
                self.subtree.insert(s);
            }
            Pattern::Glob(s) => self.globs.push(s),
        }
    }

    fn remove(&mut self, p: &Pattern) -> bool {
        match p {
            Pattern::Exact(s) => self.exact.remove(s),
            Pattern::Subtree(s) => self.subtree.remove(s),
            Pattern::Glob(s) => {
                let before = self.globs.len();
                self.globs.retain(|g| g != s);
                self.globs.len() != before
            }
        }
    }

    /// `domain` must already be normalised.
    fn find(&self, domain: &str) -> Option<String> {
        if self.exact.contains(domain) {
            return Some(domain.to_string());
        }
        let mut cand = domain;
        loop {
            if self.subtree.contains(cand) {
                return Some(format!("||{cand}^"));
            }
            match cand.split_once('.') {
                Some((_, rest)) => cand = rest,
                None => break,
            }
        }
        self.globs.iter().find(|g| glob_match(g.as_bytes(), domain.as_bytes())).cloned()
    }
}

/// The canonical text `Rules` stores for `pattern` (as `list` returns it), or why it is invalid.
pub fn canonical(pattern: &str) -> Result<String, RuleError> {
    Pattern::parse(pattern).map(|p| p.canonical())
}

pub struct Rules {
    cap: usize,
    allow: Side,
    block: Side,
    entries: Vec<(RuleKind, String)>,
}

impl Rules {
    pub fn new(cap: usize) -> Self {
        Self { cap, allow: Side::default(), block: Side::default(), entries: Vec::new() }
    }

    fn side(&self, kind: RuleKind) -> &Side {
        match kind {
            RuleKind::Allow => &self.allow,
            RuleKind::Block => &self.block,
        }
    }

    fn side_mut(&mut self, kind: RuleKind) -> &mut Side {
        match kind {
            RuleKind::Allow => &mut self.allow,
            RuleKind::Block => &mut self.block,
        }
    }

    pub fn add(&mut self, kind: RuleKind, pattern: &str) -> Result<(), RuleError> {
        let p = Pattern::parse(pattern)?;
        if self.side(kind).contains(&p) {
            return Err(RuleError::Duplicate);
        }
        if self.entries.len() >= self.cap {
            return Err(RuleError::TooMany);
        }
        self.entries.push((kind, p.canonical()));
        self.side_mut(kind).insert(p);
        Ok(())
    }

    /// True if this exact rule (same kind, same canonical pattern) is present.
    pub fn contains(&self, kind: RuleKind, pattern: &str) -> bool {
        Pattern::parse(pattern).is_ok_and(|p| self.side(kind).contains(&p))
    }

    pub fn remove(&mut self, kind: RuleKind, pattern: &str) -> bool {
        let Ok(p) = Pattern::parse(pattern) else {
            return false;
        };
        if !self.side_mut(kind).remove(&p) {
            return false;
        }
        let c = p.canonical();
        self.entries.retain(|(k, t)| !(*k == kind && *t == c));
        true
    }

    pub fn list(&self) -> Vec<(RuleKind, String)> {
        self.entries.clone()
    }

    /// The rules in insertion order, canonical text, without copying.
    pub fn entries(&self) -> &[(RuleKind, String)] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Allow always wins over block.
    pub fn matches(&self, domain: &str) -> Match {
        let Some(d) = normalize(domain) else {
            return Match::None;
        };
        if let Some(a) = self.allow.find(&d) {
            return Match::Allow(a);
        }
        match self.block.find(&d) {
            Some(b) => Match::Block(b),
            None => Match::None,
        }
    }
}
