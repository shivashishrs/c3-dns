#![forbid(unsafe_code)]
//! Host-testable DNS logic for the C3-DNS blocker.

pub mod api;
pub mod auth;
pub mod blocklist;
pub mod budget;
pub mod button;
pub mod cache;
pub mod engine;
pub mod host;
pub mod json;
pub mod lan;
pub mod limit;
pub mod listfile;
pub mod name;
pub mod names;
pub mod persist;
pub mod ring;
pub mod rules;
pub mod secret;
pub mod setup;
pub mod stats;
pub mod store;
pub mod timing;
pub mod webauth;
pub mod wire;

pub use blocklist::{hash40, BlockList};
pub use engine::{Action, ClientKey, Decision, Engine, LocalRecords, Reason};
pub use name::normalize;
pub use rules::{Match, RuleError, RuleKind, Rules};
pub use wire::{
    age_ttls, apply_0x20, build_blocked, build_local, build_refused, build_servfail,
    build_truncated, clamp_edns, parse_query, parse_response, restore_question, same_question,
    same_question_exact, set_id, set_ttls, ParseError, Query, Response,
    QTYPE_A, QTYPE_AAAA, QTYPE_CNAME,
};
