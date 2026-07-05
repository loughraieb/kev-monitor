//! kev — Windows process-legitimacy agent.
//!
//! Library root. The binary (`main.rs`) is a thin CLI over these modules; integration
//! tests drive `collector::signature` directly. The serde types in [`model`] are the
//! integration contract consumed by frontends (the TUI in [`monitor`]).

pub mod config;
pub mod investigate;
pub mod knowledge;
pub mod model;
pub mod platform;

pub mod collector;
pub mod engine;
pub mod monitor;
pub mod reputation;
pub mod store;
