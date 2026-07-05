//! Phases 5–6 — scoring engine (masquerade rules + weighted aggregation).

pub mod rules;
pub mod score;

pub use rules::{evaluate, FiredRule};
