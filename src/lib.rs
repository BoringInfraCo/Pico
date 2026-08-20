//! Pico — local-first developer security for AI-native engineering.
//!
//! Modular monolith with clear internal boundaries:
//!
//! ```text
//! cli -> application -> domain / persistence
//! ```

pub mod application;
pub mod cli;
pub mod domain;
pub mod persistence;
pub mod shared;
