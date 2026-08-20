//! Pico's own error types and diagnostics.
//!
//! Sprint 001 distinguishes the error classes required by
//! SPRINT-001.md §4 (Diagnostics): initialization failure, database
//! failure, migration failure, and scan failure.

use std::fmt;

use crate::domain::DomainError;

/// Top-level Pico error, distinguishing failure classes.
#[derive(Debug)]
pub enum PicoError {
    /// Pico workspace initialization failed.
    Init(String),
    /// Database operation failed.
    Database(String),
    /// Schema migration failed.
    Migration(String),
    /// A scan could not be created or completed.
    Scan(String),
    /// Filesystem operation failed.
    Io(String),
    /// A domain object or transition was invalid.
    Domain(DomainError),
    /// The command was invoked incorrectly.
    Usage(String),
}

impl PicoError {
    pub fn init(msg: impl Into<String>) -> Self {
        PicoError::Init(msg.into())
    }
    pub fn database(msg: impl Into<String>) -> Self {
        PicoError::Database(msg.into())
    }
    pub fn migration(msg: impl Into<String>) -> Self {
        PicoError::Migration(msg.into())
    }
    pub fn scan(msg: impl Into<String>) -> Self {
        PicoError::Scan(msg.into())
    }
    pub fn io(msg: impl Into<String>) -> Self {
        PicoError::Io(msg.into())
    }
    pub fn usage(msg: impl Into<String>) -> Self {
        PicoError::Usage(msg.into())
    }
}

impl fmt::Display for PicoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PicoError::Init(msg) => write!(f, "initialization failure: {msg}"),
            PicoError::Database(msg) => write!(f, "database failure: {msg}"),
            PicoError::Migration(msg) => write!(f, "migration failure: {msg}"),
            PicoError::Scan(msg) => write!(f, "scan failure: {msg}"),
            PicoError::Io(msg) => write!(f, "io failure: {msg}"),
            PicoError::Domain(err) => write!(f, "domain error: {err}"),
            PicoError::Usage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for PicoError {}

impl From<rusqlite::Error> for PicoError {
    fn from(e: rusqlite::Error) -> Self {
        PicoError::Database(e.to_string())
    }
}

impl From<std::io::Error> for PicoError {
    fn from(e: std::io::Error) -> Self {
        PicoError::Io(e.to_string())
    }
}

impl From<DomainError> for PicoError {
    fn from(e: DomainError) -> Self {
        PicoError::Domain(e)
    }
}

impl From<chrono::ParseError> for PicoError {
    fn from(e: chrono::ParseError) -> Self {
        PicoError::Database(format!("invalid persisted timestamp: {e}"))
    }
}

/// The Pico version reported in scans and CLI output.
pub const PICO_VERSION: &str = env!("CARGO_PKG_VERSION");
