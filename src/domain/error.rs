//! Domain-level validation errors.

use std::fmt;

/// Errors produced by domain validation and state transitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A scan attempted a state transition that is not valid.
    InvalidTransition { from: String, to: String },
    /// A domain object was constructed with an invalid value.
    InvalidValue(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::InvalidTransition { from, to } => {
                write!(f, "invalid scan state transition: {from} -> {to}")
            }
            DomainError::InvalidValue(msg) => write!(f, "invalid value: {msg}"),
        }
    }
}

impl std::error::Error for DomainError {}
