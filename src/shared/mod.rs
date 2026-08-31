//! Pico's own error types and diagnostics.
//!
//! Sprint 001 distinguishes the error classes required by
//! SPRINT-001.md §4 (Diagnostics): initialization failure, database
//! failure, migration failure, and scan failure.

use std::fmt;
use std::io::Read;
use std::path::Path;

use crate::domain::DomainError;

/// Maximum bytes read from a local config or dotenv file.
pub const MAX_LOCAL_FILE_BYTES: u64 = 1_048_576;

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

/// Read a regular file with a hard size cap. Symlinks, FIFOs, and devices are
/// refused so a workspace cannot hang or OOM the scanner.
pub fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|err| format!("cannot read file: {err}"))?;
    if !metadata.file_type().is_file() {
        return Err("refusing to read a non-regular file".to_string());
    }
    if metadata.len() > max_bytes {
        return Err("file exceeded bounded size".to_string());
    }
    let file = std::fs::File::open(path).map_err(|err| format!("cannot read file: {err}"))?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut contents = String::new();
    limited
        .read_to_string(&mut contents)
        .map_err(|err| format!("cannot read file: {err}"))?;
    if contents.len() as u64 > max_bytes {
        return Err("file exceeded bounded size".to_string());
    }
    Ok(contents)
}

/// Token-shaped values that must never be persisted. Keyed substring matches
/// like "token" are intentionally excluded so metadata such as
/// `pico-github-token-v1` still stores.
pub fn looks_like_token_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("ghp_")
        || trimmed.starts_with("gho_")
        || trimmed.starts_with("ghs_")
        || trimmed.starts_with("ghr_")
        || trimmed.starts_with("github_pat_")
        || trimmed.starts_with("cfut_")
}

/// Applies the deterministic terminal-safety policy to persisted text.
///
/// Printable ASCII (0x20-0x7E) and Unicode scalar values at or above U+00A0
/// pass through unchanged; every C0 control, DEL (0x7F), and C1 code point is
/// escaped as `\xHH` (uppercase hex over its UTF-8 bytes) so persisted text
/// can never spoof headings, colors, or additional terminal lines.
pub fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        let scalar = character as u32;
        if (0x20..=0x7E).contains(&scalar) || scalar >= 0xA0 {
            safe.push(character);
        } else {
            let mut encoded = [0u8; 4];
            for byte in character.encode_utf8(&mut encoded).as_bytes() {
                safe.push_str(&format!("\\x{byte:02X}"));
            }
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::terminal_safe;

    #[test]
    fn looks_like_token_value_matches_known_prefixes_only() {
        assert!(super::looks_like_token_value("ghp_LIVE"));
        assert!(super::looks_like_token_value("github_pat_LIVE"));
        assert!(!super::looks_like_token_value(
            "sha256:pico-github-token-v1"
        ));
        assert!(!super::looks_like_token_value("CLOUDFLARE_API_TOKEN"));
    }

    #[test]
    fn terminal_safe_passes_printable_and_unicode_text_through() {
        assert_eq!(terminal_safe("plain ASCII"), "plain ASCII");
        assert_eq!(terminal_safe("CRITICAL · HIGH"), "CRITICAL · HIGH");
        assert_eq!(terminal_safe("a → b"), "a → b");
    }

    #[test]
    fn terminal_safe_escapes_c0_del_and_c1_over_utf8_bytes() {
        assert_eq!(terminal_safe("line1\nline2"), "line1\\x0Aline2");
        assert_eq!(terminal_safe("col\ttab"), "col\\x09tab");
        assert_eq!(terminal_safe("\r"), "\\x0D");
        assert_eq!(terminal_safe("\u{7F}"), "\\x7F");
        assert_eq!(terminal_safe("\u{9B}"), "\\xC2\\x9B");
        assert_eq!(
            terminal_safe("\u{1B}[31mSPOOF\u{1B}[0m"),
            "\\x1B[31mSPOOF\\x1B[0m"
        );
    }
}
