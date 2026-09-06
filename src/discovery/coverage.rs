//! Safe bounded collection manifest. Entries describe attempted locations,
//! never raw configuration, credential values, or exhaustive provider coverage.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Inspected,
    Incomplete,
    NotAttempted,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEntry {
    pub provider: String,
    pub operation: String,
    pub scope: String,
    pub scope_fingerprint: String,
    pub state: CoverageState,
}

impl CoverageEntry {
    pub fn candidate(provider: &str, locator: &str, path: &Path) -> Self {
        // A missing candidate was inspected successfully. Other metadata
        // failures and non-files cannot prove an empty configuration surface.
        let state = match std::fs::metadata(path) {
            Ok(value) if value.is_file() => CoverageState::Inspected,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CoverageState::Inspected,
            _ => CoverageState::Incomplete,
        };
        Self {
            provider: provider.into(),
            operation: "static_config".into(),
            scope: locator.into(),
            scope_fingerprint: format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes())),
            state,
        }
    }
    pub fn omitted_home(provider: &str) -> Self {
        Self {
            provider: provider.into(),
            operation: "static_config".into(),
            scope: "user".into(),
            scope_fingerprint: "not_attempted".into(),
            state: CoverageState::NotAttempted,
        }
    }
}
