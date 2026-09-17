//! Safe bounded collection manifest. Entries describe attempted locations,
//! never raw configuration, credential values, or exhaustive provider coverage.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Operation name for the opt-in read of supported agent runtime artifacts
/// (SPRINT-040 §1.9). Unlike `static_config`, this operation is only ever
/// recorded when the operator explicitly enabled runtime ingestion.
pub const OPERATION_RUNTIME_ARTIFACTS: &str = "runtime_artifacts";
/// Provider whose runtime store the `runtime_artifacts` operation reads.
pub const PROVIDER_OPENCODE: &str = "opencode";
/// Stable scope label for the OpenCode runtime store read. It is structural and
/// never contains the resolved filesystem path.
pub const SCOPE_OPENCODE_RUNTIME_STORE: &str = "user:opencode_runtime_store";

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

    /// Coverage for an attempted runtime-artifact read (SPRINT-040 §1.9).
    ///
    /// The caller is responsible for passing an honest `state`:
    /// `Inspected` on a successful read, `Incomplete` on truncation/corrupt/busy,
    /// `Unknown` on an unsupported schema. The entry is never created when the
    /// runtime step did not run.
    pub fn runtime_artifacts(state: CoverageState, store: &Path) -> Self {
        Self {
            provider: PROVIDER_OPENCODE.into(),
            operation: OPERATION_RUNTIME_ARTIFACTS.into(),
            scope: SCOPE_OPENCODE_RUNTIME_STORE.into(),
            scope_fingerprint: format!(
                "{:x}",
                Sha256::digest(store.as_os_str().as_encoded_bytes())
            ),
            state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_artifact_entry_is_structural_and_path_free() {
        let store = Path::new("/home/example/.local/share/opencode/opencode.db");
        let entry = CoverageEntry::runtime_artifacts(CoverageState::Inspected, store);
        assert_eq!(entry.provider, PROVIDER_OPENCODE);
        assert_eq!(entry.operation, OPERATION_RUNTIME_ARTIFACTS);
        assert_eq!(entry.scope, SCOPE_OPENCODE_RUNTIME_STORE);
        assert_eq!(entry.scope_fingerprint.len(), 64);
        assert!(entry
            .scope_fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit()));
        assert_eq!(entry.state, CoverageState::Inspected);
        // The resolved path never appears in the manifest.
        assert!(!entry.scope.contains("opencode.db"));
    }

    #[test]
    fn runtime_artifact_entry_preserves_honest_state() {
        let store = Path::new("/tmp/opencode.db");
        assert_eq!(
            CoverageEntry::runtime_artifacts(CoverageState::Incomplete, store).state,
            CoverageState::Incomplete
        );
        assert_eq!(
            CoverageEntry::runtime_artifacts(CoverageState::Unknown, store).state,
            CoverageState::Unknown
        );
    }
}
