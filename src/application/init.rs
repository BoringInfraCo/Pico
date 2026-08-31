//! `pico init` application service (SPRINT-001.md §11).

use std::path::{Path, PathBuf};

use crate::persistence::Database;
use crate::shared::PicoError;

/// Result of a successful `pico init`.
#[derive(Debug, Clone)]
pub struct InitResult {
    pub workspace: PathBuf,
    pub db_path: PathBuf,
    pub schema_version: i64,
}

/// Initializes local Pico state in a workspace.
///
/// Idempotent: creates `.pico/` if missing, creates/opens `pico.db`,
/// applies migrations, and reports success. Never resets or deletes
/// existing state.
pub struct InitService;

impl InitService {
    pub fn run(workspace: &Path) -> Result<InitResult, PicoError> {
        let pico_dir = workspace.join(".pico");
        reject_symlink(&pico_dir)?;
        std::fs::create_dir_all(&pico_dir).map_err(|e| PicoError::init(e.to_string()))?;
        reject_symlink(&pico_dir)?;
        #[cfg(unix)]
        set_dir_permissions(&pico_dir)?;

        let db_path = pico_dir.join("pico.db");
        reject_symlink(&db_path)?;
        let mut db = Database::open(&db_path).map_err(|e| PicoError::init(e.to_string()))?;
        reject_symlink(&db_path)?;
        #[cfg(unix)]
        set_file_permissions(&db_path)?;

        db.migrate().map_err(|e| PicoError::init(e.to_string()))?;
        let schema_version = db
            .schema_version()
            .map_err(|e| PicoError::init(e.to_string()))?;

        Ok(InitResult {
            workspace: workspace.to_path_buf(),
            db_path,
            schema_version,
        })
    }
}

fn reject_symlink(path: &Path) -> Result<(), PicoError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(PicoError::init(format!(
            "refusing to use symlink at {}",
            path.display()
        ))),
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<(), PicoError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| PicoError::init(format!("cannot secure {}: {e}", path.display())))
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), PicoError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| PicoError::init(format!("cannot secure {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let first = InitService::run(dir.path()).unwrap();
        assert_eq!(first.schema_version, 5);
        assert!(first.db_path.exists());

        let second = InitService::run(dir.path()).unwrap();
        assert_eq!(second.schema_version, first.schema_version);
    }

    #[cfg(unix)]
    #[test]
    fn init_refuses_a_symlinked_database_path() {
        let dir = tempfile::tempdir().unwrap();
        let pico_dir = dir.path().join(".pico");
        std::fs::create_dir_all(&pico_dir).unwrap();
        let target = dir.path().join("outside.db");
        std::fs::write(&target, b"not-a-database").unwrap();
        std::os::unix::fs::symlink(&target, pico_dir.join("pico.db")).unwrap();
        let error = InitService::run(dir.path()).unwrap_err();
        assert!(error.to_string().contains("refusing to use symlink"));
        assert_eq!(std::fs::read(&target).unwrap(), b"not-a-database");
    }
}
