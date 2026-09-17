//! Bounded lifecycle for the observation log (`.pico/watch.jsonl`,
//! SPRINT-044.md §2.2).
//!
//! `pico watch` appends one JSONL event per trigger and would otherwise grow
//! without bound. This module is the single implementation of the frozen
//! trim contract: count complete lines, keep the newest `keep` whole lines,
//! and rewrite atomically through a temporary sibling in the same directory
//! plus rename, so a crash never exposes a partially written log.
//!
//! The log is a sidecar file, never SQLite: trimming it is a pure filesystem
//! operation and never affects scan units, findings, diffs, or comparisons.
//! An absent log is not an error and is never created here — Pico never
//! treats a missing observation log as evidence of safety.

use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::shared::PicoError;

/// `pico prune` trims the observation log to this many whole events
/// (SPRINT-044.md §2.2).
pub const WATCH_LOG_MAX_EVENTS: usize = 1000;

/// `pico watch` self-bounds to this many events once [`WATCH_LOG_MAX_EVENTS`]
/// is exceeded; the gap is hysteresis so rewrites stay rare (~every 500
/// events) and amortized (SPRINT-044.md §2.2).
pub const WATCH_LOG_TRIM_TARGET: usize = 500;

/// Line-count outcome of one [`trim`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct TrimReport {
    /// Complete lines before the trim. A torn trailing partial line is not a
    /// line and is not counted.
    pub before: usize,
    /// Complete lines kept after the trim.
    pub after: usize,
    /// Complete lines dropped (`before - after`).
    pub removed: usize,
}

/// Count the complete lines in `path`, or `0` when the file is absent
/// (SPRINT-044.md §2.2). A trailing partial line without a terminating `\n`
/// is not counted.
pub fn len(path: &Path) -> Result<usize, PicoError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(read_error(path, &error)),
    };
    Ok(count_complete_lines(&bytes))
}

/// Keep the newest `keep` whole lines of `path`, dropping the rest and any
/// torn trailing partial line (SPRINT-044.md §2.2).
///
/// - Only complete lines are dropped; `before`/`after`/`removed` count them.
/// - The file is rewritten atomically through a temporary sibling in the same
///   directory, so a crash never leaves a partially written log.
/// - Idempotent: a second call with the same `keep` removes nothing and does
///   not rewrite the file.
/// - Never creates the file: an absent log yields a zeroed report and no
///   filesystem change.
/// - Line order (oldest → newest) is preserved.
pub fn trim(path: &Path, keep: usize) -> Result<TrimReport, PicoError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(TrimReport::default()),
        Err(error) => return Err(read_error(path, &error)),
    };

    let mut complete: Vec<&[u8]> = Vec::new();
    let mut line_start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            complete.push(&bytes[line_start..=index]);
            line_start = index + 1;
        }
    }
    let torn = line_start < bytes.len();

    let before = complete.len();
    let removed = before.saturating_sub(keep);
    let after = before - removed;

    // Nothing to drop and no torn tail: leave the file exactly as it is.
    if removed == 0 && !torn {
        return Ok(TrimReport {
            before,
            after,
            removed,
        });
    }

    let mut kept = Vec::new();
    for line in complete.iter().skip(removed) {
        kept.extend_from_slice(line);
    }
    write_atomic(path, &kept)?;

    Ok(TrimReport {
        before,
        after,
        removed,
    })
}

fn count_complete_lines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

fn read_error(path: &Path, error: &std::io::Error) -> PicoError {
    PicoError::io(format!("cannot read {}: {error}", path.display()))
}

/// One process-unique temporary sibling path in the target's directory.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name: OsString = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("watch.jsonl"));
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    path.with_file_name(name)
}

/// Write `contents` to `path` through a create-new temporary sibling then
/// rename. The temporary is removed on any failure; on success the rename
/// consumes it so no artifact is left behind.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), PicoError> {
    let temporary = temporary_sibling(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            PicoError::io(format!(
                "cannot create temporary watch log {}: {error}",
                temporary.display()
            ))
        })?;
    if let Err(error) = file.write_all(contents).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(PicoError::io(format!(
            "cannot write temporary watch log {}: {error}",
            temporary.display()
        )));
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(PicoError::io(format!(
            "cannot replace {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn workspace_log(dir: &Path) -> PathBuf {
        let pico = dir.join(".pico");
        std::fs::create_dir_all(&pico).unwrap();
        pico.join("watch.jsonl")
    }

    fn write_log(path: &Path, lines: &[&str]) {
        let mut file = std::fs::File::create(path).unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
    }

    fn temp_artifacts(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir.join(".pico"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("watch.jsonl.tmp"))
            .collect()
    }

    #[test]
    fn len_absent_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        assert_eq!(len(&path).unwrap(), 0);
    }

    #[test]
    fn len_counts_complete_lines_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        std::fs::write(&path, "").unwrap();
        assert_eq!(len(&path).unwrap(), 0);
        std::fs::write(&path, "only-a-torn-line").unwrap();
        assert_eq!(len(&path).unwrap(), 0);
        std::fs::write(&path, "a\nb\nc").unwrap();
        assert_eq!(len(&path).unwrap(), 2);
        std::fs::write(&path, "a\nb\n").unwrap();
        assert_eq!(len(&path).unwrap(), 2);
    }

    #[test]
    fn trim_keeps_newest_whole_lines_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        write_log(&path, &["e0", "e1", "e2", "e3", "e4"]);
        let report = trim(&path, 2).unwrap();
        assert_eq!(
            report,
            TrimReport {
                before: 5,
                after: 2,
                removed: 3
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "e3\ne4\n");
    }

    #[test]
    fn trim_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        write_log(&path, &["e0", "e1", "e2", "e3", "e4"]);
        let first = trim(&path, 3).unwrap();
        assert_eq!(first.removed, 2);
        let second = trim(&path, 3).unwrap();
        assert_eq!(
            second,
            TrimReport {
                before: 3,
                after: 3,
                removed: 0
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "e2\ne3\ne4\n");
    }

    #[test]
    fn trim_absent_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        let report = trim(&path, 5).unwrap();
        assert_eq!(report, TrimReport::default());
        assert!(!path.exists(), "an absent log must never be created");
    }

    #[test]
    fn trim_edge_cases_zero_one_at_cap_and_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        // keep 0: every complete line goes, the file remains (empty).
        write_log(&path, &["a", "b"]);
        assert_eq!(
            trim(&path, 0).unwrap(),
            TrimReport {
                before: 2,
                after: 0,
                removed: 2
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        // keep 1 over one line: no-op.
        write_log(&path, &["only"]);
        assert_eq!(
            trim(&path, 1).unwrap(),
            TrimReport {
                before: 1,
                after: 1,
                removed: 0
            }
        );
        // at cap: exactly keep lines removes nothing.
        write_log(&path, &["a", "b", "c"]);
        assert_eq!(trim(&path, 3).unwrap().removed, 0);
        // over cap: only the excess is dropped.
        assert_eq!(
            trim(&path, 2).unwrap(),
            TrimReport {
                before: 3,
                after: 2,
                removed: 1
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b\nc\n");
        // keep larger than the file: no-op.
        assert_eq!(trim(&path, 99).unwrap().removed, 0);
    }

    #[test]
    fn trim_drops_torn_trailing_line_not_keeps_it_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        std::fs::write(&path, "a\nb\nc-torn").unwrap();
        let report = trim(&path, 10).unwrap();
        assert_eq!(
            report,
            TrimReport {
                before: 2,
                after: 2,
                removed: 0
            }
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
        // A file with only a torn line becomes empty, with no line counted.
        std::fs::write(&path, "only-torn").unwrap();
        assert_eq!(trim(&path, 10).unwrap(), TrimReport::default());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn trim_leaves_no_temporary_artifact_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        write_log(&path, &["a", "b", "c", "d"]);
        trim(&path, 2).unwrap();
        assert!(temp_artifacts(dir.path()).is_empty());
    }

    #[test]
    fn trim_surfaces_io_error_when_parent_is_not_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "not a directory").unwrap();
        let path = blocker.join("watch.jsonl");
        let error = trim(&path, 5).unwrap_err();
        assert!(
            error.to_string().contains("cannot read"),
            "an io failure must surface, got: {error}"
        );
        let _ = len(&path).unwrap_err();
    }

    #[cfg(unix)]
    #[test]
    fn trim_surfaces_write_failure_when_directory_is_unwritable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = workspace_log(dir.path());
        write_log(&path, &["a", "b", "c"]);
        let pico = dir.path().join(".pico");
        std::fs::set_permissions(&pico, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = trim(&path, 1);
        std::fs::set_permissions(&pico, std::fs::Permissions::from_mode(0o755)).unwrap();
        if let Ok(report) = result {
            // Running with elevated privileges bypasses the directory mode;
            // the deterministic assertion is covered on normal test runs.
            assert_eq!(report.removed, 2);
            return;
        }
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("temporary watch log"),
            "a write failure must name the temporary artifact"
        );
        assert!(temp_artifacts(dir.path()).is_empty());
    }
}
