//! Sprint 043 Claude Code observability probe (SPRINT-043.md §§2.1/2.2/4).
//!
//! Binary-driven proof over a synthetic fake HOME (`tempfile` only; never the
//! real `~/.claude`), following the `sprint039_cli_test.rs` pattern:
//!
//! - `runtime --json` reports the Claude transcript `*.jsonl` count and the
//!   declared CLI version in `notes`; present-but-empty is distinct from absent.
//! - Claude distinctions are exactly SPRINT-043 §2.2 and the deferred-parsing
//!   reason is present in `notes`.
//! - Sentinels placed in fake transcript/`todos`/`shell-snapshot` files never
//!   appear in stdout, stderr, or JSON.
//! - Read-only proof: the fake HOME digest is unchanged and no sidecar appears.
//! - No Claude evidence/observation/"observed" claim is produced.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_APPEAR_043";

const SCRUBBED_ENV: &[&str] = &[
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
];

struct Env {
    workspace: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn seed_file(home: &Path, rel: &str, contents: &[u8]) {
    let path = home.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

/// Two countable transcripts, seeded in the documented nested layout
/// (`projects/<project>/<session>.jsonl`), plus non-`*.jsonl` files and
/// auxiliary Claude surfaces seeded with the sentinel.
fn seed_fake_home(home: &Path) {
    for rel in [
        ".claude/projects/proj-a/alpha.jsonl",
        ".claude/projects/proj-b/beta.jsonl",
        ".claude/projects/README.md",
        ".claude/sessions/thread.jsonl",
        ".claude/todos/todo.json",
        ".claude/shell-snapshots/snapshot.sh",
        ".claude/.credentials.json",
        ".local/share/claude/versions/2.1.260",
    ] {
        seed_file(home, rel, SENTINEL.as_bytes());
    }
}

fn setup() -> Env {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    seed_fake_home(home.path());
    Env { workspace, home }
}

fn pico_command(env: &Env, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    cmd.args(args)
        .current_dir(env.workspace.path())
        .env("HOME", env.home.path());
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd
}

fn run_pico(env: &Env, args: &[&str]) -> std::process::Output {
    pico_command(env, args).output().unwrap()
}

fn assert_secret_free(label: &str, text: &str) {
    assert!(!text.contains(SENTINEL), "{label} leaked the sentinel");
}

fn tree_digest(root: &Path) -> String {
    let mut entries: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    collect_entries(root, root, &mut entries);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0u8]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    format!("{:x}", hasher.finalize())
}

fn collect_entries(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(rel) = path.strip_prefix(root).map(Path::to_path_buf) else {
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            out.push((rel, b"dir".to_vec()));
            collect_entries(root, &path, out);
        } else {
            out.push((rel, fs::read(&path).unwrap_or_default()));
        }
    }
}

fn notes_text(value: &serde_json::Value) -> String {
    value["notes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|note| note.as_str().unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn s043_json_reports_claude_count_version_and_exact_distinctions() {
    let env = setup();
    let out = run_pico(&env, &["runtime", "--json"]);
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "a clean JSON run must not write stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    let notes = notes_text(&value);
    assert!(
        notes.contains("contains 2 *.jsonl"),
        "the transcript count must be reported in notes: {notes}"
    );
    assert!(
        notes.contains("Claude CLI version 2.1.260: DECLARED"),
        "the declared CLI version must be reported in notes: {notes}"
    );
    assert!(
        notes.contains("internal and version-varying")
            && notes.contains("does not parse transcripts yet"),
        "the deferred-parsing reason must be in notes: {notes}"
    );

    let distinctions = value["distinctions"].as_array().unwrap();
    let codes: Vec<&str> = distinctions
        .iter()
        .map(|entry| entry["distinction"].as_str().unwrap())
        .collect();
    let levels: Vec<&str> = distinctions
        .iter()
        .map(|entry| entry["level"].as_str().unwrap())
        .collect();
    assert_eq!(
        codes,
        [
            "configured_capability",
            "attempted_use",
            "approved_use",
            "completed_action"
        ]
    );
    assert_eq!(
        levels,
        [
            "observable",
            "available_unread",
            "not_available",
            "available_unread"
        ],
        "Claude distinctions must match SPRINT-043 §2.2"
    );

    assert_secret_free("runtime json stdout", &String::from_utf8_lossy(&out.stdout));
    assert!(
        !String::from_utf8_lossy(&out.stdout)
            .to_lowercase()
            .contains("observed"),
        "no observed/execution claim may be produced"
    );
}

#[test]
fn s043_present_but_empty_and_absent_are_reported_distinctly() {
    let workspace = tempfile::tempdir().unwrap();

    // Present but empty.
    let empty = tempfile::tempdir().unwrap();
    fs::create_dir_all(empty.path().join(".claude/projects")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    let out = cmd
        .args(["runtime", "--json"])
        .current_dir(workspace.path())
        .env("HOME", empty.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let notes = notes_text(&value);
    assert!(notes.contains("present but EMPTY"), "notes: {notes}");
    assert!(!notes.contains("is absent"), "notes: {notes}");

    // Absent.
    let absent = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_pico"))
        .args(["runtime", "--json"])
        .current_dir(workspace.path())
        .env("HOME", absent.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let notes = notes_text(&value);
    assert!(notes.contains("is absent"), "notes: {notes}");
    assert!(
        notes.contains("Claude CLI version: Unknown"),
        "notes: {notes}"
    );
    assert!(!notes.contains("present but EMPTY"), "notes: {notes}");
}

#[test]
fn s043_sentinel_in_claude_files_never_appears() {
    let env = setup();
    for args in [vec!["runtime"], vec!["runtime", "--json"]] {
        let out = run_pico(&env, &args);
        assert!(out.status.success());
        assert_secret_free("runtime stdout", &String::from_utf8_lossy(&out.stdout));
        assert_secret_free("runtime stderr", &String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
fn s043_runtime_is_read_only_and_creates_no_sidecars() {
    let env = setup();
    let before = tree_digest(env.home.path());
    assert!(run_pico(&env, &["runtime"]).status.success());
    assert!(run_pico(&env, &["runtime", "--json"]).status.success());
    assert_eq!(
        tree_digest(env.home.path()),
        before,
        "runtime must not mutate the fake Claude home"
    );

    let mut stack = vec![env.home.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.ends_with("-wal") && !name.ends_with("-shm"),
                "unexpected sidecar created: {}",
                entry.path().display()
            );
            if entry.path().is_dir() {
                stack.push(entry.path());
            }
        }
    }
}
