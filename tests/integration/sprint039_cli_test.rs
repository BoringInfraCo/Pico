//! Sprint 039 `pico runtime` CLI + integration tests (SPRINT-039.md §§2.3/4/5).
//!
//! Drives the compiled binary (`env!("CARGO_BIN_EXE_pico")`) with an isolated
//! temp workspace + a synthetic fake agent HOME (`tempfile` only; never the
//! real store), following the `tests/integration/sprint038_cli_test.rs`
//! binary-driving pattern:
//!
//! - `runtime --help` documents the read-only, metadata-only contract.
//! - Human output lists every surface, every distinction, and ends with the
//!   exact honesty line.
//! - `--json` validates against the public schema (`command: "runtime"`) and
//!   is byte-equal across repeated runs.
//! - A missing HOME yields explicit `unknown`/`not_available` levels, never
//!   blank reassurance.
//! - Read-only proof: the fake agent home (and workspace) digest is unchanged
//!   and no `-wal`/`-shm` sidecar appears.
//! - Secret sweep: synthetic sentinels placed in fake prompt-history and
//!   credential files never appear in stdout, stderr, or JSON.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pico::application::InitService;
use sha2::{Digest, Sha256};

const SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_APPEAR_039";
const HONESTY: &str = "This reports what is observable, not what the agent did.";

const WORKSPACE_CONFIG: &str = r#"{ "permission": { "bash": "allow" } }"#;

/// Scrubbed ambient credential variables so binary-driven runs stay hermetic
/// and offline regardless of the developer's environment.
const SCRUBBED_ENV: &[&str] = &[
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
];

/// Plausible prompt-history / credential locations seeded with the sentinel.
const CURATED_SENTINEL_FILES: &[&str] = &[
    ".local/share/opencode/opencode.db",
    ".local/share/opencode/tool-output/call-1.txt",
    ".local/share/opencode/auth.json",
    ".config/opencode/opencode.json",
    ".claude/projects/-Users-test/session.jsonl",
    ".claude/sessions/thread.jsonl",
    ".claude/.credentials.json",
    ".claude.json",
];

struct Env {
    workspace: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn setup() -> Env {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), WORKSPACE_CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    seed_fake_home(home.path());
    Env { workspace, home }
}

/// A synthetic agent home: plausible runtime artifacts, no real credentials.
fn seed_fake_home(home: &Path) {
    let credential = format!(r#"{{"token":"{SENTINEL}"}}"#);
    let session = format!(r#"{{"text":"{SENTINEL}"}}"#);
    for (rel, content) in [
        (
            ".config/opencode/opencode.json",
            r#"{"permission":{"bash":"deny"}}"#.to_string(),
        ),
        (".local/share/opencode/opencode.db", SENTINEL.to_string()),
        (
            ".local/share/opencode/tool-output/call-1.txt",
            SENTINEL.to_string(),
        ),
        (".local/share/opencode/auth.json", credential.clone()),
        (".claude/projects/-Users-test/session.jsonl", session),
        (".claude/sessions/thread.jsonl", SENTINEL.to_string()),
        (".claude/.credentials.json", credential),
        (".claude.json", "{}".to_string()),
    ] {
        let path = home.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }
}

fn pico_command(env: &Env, args: &[&str], with_home: bool) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    cmd.args(args).current_dir(env.workspace.path());
    if with_home {
        cmd.env("HOME", env.home.path());
    } else {
        cmd.env_remove("HOME");
    }
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd
}

fn run_pico(env: &Env, args: &[&str]) -> std::process::Output {
    pico_command(env, args, true).output().unwrap()
}

fn run_pico_no_home(env: &Env, args: &[&str]) -> std::process::Output {
    pico_command(env, args, false).output().unwrap()
}

fn assert_secret_free(label: &str, text: &str) {
    assert!(!text.contains(SENTINEL), "{label} leaked the sentinel");
}

/// A whole-tree digest: sorted relative paths + directory markers + file bytes.
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

fn assert_no_sidecars(root: &Path) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.ends_with("-wal") && !name.ends_with("-shm"),
                "unexpected SQLite sidecar created: {}",
                path.display()
            );
            if path.is_dir() {
                stack.push(path);
            }
        }
    }
}

// Validate the runtime payload against the checked-in schema's `runtime` def,
// failing closed for unknown validation keywords. This is the same schema
// subset the S033 producer contract uses, not a general JSON Schema engine.
fn valid(schema: &serde_json::Value, value: &serde_json::Value, root: &serde_json::Value) -> bool {
    for key in schema.as_object().unwrap().keys() {
        assert!(
            [
                "$schema",
                "title",
                "$defs",
                "$ref",
                "oneOf",
                "anyOf",
                "type",
                "properties",
                "required",
                "additionalProperties",
                "items",
                "const",
                "enum",
                "minimum"
            ]
            .contains(&key.as_str()),
            "unsupported schema keyword: {key}"
        );
    }
    if let Some(reference) = schema.get("$ref") {
        let pointer = reference.as_str().unwrap().strip_prefix('#').unwrap();
        return valid(root.pointer(pointer).unwrap(), value, root);
    }
    if let Some(branches) = schema.get("oneOf") {
        if branches
            .as_array()
            .unwrap()
            .iter()
            .filter(|branch| valid(branch, value, root))
            .count()
            != 1
        {
            return false;
        }
    }
    if let Some(branches) = schema.get("anyOf") {
        if !branches
            .as_array()
            .unwrap()
            .iter()
            .any(|branch| valid(branch, value, root))
        {
            return false;
        }
    }
    if let Some(expected) = schema.get("const") {
        if value != expected {
            return false;
        }
    }
    if let Some(expected) = schema.get("enum") {
        if !expected.as_array().unwrap().contains(value) {
            return false;
        }
    }
    if let Some(kind) = schema.get("type").and_then(serde_json::Value::as_str) {
        let ok = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "number" => value.is_number(),
            "integer" => value.is_i64() || value.is_u64(),
            "null" => value.is_null(),
            other => panic!("unsupported type {other}"),
        };
        if !ok {
            return false;
        }
    }
    if let Some(minimum) = schema.get("minimum") {
        if value
            .as_f64()
            .is_some_and(|v| v < minimum.as_f64().unwrap())
        {
            return false;
        }
    }
    if let Some(properties) = schema.get("properties") {
        let Some(object) = value.as_object() else {
            return false;
        };
        if schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| !object.contains_key(key.as_str().unwrap()))
        {
            return false;
        }
        for (key, value) in object {
            match properties.get(key) {
                Some(property) => {
                    if !valid(property, value, root) {
                        return false;
                    }
                }
                None if schema["additionalProperties"] == false => return false,
                None => {}
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if !value
            .as_array()
            .unwrap()
            .iter()
            .all(|item| valid(items, item, root))
        {
            return false;
        }
    }
    true
}

fn check_runtime(value: &serde_json::Value) {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../docs/public/output-v1.schema.json")).unwrap();
    let def = &schema["$defs"]["runtime"];
    assert!(
        valid(def, value, &schema),
        "runtime schema rejected {value}"
    );
}

#[test]
fn s039_runtime_help_documents_read_only_metadata_contract() {
    let env = setup();
    let out = run_pico(&env, &["runtime", "--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap().to_lowercase();
    for needle in [
        "read-only",
        "metadata",
        "database",
        "approval",
        "execution",
        "sidecar",
    ] {
        assert!(
            help.contains(needle),
            "runtime --help must document {needle:?}; got:\n{help}"
        );
    }
    assert_secret_free("runtime --help", &help);
}

#[test]
fn s039_runtime_human_lists_surfaces_distinctions_and_honesty_line() {
    let env = setup();
    let out = run_pico(&env, &["runtime"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.starts_with("Pico runtime survey\n"),
        "human output must carry the survey header; got:\n{text}"
    );
    assert!(text.contains("Surfaces (filesystem metadata only):"));
    assert!(text.contains("Distinctions:"));
    for line in [
        "configured capability: OBSERVABLE",
        "attempted use: AVAILABLE_UNREAD",
        "approved vs denied use: NOT_AVAILABLE",
        "completed consequential action: AVAILABLE_UNREAD",
    ] {
        assert!(
            text.contains(line),
            "missing frozen distinction line {line:?}; got:\n{text}"
        );
    }
    assert!(
        text.trim_end().ends_with(HONESTY),
        "human output must end with the exact honesty line; got:\n{text}"
    );
    assert_secret_free("runtime human output", &text);
}

#[test]
fn s039_missing_home_reports_explicit_levels_not_blank() {
    let env = setup();
    let out = run_pico_no_home(&env, &["runtime"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("UNKNOWN") || text.contains("NOT_AVAILABLE"),
        "missing HOME must be reported explicitly; got:\n{text}"
    );

    let json = run_pico_no_home(&env, &["runtime", "--json"]);
    assert!(json.status.success());
    check_runtime(&serde_json::from_slice(&json.stdout).unwrap());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let surfaces = value["surfaces"].as_array().unwrap();
    assert!(!surfaces.is_empty(), "survey must report surfaces");
    let levels: Vec<&str> = surfaces
        .iter()
        .map(|surface| surface["level"].as_str().unwrap())
        .collect();
    assert!(
        levels
            .iter()
            .any(|level| *level == "unknown" || *level == "not_available"),
        "missing HOME must yield explicit unknown/not_available levels; got {levels:?}"
    );
    assert_secret_free("runtime missing-home human", &text);
    assert_secret_free(
        "runtime missing-home json",
        &String::from_utf8_lossy(&json.stdout),
    );
}

#[test]
fn s039_json_matches_schema_and_is_deterministic() {
    let env = setup();
    let first = run_pico(&env, &["runtime", "--json"]);
    let second = run_pico(&env, &["runtime", "--json"]);
    assert!(first.status.success());
    assert!(
        first.stderr.is_empty(),
        "a clean JSON run must not write stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        first.stdout, second.stdout,
        "runtime --json must be byte-equal across runs"
    );

    let value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    check_runtime(&value);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "runtime");
    assert_eq!(value["status"], "ready");

    let surfaces = value["surfaces"].as_array().unwrap();
    let keys: Vec<(&str, &str)> = surfaces
        .iter()
        .map(|surface| {
            (
                surface["agent"].as_str().unwrap(),
                surface["label"].as_str().unwrap(),
            )
        })
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "surfaces must be ordered by agent then label");

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
        ]
    );
    assert_secret_free("runtime json", &String::from_utf8_lossy(&first.stdout));
}

#[test]
fn s039_runtime_is_read_only_and_creates_no_sidecars() {
    let env = setup();
    let home_before = tree_digest(env.home.path());
    let workspace_before = tree_digest(env.workspace.path());

    assert!(run_pico(&env, &["runtime"]).status.success());
    assert!(run_pico(&env, &["runtime", "--json"]).status.success());

    assert_eq!(
        tree_digest(env.home.path()),
        home_before,
        "runtime must not mutate the fake agent home"
    );
    assert_eq!(
        tree_digest(env.workspace.path()),
        workspace_before,
        "runtime must not mutate the workspace"
    );
    assert_no_sidecars(env.home.path());
    assert_no_sidecars(env.workspace.path());
}

#[test]
fn s039_sentinel_in_prompts_and_credentials_never_appears() {
    let env = setup();

    // Learn the reported surface paths from the tool, then overwrite every
    // present file surface under HOME with the sentinel so the sweep covers
    // exactly the artifacts this survey reports.
    let probe = run_pico(&env, &["runtime", "--json"]);
    assert!(probe.status.success());
    let base: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
    let mut seeded = 0usize;
    for surface in base["surfaces"].as_array().unwrap() {
        let Some(path) = surface["path"].as_str() else {
            continue;
        };
        let Some(rel) = path
            .strip_prefix("~/")
            .or_else(|| path.strip_prefix("$HOME/"))
        else {
            continue;
        };
        if surface["present"] != true || surface["bytes"].is_null() {
            continue;
        }
        let abs = env.home.path().join(rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&abs, SENTINEL).unwrap();
        seeded += 1;
    }
    // Curated prompt-history / credential files, independent of the reported
    // surface set.
    for rel in CURATED_SENTINEL_FILES {
        let abs = env.home.path().join(rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&abs, SENTINEL).unwrap();
    }
    assert!(
        seeded > 0,
        "survey reported no seedable present file surfaces; got: {base}"
    );

    for args in [vec!["runtime"], vec!["runtime", "--json"]] {
        let out = run_pico(&env, &args);
        assert!(out.status.success());
        assert_secret_free("runtime stdout", &String::from_utf8_lossy(&out.stdout));
        assert_secret_free("runtime stderr", &String::from_utf8_lossy(&out.stderr));
    }
}
