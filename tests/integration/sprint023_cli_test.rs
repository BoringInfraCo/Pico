//! Sprint 023 CLI scan-summary fixtures (R1–R4, R6, R7 / F-U1).
//!
//! Mixed-agent workspaces must list every agent's effective Bash posture in
//! the `pico scan` summary. The single-agent OpenCode golden path keeps the
//! legacy `Effective Bash: ALLOW` line byte-for-byte. F-U1 is the mixed
//! zero-finding case: both postures must be visible without requiring a
//! Finding. R5 (MCP scan-summary tool) is N/A and is not tested here.

use std::fs;

use pico::application::{InitService, ScanResult, ScanService};
use pico::cli::render::render_scan_effective_bash;
use pico::discovery::EnvironmentReachability;
use pico::domain::ScanStatus;
use tempfile::tempdir;

const OPENCODE_ALLOW: &str = include_str!("../fixtures/opencode/allow/opencode.json");
const MIXED_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");
const CLAUDE_ASK: &str = include_str!("../fixtures/claude/ask/settings.json");

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const CLOUDFLARE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";
const GITHUB_TOKEN: &str = "ghp_TESTFAKE0000000000000000000000000000";

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

fn write_claude(workspace: &std::path::Path, contents: &str) {
    let dir = workspace.join(".claude");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("settings.json"), contents).unwrap();
}

fn setup_mixed_allow_ask() -> (tempfile::TempDir, tempfile::TempDir) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), OPENCODE_ALLOW);
    write_claude(workspace.path(), CLAUDE_ASK);
    InitService::run(workspace.path()).unwrap();
    (workspace, home)
}

fn scan(workspace: &std::path::Path, home: &std::path::Path) -> ScanResult {
    ScanService::run_with_home(workspace, Some(home)).unwrap()
}

fn summary(result: &ScanResult) -> String {
    render_scan_effective_bash(result)
}

/// R1: ScanResult carries per-agent Bash postures from every discovered
/// capability, not just the first. Primary `bash_permission` stays ALLOW.
#[test]
fn scan_result_carries_per_agent_bash_postures() {
    let (workspace, home) = setup_mixed_allow_ask();
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 2);
    assert_eq!(result.finding_count, 0);
    assert_eq!(result.agent_bash_postures.len(), 2);
    assert_eq!(result.bash_permission.as_deref(), Some("ALLOW"));

    let postures: Vec<(&str, &str)> = result
        .agent_bash_postures
        .iter()
        .map(|posture| (posture.provider.as_str(), posture.effective_state.as_str()))
        .collect();
    assert!(
        postures.contains(&("opencode", "AUTO_ALLOW")),
        "expected opencode AUTO_ALLOW in {postures:?}"
    );
    assert!(
        postures.contains(&("claude", "APPROVAL_GATED")),
        "expected claude APPROVAL_GATED in {postures:?}"
    );
}

/// R2: mixed-agent scan summary lists every agent's effective Bash state
/// and does not emit the single-agent `Effective Bash: ALLOW` line.
#[test]
fn mixed_agent_summary_lists_every_agent_bash_posture() {
    let (workspace, home) = setup_mixed_allow_ask();
    let result = scan(workspace.path(), home.path());
    let rendered = summary(&result);
    assert_eq!(
        rendered,
        "Effective Bash:\n  opencode: AUTO_ALLOW\n  claude: APPROVAL_GATED\n"
    );
}

/// R3: single-agent OpenCode keeps the legacy `Effective Bash: ALLOW` line
/// byte-for-byte and does not render a per-agent `opencode:` line.
#[test]
fn single_agent_opencode_summary_keeps_legacy_effective_bash_line() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), OPENCODE_ALLOW);
    InitService::run(workspace.path()).unwrap();
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 1);
    let rendered = summary(&result);
    assert_eq!(rendered, "Effective Bash: ALLOW\n");
    assert!(
        !rendered.contains("opencode:"),
        "single-agent summary must not list a per-agent line:\n{rendered}"
    );
}

/// R4 / F-U1: mixed-agent zero-finding scan still shows both Bash postures.
#[test]
fn mixed_agent_zero_finding_summary_shows_both_bash_postures() {
    let (workspace, home) = setup_mixed_allow_ask();
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.finding_count, 0);
    assert_eq!(result.agent_count, 2);
    assert_eq!(
        summary(&result),
        "Effective Bash:\n  opencode: AUTO_ALLOW\n  claude: APPROVAL_GATED\n"
    );
}

/// Mixed workspace with a Claude actor but no Claude Bash capability must
/// still use the per-agent block so the primary `Effective Bash: ALLOW` line
/// cannot conceal that a second agent was detected.
#[test]
fn mixed_agents_with_one_bash_capability_use_per_agent_block() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), OPENCODE_ALLOW);
    fs::write(
        workspace.path().join(".mcp.json"),
        r#"{"mcpServers":{"github":{"type":"stdio","command":"npx"}}}"#,
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.agent_count, 2);
    assert_eq!(result.agent_bash_postures.len(), 1);
    assert_eq!(result.bash_permission.as_deref(), Some("ALLOW"));
    let rendered = summary(&result);
    assert_eq!(rendered, "Effective Bash:\n  opencode: AUTO_ALLOW\n");
    assert!(
        !rendered.starts_with("Effective Bash: ALLOW"),
        "mixed-agent summary must not collapse to the primary permission line:\n{rendered}"
    );
}

/// R6: identical mixed-agent scans produce identical per-agent postures
/// and identical rendered summaries.
#[test]
fn per_agent_postures_stable_across_identical_scans() {
    let (workspace, home) = setup_mixed_allow_ask();
    let first = scan(workspace.path(), home.path());
    let second = scan(workspace.path(), home.path());
    assert_eq!(first.agent_bash_postures, second.agent_bash_postures);
    assert_eq!(summary(&first), summary(&second));
}

/// R7: synthetic tokens never appear in the scan-summary Effective Bash
/// block, posture Debug output, or bash_permission.
#[test]
fn secret_sweep_never_leaks_token_in_summary() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), CLAUDE_ASK);
    InitService::run(workspace.path()).unwrap();
    let environment = [
        ("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN),
        ("GITHUB_TOKEN", GITHUB_TOKEN),
    ];
    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Unknown,
    )
    .unwrap();

    let rendered = summary(&result);
    let postures_debug = format!("{:?}", result.agent_bash_postures);
    let permission = result.bash_permission.clone().unwrap_or_default();
    for haystack in [&rendered, &postures_debug, &permission] {
        assert!(
            !haystack.contains(SECRET_SENTINEL),
            "summary leaked the config sentinel in:\n{haystack}"
        );
        assert!(
            !haystack.contains(CLOUDFLARE_TOKEN),
            "summary leaked the Cloudflare token in:\n{haystack}"
        );
        assert!(
            !haystack.contains(GITHUB_TOKEN),
            "summary leaked the GitHub token in:\n{haystack}"
        );
        assert!(
            !haystack.contains("cfut_TESTFAKE"),
            "summary leaked a Cloudflare token prefix in:\n{haystack}"
        );
        assert!(
            !haystack.contains("ghp_TESTFAKE"),
            "summary leaked a GitHub token prefix in:\n{haystack}"
        );
    }
}
