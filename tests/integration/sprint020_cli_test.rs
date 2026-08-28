//! Sprint 020 CLI surfacing fixtures (R6 / R10).
//!
//! R6 asserts the explained finding view surfaces the Bash effective state PER
//! AGENT: a mixed OpenCode + Claude Code workspace renders one
//! `Agent <provider> effective Bash: <state>; boundary: <kind>` line per
//! `agent:<provider>|can_execute|shell:bash` edge, while the OpenCode-only golden
//! path keeps its legacy single-agent `Effective Bash capability:` line
//! byte-identical. R10 asserts that across the Claude postures
//! (allow / ask / deny / sandbox / disable-bash) the rendered CLI output and the
//! persisted metadata never contain a synthetic secret-shaped token value.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::cli::render::render_finding_detail;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::persistence::Database;
use tempfile::tempdir;

/// Synthetic fake Cloudflare token used only to prove it never reaches output.
const FAKE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";
const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";

const MIXED_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");
const MIXED_CLAUDE: &str = include_str!("../fixtures/mixed/.claude/settings.json");
const CLAUDE_ASK: &str = include_str!("../fixtures/claude/ask/settings.json");
const CLAUDE_DENY: &str = include_str!("../fixtures/claude/deny/settings.json");
const CLAUDE_SANDBOX: &str = include_str!("../fixtures/claude/sandbox/settings.json");
const CLAUDE_DISABLE_BASH: &str = include_str!("../fixtures/claude/disable-bash/settings.json");

fn write_claude(workspace: &std::path::Path, contents: &str) {
    let dir = workspace.join(".claude");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("settings.json"), contents).unwrap();
}

/// Golden-style OpenCode config: bash allow + official GitHub MCP server. The
/// synthetic token appears ONLY in the MCP environment; it must never be
/// rendered, serialized, or persisted.
fn opencode_config(token: &str) -> String {
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "allow" }}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{token}" }} }} }} }} }}"#
    )
}

fn setup_with(workspace: &std::path::Path, config: &str) {
    fs::write(workspace.join("opencode.json"), config).unwrap();
    InitService::run(workspace).unwrap();
}

fn provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_TOKEN)];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    };
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: discovered.credentials[0].fingerprint.clone(),
        credential_status: Some(CredentialStatus::Active),
        accounts: vec![ObservedAccount {
            account_id: "account-1234567890123456".to_string(),
            name: Some("Synthetic Account".to_string()),
            account_type: Some("standard".to_string()),
            scope: ScopeState::InScope,
            source_locator: "/accounts".to_string(),
        }],
        workers: vec![worker],
        authorities: vec![AuthorityObservation {
            account_id: "account-1234567890123456".to_string(),
            worker_key,
            state: RelationshipState::Derived,
            resolution: AuthorityResolution::Exact,
            permission_state: "WORKERS_SCRIPTS_WRITE".to_string(),
            scope_state: ScopeState::InScope,
            unknown_reasons: Vec::new(),
            granted_permissions: Vec::new(),
            zone_scoped: false,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan(workspace: &std::path::Path, home: &std::path::Path) -> ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_TOKEN)];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace, home)),
    )
    .unwrap()
}

fn rendered_finding(workspace: &std::path::Path) -> String {
    let list = FindingQueryService::list_latest(workspace).unwrap();
    let detail = FindingQueryService::get(workspace, &list.findings[0].id).unwrap();
    render_finding_detail(&detail)
}

/// R6 (mixed): a scan over `tests/fixtures/mixed/` (OpenCode + Claude Code)
/// renders ONE per-agent effective Bash line for EACH agent, with the exact
/// effective state each fixture resolves (both are AUTO_ALLOW).
#[test]
fn cli_explain_surfaces_bash_effective_state_per_agent_for_mixed_workspace() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), MIXED_CLAUDE);
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(
        result.finding_count, 1,
        "mixed environment must still yield exactly 1 finding"
    );
    assert_eq!(result.agent_count, 2);

    let rendered = rendered_finding(workspace.path());
    assert!(
        rendered.contains("Agent opencode effective Bash: AUTO_ALLOW; boundary: none"),
        "expected the opencode per-agent line in:\n{rendered}"
    );
    assert!(
        rendered.contains("Agent claude effective Bash: AUTO_ALLOW; boundary: none"),
        "expected the claude per-agent line in:\n{rendered}"
    );
}

/// R6 (mixed, differentiated): a mixed workspace whose Claude Code settings
/// resolve to approval-gated (ask) surfaces the claude line with its own
/// interrupting boundary, distinct from the opencode line.
#[test]
fn cli_explain_surfaces_approval_gated_claude_boundary() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), CLAUDE_ASK);
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);

    let rendered = rendered_finding(workspace.path());
    assert!(
        rendered.contains("Agent opencode effective Bash: AUTO_ALLOW; boundary: none"),
        "expected the opencode per-agent line in:\n{rendered}"
    );
    assert!(
        rendered
            .contains("Agent claude effective Bash: APPROVAL_GATED; boundary: MANDATORY_APPROVAL"),
        "expected the approval-gated claude per-agent line in:\n{rendered}"
    );
}

/// R6 (golden): the OpenCode-only golden path still renders the legacy
/// single-agent `Effective Bash capability:` line, byte-identical to S016, and
/// never renders the per-agent block.
#[test]
fn cli_explain_golden_path_keeps_single_opencode_line() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), &opencode_config(FAKE_TOKEN));
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);
    assert_eq!(result.agent_count, 1);

    let rendered = rendered_finding(workspace.path());
    assert!(
        rendered.contains("Effective Bash capability: AUTO_ALLOW"),
        "golden path must keep the legacy single-agent line in:\n{rendered}"
    );
    assert!(
        rendered.contains("Bash interrupting boundary: none"),
        "golden path must keep the legacy boundary line in:\n{rendered}"
    );
    assert!(
        !rendered.contains("Agent opencode effective Bash:"),
        "single-agent golden path must not render the per-agent block in:\n{rendered}"
    );
}

/// R10: across the Claude postures allow / ask / deny / sandbox / disable-bash
/// in a mixed environment, neither the rendered CLI explain nor the persisted
/// relationship/resource/evidence metadata ever contains the synthetic token
/// value.
#[test]
fn secret_sweep_never_leaks_fake_token_across_claude_postures() {
    for (name, claude_fixture) in [
        ("allow", MIXED_CLAUDE),
        ("ask", CLAUDE_ASK),
        ("deny", CLAUDE_DENY),
        ("sandbox", CLAUDE_SANDBOX),
        ("disable-bash", CLAUDE_DISABLE_BASH),
    ] {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        setup_with(workspace.path(), &opencode_config(FAKE_TOKEN));
        write_claude(workspace.path(), claude_fixture);
        let result = scan(workspace.path(), home.path());
        assert_eq!(result.status, ScanStatus::Complete, "posture {name}");
        assert_eq!(
            result.finding_count, 1,
            "mixed env must still yield exactly 1 finding for posture {name}"
        );

        let db = Database::open_existing(&workspace.path().join(".pico").join("pico.db")).unwrap();
        let locators: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(source_locator), '') FROM evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata_dump: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM relationships",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let resource_dump: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM resources",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let observation_dump: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(observation), '') FROM evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(db);

        assert!(
            !locators.contains(FAKE_TOKEN),
            "posture {name} locator leak"
        );
        assert!(
            !locators.contains(SECRET_SENTINEL),
            "posture {name} locator leaked the config sentinel"
        );
        assert!(
            !metadata_dump.contains(FAKE_TOKEN),
            "posture {name} relationship metadata leak"
        );
        assert!(
            !resource_dump.contains(FAKE_TOKEN),
            "posture {name} resource metadata leak"
        );
        assert!(
            !observation_dump.contains(FAKE_TOKEN),
            "posture {name} evidence observation leak"
        );

        let rendered = rendered_finding(workspace.path());
        assert!(
            !rendered.contains(FAKE_TOKEN),
            "posture {name} rendered explain leaked the fake token in:\n{rendered}"
        );
        assert!(
            !rendered.contains(SECRET_SENTINEL),
            "posture {name} rendered explain leaked the config sentinel in:\n{rendered}"
        );
        for line in rendered.lines() {
            if line.starts_with("Agent ") {
                assert!(
                    !line.contains(FAKE_TOKEN),
                    "posture {name} per-agent line leaked the token: {line}"
                );
            }
        }
    }
}
