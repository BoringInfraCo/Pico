//! Sprint 020 Claude Code adapter fixtures (R4, R5, R8).
//!
//! R4 asserts provider-aware relationship keys: the OpenCode actor keeps its
//! golden `agent:opencode|can_execute|shell:bash` edge while the Claude Code
//! actor gets its own `agent:claude|can_execute|shell:bash` edge. R5 asserts a
//! mixed OpenCode + Claude Code workspace coexists without key collision,
//! duplicated findings, or cross-agent leakage (exactly one finding remains).
//! R8 is a broad sanitized battery: Bash precedence modes, disableBash,
//! defaultMode, sandbox, MCP local/remote transport, disabled server, mixed
//! environments, and provider-failure partiality.

use std::fs;

use pico::application::{InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::persistence::Database;
use tempfile::tempdir;

const MIXED_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");
const MIXED_CLAUDE: &str = include_str!("../fixtures/mixed/.claude/settings.json");
const CLAUDE_ALLOW: &str = include_str!("../fixtures/claude/allow/settings.json");
const CLAUDE_ASK: &str = include_str!("../fixtures/claude/ask/settings.json");
const CLAUDE_DENY: &str = include_str!("../fixtures/claude/deny/settings.json");
const CLAUDE_DISABLE_BASH: &str = include_str!("../fixtures/claude/disable-bash/settings.json");
const CLAUDE_SANDBOX: &str = include_str!("../fixtures/claude/sandbox/settings.json");
const CLAUDE_DEFAULT_MODE: &str = include_str!("../fixtures/claude/default-mode/settings.json");
const CLAUDE_MALFORMED: &str = include_str!("../fixtures/claude/malformed/settings.json");
const CLAUDE_MCP: &str = include_str!("../fixtures/claude/mcp/.mcp.json");
const CLAUDE_DISABLED: &str = include_str!("../fixtures/claude/disabled/.claude/settings.json");

fn write_claude(workspace: &std::path::Path, contents: &str) {
    let dir = workspace.join(".claude");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("settings.json"), contents).unwrap();
}

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

fn discover_fingerprint(workspace: &std::path::Path, home: &std::path::Path) -> String {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap()
    .credentials[0]
        .fingerprint
        .clone()
}

fn production_worker() -> ObservedWorker {
    ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    }
}

fn valid_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let worker = production_worker();
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: discover_fingerprint(workspace, home),
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

fn run(
    workspace: &std::path::Path,
    home: &std::path::Path,
    provider: Option<ProviderResult>,
) -> ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        provider,
    )
    .unwrap()
}

fn relationship_state(workspace: &std::path::Path, key: &str) -> String {
    let db = Database::open(&workspace.join(".pico/pico.db")).unwrap();
    db.connection()
        .query_row(
            "SELECT state FROM relationships WHERE canonical_key = ?1",
            [key],
            |row| row.get(0),
        )
        .unwrap()
}

fn count_relationships(workspace: &std::path::Path, key: &str) -> i64 {
    let db = Database::open(&workspace.join(".pico/pico.db")).unwrap();
    db.connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = ?1",
            [key],
            |row| row.get(0),
        )
        .unwrap()
}

/// R4: provider-aware relationship keys — each actor owns its own
/// `agent:<provider>|can_execute|shell:bash` edge with no collision.
#[test]
fn provider_aware_relationship_keys() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), r#"{"permission":{"bash":"allow"}}"#);
    write_claude(workspace.path(), CLAUDE_ALLOW);
    InitService::run(workspace.path()).unwrap();

    let result = run(workspace.path(), home.path(), None);
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 2);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let conn = db.connection();
    let opencode_agent: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE canonical_key = 'agent:opencode'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let claude_agent: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE canonical_key = 'agent:claude'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((opencode_agent, claude_agent), (1, 1));

    assert_eq!(
        relationship_state(workspace.path(), "agent:opencode|can_execute|shell:bash"),
        "DERIVED"
    );
    assert_eq!(
        relationship_state(workspace.path(), "agent:claude|can_execute|shell:bash"),
        "DERIVED"
    );
    // No key collision: exactly one relationship per agent edge.
    assert_eq!(
        count_relationships(workspace.path(), "agent:opencode|can_execute|shell:bash"),
        1
    );
    assert_eq!(
        count_relationships(workspace.path(), "agent:claude|can_execute|shell:bash"),
        1
    );
}

/// R5: a mixed OpenCode + Claude Code workspace coexists without key collision,
/// duplicated findings, or cross-agent evidence leakage — exactly one finding
/// remains (the OpenCode golden path).
#[test]
fn mixed_environment_open_code_plus_claude() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), MIXED_CLAUDE);
    InitService::run(workspace.path()).unwrap();

    let result = run(
        workspace.path(),
        home.path(),
        Some(valid_provider(workspace.path(), home.path())),
    );
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 2);
    assert_eq!(
        result.finding_count, 1,
        "the mixed environment must still yield exactly 1 finding"
    );
    assert!(result.github_mcp_observed);
    assert_eq!(result.bash_permission.as_deref(), Some("ALLOW"));

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let conn = db.connection();
    // Both actors and both can_execute edges coexist.
    let opencode_execute: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = 'agent:opencode|can_execute|shell:bash'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let claude_execute: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = 'agent:claude|can_execute|shell:bash'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((opencode_execute, claude_execute), (1, 1));

    // The GitHub MCP configured_with edge is attributed only to the actor that
    // declared it (OpenCode). Claude Code never leaks into the GitHub surface.
    let opencode_configured: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = 'agent:opencode|configured_with|mcp:github:official'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let claude_configured: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = 'agent:claude|configured_with|mcp:github:official'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((opencode_configured, claude_configured), (1, 0));

    // Exactly one finding row is persisted.
    let findings: i64 = conn
        .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(findings, 1);

    // Both discovered providers are reachable in the diagnostics surface.
    let detail = result.diagnostics_detail.expect("diagnostics populated");
    let names: Vec<&str> = detail
        .provider_statuses
        .iter()
        .map(|provider| provider.name.as_str())
        .collect();
    assert!(names.contains(&"opencode"));
    assert!(names.contains(&"claude"));
    assert!(detail
        .provider_statuses
        .iter()
        .all(|provider| provider.reachable));
}

/// R8: broad sanitized battery covering precedence, modes, sandbox, MCP
/// transport, disabled servers, mixed environments, and provider failure.
#[test]
fn r8_battery_claude_precedence_modes_sandbox_transport_disabled_mixed_failure() {
    // (a) Bash precedence modes and relationship states (claude-only workspaces).
    for (fixture, expected_permission, expected_state) in [
        (CLAUDE_ALLOW, "ALLOW", "DERIVED"),
        (CLAUDE_ASK, "ASK", "UNKNOWN"),
        (CLAUDE_DENY, "DENY", "BLOCKED"),
        (CLAUDE_DISABLE_BASH, "DENY", "BLOCKED"),
    ] {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_claude(workspace.path(), fixture);
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.status, ScanStatus::Complete, "fixture {fixture:?}");
        assert_eq!(result.agent_count, 1);
        assert_eq!(result.bash_permission.as_deref(), Some(expected_permission));
        assert_eq!(
            relationship_state(workspace.path(), "agent:claude|can_execute|shell:bash"),
            expected_state
        );
    }

    // (b) defaultMode alone never fabricates AUTO_ALLOW: the claude Bash edge
    // stays approval-gated (UNKNOWN state, ASK permission).
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_claude(workspace.path(), CLAUDE_DEFAULT_MODE);
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.bash_permission.as_deref(), Some("ASK"));
        assert_eq!(
            relationship_state(workspace.path(), "agent:claude|can_execute|shell:bash"),
            "UNKNOWN"
        );
    }

    // (c) sandbox => SANDBOX boundary metadata on the claude can_execute edge.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_claude(workspace.path(), CLAUDE_SANDBOX);
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.status, ScanStatus::Complete);
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let (state, metadata): (String, String) = db
            .connection()
            .query_row(
                "SELECT state, metadata FROM relationships WHERE canonical_key = 'agent:claude|can_execute|shell:bash'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "DERIVED");
        assert!(metadata.contains("\"effective_state\":\"SANDBOXED\""));
        assert!(metadata.contains("\"boundary_kind\":\"SANDBOX\""));
    }

    // (d) MCP transport: a Claude `.mcp.json` with local stdio + remote http
    // GitHub servers is normalized and classified, with both transports kept.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        fs::write(workspace.path().join(".mcp.json"), CLAUDE_MCP).unwrap();
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.status, ScanStatus::Complete);
        assert!(result.github_mcp_observed);
        assert_eq!(result.agent_count, 1);
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let conn = db.connection();
        let stdio_server: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM resources WHERE canonical_key = 'mcp:github:official'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stdio_server, 1);
        // OpenCode never leaks into this claude-only workspace.
        let opencode_edges: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM relationships WHERE canonical_key LIKE 'agent:opencode|%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(opencode_edges, 0);
    }

    // (e) Disabled official server: observed but no influence edges.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_claude(workspace.path(), CLAUDE_DISABLED);
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.status, ScanStatus::Complete);
        assert!(result.github_mcp_observed);
        assert_eq!(result.influence_strength, None);
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let can_call: i64 = db
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM relationships WHERE kind = 'can_call'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(can_call, 0);
    }

    // (f) Mixed environment (OpenCode + Claude Code) coexists without
    // duplication — exactly one finding remains.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), MIXED_OPENCODE);
        write_claude(workspace.path(), MIXED_CLAUDE);
        InitService::run(workspace.path()).unwrap();
        let result = run(
            workspace.path(),
            home.path(),
            Some(valid_provider(workspace.path(), home.path())),
        );
        assert_eq!(result.finding_count, 1);
        assert_eq!(result.agent_count, 2);
    }

    // (g) Provider failure: a malformed Claude settings file makes the scan
    // PARTIAL with the claude provider named in the diagnostics, and no actor
    // is persisted.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_claude(workspace.path(), CLAUDE_MALFORMED);
        InitService::run(workspace.path()).unwrap();
        let result = run(workspace.path(), home.path(), None);
        assert_eq!(result.status, ScanStatus::Partial);
        assert_eq!(result.agent_count, 0);
        let detail = result.diagnostics_detail.expect("diagnostics populated");
        assert_eq!(detail.scan_status, "PARTIAL");
        assert_eq!(detail.partial_reason.as_deref(), Some("claude"));
        let claude = detail
            .provider_statuses
            .iter()
            .find(|provider| provider.name == "claude")
            .expect("claude provider status present");
        assert!(!claude.reachable);
        assert!(
            claude
                .problems
                .iter()
                .any(|problem| problem.starts_with("project:.claude/settings.json")),
            "claude problem carries its source locator: {:?}",
            claude.problems
        );
    }
}
