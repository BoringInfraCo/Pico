//! Sprint 020 MCP surfacing fixtures (R7 / R10).
//!
//! R7 asserts the `get_finding` tool JSON carries a per-agent
//! `agents` array (provider + effective_bash_capability + bash_boundary) for a
//! mixed OpenCode + Claude Code workspace, alongside the legacy
//! `effective_bash_capability` / `bash_boundary` fields. R10 asserts that across
//! the Claude postures the `get_finding` JSON never contains a synthetic
//! secret-shaped token value.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::mcp::handle_line;
use serde_json::{json, Value};
use tempfile::tempdir;

/// Synthetic fake Cloudflare token used only to prove it never reaches output.
const FAKE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";

const MIXED_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");
const MIXED_CLAUDE: &str = include_str!("../fixtures/mixed/.claude/settings.json");
const CLAUDE_ASK: &str = include_str!("../fixtures/claude/ask/settings.json");
const CLAUDE_DENY: &str = include_str!("../fixtures/claude/deny/settings.json");
const CLAUDE_SANDBOX: &str = include_str!("../fixtures/claude/sandbox/settings.json");
const CLAUDE_DISABLE_BASH: &str = include_str!("../fixtures/claude/disable-bash/settings.json");

const GET_CALL: &str = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_finding","arguments":{"id":"PLACEHOLDER"}}}"#;

fn write_claude(workspace: &std::path::Path, contents: &str) {
    let dir = workspace.join(".claude");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("settings.json"), contents).unwrap();
}

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

fn get_finding_payload(workspace: &std::path::Path) -> Value {
    let list = FindingQueryService::list_latest(workspace).unwrap();
    let finding_id = list.findings[0].id.clone();
    let call = GET_CALL.replace("PLACEHOLDER", &finding_id);
    let frame = handle_line(&call, workspace).expect("get_finding frame");
    let frame: Value = serde_json::from_str(&frame).expect("frame is JSON");
    let inner = frame["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    serde_json::from_str(inner).expect("tool payload JSON")
}

fn agents_by_provider(detail: &Value) -> std::collections::BTreeMap<String, Value> {
    let mut map = std::collections::BTreeMap::new();
    for agent in detail["paths"][0]["agents"]
        .as_array()
        .expect("agents must be an array")
    {
        map.insert(
            agent["provider"].as_str().unwrap().to_string(),
            agent.clone(),
        );
    }
    map
}

/// R7: the `get_finding` JSON for the mixed fixture carries one per-agent entry
/// for each of opencode and claude, with provider + effective_bash_capability +
/// bash_boundary, while the legacy single-agent fields stay present.
#[test]
fn mcp_get_finding_includes_per_agent_bash_for_mixed_workspace() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), MIXED_CLAUDE);
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);
    assert_eq!(result.agent_count, 2);

    let detail = get_finding_payload(workspace.path());
    let agents = agents_by_provider(&detail);
    assert_eq!(
        agents.len(),
        2,
        "both agents must be surfaced: {:?}",
        agents.keys().collect::<Vec<_>>()
    );

    assert_eq!(
        agents["opencode"],
        json!({
            "provider": "opencode",
            "effective_bash_capability": "AUTO_ALLOW",
            "bash_boundary": null,
        }),
        "opencode per-agent entry"
    );
    assert_eq!(
        agents["claude"],
        json!({
            "provider": "claude",
            "effective_bash_capability": "AUTO_ALLOW",
            "bash_boundary": null,
        }),
        "claude per-agent entry resolves to the mixed fixture's allow posture"
    );

    // Legacy single-agent fields remain for backward compatibility.
    assert_eq!(
        detail["paths"][0]["effective_bash_capability"],
        json!("AUTO_ALLOW")
    );
    assert_eq!(detail["paths"][0]["bash_boundary"], Value::Null);
}

/// R7: an approval-gated Claude posture surfaces its own boundary in the
/// per-agent JSON, distinct from the opencode AUTO_ALLOW entry.
#[test]
fn mcp_get_finding_surfaces_approval_gated_claude_boundary() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), MIXED_OPENCODE);
    write_claude(workspace.path(), CLAUDE_ASK);
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);

    let detail = get_finding_payload(workspace.path());
    let agents = agents_by_provider(&detail);
    assert_eq!(
        agents["opencode"]["effective_bash_capability"],
        json!("AUTO_ALLOW")
    );
    assert_eq!(
        agents["claude"],
        json!({
            "provider": "claude",
            "effective_bash_capability": "APPROVAL_GATED",
            "bash_boundary": "MANDATORY_APPROVAL",
        }),
        "approval-gated claude entry must carry its interrupting boundary"
    );
}

/// R7 (golden): the OpenCode-only golden path emits exactly one per-agent entry
/// (opencode) and keeps the legacy fields.
#[test]
fn mcp_get_finding_golden_path_has_single_opencode_agent() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    setup_with(workspace.path(), &opencode_config(FAKE_TOKEN));
    let result = scan(workspace.path(), home.path());
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);
    assert_eq!(result.agent_count, 1);

    let detail = get_finding_payload(workspace.path());
    let agents = agents_by_provider(&detail);
    assert_eq!(agents.len(), 1, "golden path surfaces only opencode");
    assert_eq!(
        agents["opencode"],
        json!({
            "provider": "opencode",
            "effective_bash_capability": "AUTO_ALLOW",
            "bash_boundary": null,
        })
    );
    assert_eq!(
        detail["paths"][0]["effective_bash_capability"],
        json!("AUTO_ALLOW")
    );
    assert_eq!(detail["paths"][0]["bash_boundary"], Value::Null);
}

/// R10: across the Claude postures allow / ask / deny / sandbox / disable-bash
/// in a mixed environment, the `get_finding` JSON never contains the synthetic
/// token value.
#[test]
fn mcp_secret_sweep_never_leaks_fake_token_across_claude_postures() {
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

        let payload = get_finding_payload(workspace.path());
        let serialized = serde_json::to_string(&payload).expect("serializable");
        assert!(
            !serialized.contains(FAKE_TOKEN),
            "posture {name} get_finding JSON leaked the fake token:\n{serialized}"
        );
        for agent in payload["paths"][0]["agents"]
            .as_array()
            .expect("agents must be an array")
        {
            let entry = serde_json::to_string(agent).expect("serializable");
            assert!(
                !entry.contains(FAKE_TOKEN),
                "posture {name} per-agent entry leaked the token: {entry}"
            );
        }
    }
}
