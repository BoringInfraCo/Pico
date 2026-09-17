//! Sprint 042 Finding-list observation-basis tests (SPRINT-042.md §2.1/§2.2).
//!
//! A golden-style production Finding is generated with the Sprint 009/010
//! controlled provider seam (no network, synthetic credentials). DIRECT
//! `opencode_runtime_observer` evidence is then linked to that Finding in a
//! temp-workspace store — never the founder store and never the real
//! `~/.local/share/opencode` — so the compiled `pico` binary can be driven
//! against it. This proves the list summary carries the same observation basis
//! as the detail, prints one line per entry, and prints nothing without it.

use std::fs;
use std::path::Path;
use std::process::Command;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{Evidence, EvidenceClass, RelationshipState, ScanStatus, Sensitivity};
use pico::persistence::{Database, EvidenceRepo, FindingEvidenceRecord, FindingRepo};
use tempfile::tempdir;

const SENTINEL: &str = "SENTINEL_S042";
const RUNTIME_SUBJECT: &str = "agent:opencode|can_execute|shell:bash";
const OBSERVED_LINE: &str = "Observed execution: can_execute via runtime evidence (FRESH)";
const ATTEMPTED_LINE: &str = "Attempted (not executed): can_execute via runtime evidence (FRESH)";

const WORKSPACE_CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }
    }
  }}
}"#;

/// Scrubbed ambient credential variables so the seeded scan stays hermetic and
/// offline regardless of the developer's environment.
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

fn scan_with_production_finding() -> (Env, ScanResult) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), WORKSPACE_CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();

    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace.path(),
        Some(home.path()),
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
    let provider = ProviderResult {
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
    };
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);
    (Env { workspace, home }, result)
}

fn open_rw(workspace: &Path) -> Database {
    Database::open_existing(&workspace.join(".pico").join("pico.db")).unwrap()
}

/// Link one DIRECT `opencode_runtime_observer` evidence item to the scan's only
/// Finding, matching the shape SPRINT-040 persists. Returns the evidence id.
fn inject_runtime_evidence(env: &Env, scan_id: &str, classification: &str) -> String {
    let list = FindingQueryService::list_latest(env.workspace.path()).unwrap();
    let finding_id = list.findings[0].id.clone();

    let db = open_rw(env.workspace.path());
    let mut evidence = Evidence::new(
        scan_id,
        EvidenceClass::Direct,
        "opencode_runtime_observer",
        "user:opencode_runtime_store",
        RUNTIME_SUBJECT,
        "OpenCode agent invoked Bash in this workspace (status: completed)",
        Sensitivity::Internal,
    )
    .unwrap();
    evidence.freshness = Some("FRESH".to_string());
    evidence.metadata = Some(serde_json::json!({ "classification": classification }));

    let evidence_repo = EvidenceRepo::new(db.connection());
    evidence_repo.insert(&evidence).unwrap();

    let finding_repo = FindingRepo::new(db.connection());
    let position = finding_repo.list_evidence(&finding_id).unwrap().len() as u32;
    finding_repo
        .insert_evidence(&FindingEvidenceRecord {
            finding_id,
            evidence_id: evidence.id.clone(),
            position,
            support_role: "SUPPORTING".to_string(),
        })
        .unwrap();
    evidence.id
}

fn run_pico(env: &Env, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    cmd.args(args)
        .current_dir(env.workspace.path())
        .env("HOME", env.home.path());
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd.output().unwrap()
}

fn stdout_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn observed_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.starts_with("Observed execution:"))
        .collect()
}

fn attempted_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.starts_with("Attempted (not executed):"))
        .collect()
}

/// A linked DIRECT runtime observation populates the summary with the same
/// basis as the detail, and `pico findings` prints exactly one line for it.
#[test]
fn s042_list_summary_and_binary_show_observed_execution() {
    let (env, scan) = scan_with_production_finding();
    inject_runtime_evidence(&env, &scan.scan_id, "observed_execution");

    let list = FindingQueryService::list_latest(env.workspace.path()).unwrap();
    let summary = &list.findings[0];
    assert_eq!(
        summary.observed_execution.len(),
        1,
        "the linked DIRECT runtime evidence must populate the summary"
    );
    let detail = FindingQueryService::get(env.workspace.path(), &summary.id).unwrap();
    assert_eq!(
        summary.observed_execution, detail.observed_execution,
        "list and detail must agree field-for-field for the same Finding"
    );
    assert_eq!(summary.observed_execution[0].basis, "OBSERVED_EXECUTION");
    assert_eq!(summary.observed_execution[0].freshness, "FRESH");
    assert_eq!(
        summary.observed_execution[0].relationship_key,
        RUNTIME_SUBJECT
    );

    let out = run_pico(&env, &["findings"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert_eq!(
        observed_lines(&stdout),
        vec![OBSERVED_LINE],
        "exactly one observed-execution line:\n{stdout}"
    );

    let detail_out = run_pico(&env, &["finding", &summary.id]);
    assert!(detail_out.status.success(), "{}", stderr_text(&detail_out));
    let detail_stdout = stdout_text(&detail_out);
    assert!(
        detail_stdout.contains(&format!("  {OBSERVED_LINE}\n")),
        "the detail section must contain the same sentence:\n{detail_stdout}"
    );
}

/// A Finding with no linked runtime evidence keeps an empty summary vec and no
/// marker line in `pico findings`.
#[test]
fn s042_list_omits_lines_without_runtime_evidence() {
    let (env, _scan) = scan_with_production_finding();

    let list = FindingQueryService::list_latest(env.workspace.path()).unwrap();
    assert!(
        list.findings[0].observed_execution.is_empty(),
        "no linked runtime evidence means an empty observation basis"
    );

    let out = run_pico(&env, &["findings"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(
        observed_lines(&stdout).is_empty(),
        "no observed line:\n{stdout}"
    );
    assert!(
        attempted_lines(&stdout).is_empty(),
        "no attempted line:\n{stdout}"
    );
    assert!(
        stdout.contains("Pico Findings"),
        "the list still renders:\n{stdout}"
    );
}

/// The list line label follows the persisted basis, never a hardcoded
/// `Observed execution` (the S041 bug class): an attempted-only observation
/// renders the attempt form and zero observed-execution lines.
#[test]
fn s042_list_label_follows_basis_for_an_attempt() {
    let (env, scan) = scan_with_production_finding();
    inject_runtime_evidence(&env, &scan.scan_id, "attempted_not_executed");

    let list = FindingQueryService::list_latest(env.workspace.path()).unwrap();
    assert_eq!(
        list.findings[0].observed_execution[0].basis,
        "ATTEMPTED_NOT_EXECUTED"
    );

    let out = run_pico(&env, &["findings"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let stdout = stdout_text(&out);
    assert!(
        observed_lines(&stdout).is_empty(),
        "must not claim execution:\n{stdout}"
    );
    assert_eq!(
        attempted_lines(&stdout),
        vec![ATTEMPTED_LINE],
        "the attempted form must render:\n{stdout}"
    );
}

/// Repeated binary renders over a fixed seeded store are byte-identical.
#[test]
fn s042_repeated_binary_list_renders_are_byte_identical() {
    let (env, scan) = scan_with_production_finding();
    inject_runtime_evidence(&env, &scan.scan_id, "observed_execution");

    let first = run_pico(&env, &["findings"]);
    assert!(first.status.success(), "{}", stderr_text(&first));
    let second = run_pico(&env, &["findings"]);
    assert!(second.status.success(), "{}", stderr_text(&second));
    assert_eq!(
        stdout_text(&first).as_bytes(),
        stdout_text(&second).as_bytes(),
        "the list render must be byte-identical across runs"
    );
}

/// Neither a synthetic secret sentinel nor a control byte carried by the
/// injected evidence leaks into the list output.
#[test]
fn s042_list_output_never_leaks_evidence_content() {
    let (env, scan) = scan_with_production_finding();

    let list = FindingQueryService::list_latest(env.workspace.path()).unwrap();
    let finding_id = list.findings[0].id.clone();
    {
        let db = open_rw(env.workspace.path());
        let mut evidence = Evidence::new(
            &scan.scan_id,
            EvidenceClass::Direct,
            "opencode_runtime_observer",
            SENTINEL,
            RUNTIME_SUBJECT,
            SENTINEL,
            Sensitivity::Internal,
        )
        .unwrap();
        evidence.freshness = Some("FRESH".to_string());
        evidence.metadata = Some(serde_json::json!({ "classification": "observed_execution" }));
        let evidence_repo = EvidenceRepo::new(db.connection());
        evidence_repo.insert(&evidence).unwrap();
        let finding_repo = FindingRepo::new(db.connection());
        let position = finding_repo.list_evidence(&finding_id).unwrap().len() as u32;
        finding_repo
            .insert_evidence(&FindingEvidenceRecord {
                finding_id,
                evidence_id: evidence.id,
                position,
                support_role: "SUPPORTING".to_string(),
            })
            .unwrap();
    }

    let out = run_pico(&env, &["findings"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let combined = format!("{}{}", stdout_text(&out), stderr_text(&out));
    assert!(
        !combined.contains(SENTINEL),
        "list output leaked {SENTINEL}"
    );
    assert!(
        !combined.contains('\u{1B}'),
        "list output leaked a control byte"
    );
}
