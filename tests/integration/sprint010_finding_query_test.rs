//! Sprint 010 Finding query and explanation fixtures.
//!
//! These fixtures reuse the Sprint 009 controlled provider seam so that no
//! network, credential, or provider call is involved. Query commands are
//! asserted to be read-only and deterministic over the persisted state.

use std::fs;

use pico::application::{
    finding_navigation_ids, Currentness, FindingQueryService, Freshness, InitService, ScanResult,
    ScanService,
};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::findings::{
    Confidence, Finding, FindingClass, FindingGenerationStatus, FindingResult, FindingStatus,
    Remediation, Severity,
};
use pico::persistence::{Database, ResourceRepo, ScanRepo};
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const AUTH_HEADER_SENTINEL: &str = "TEST_AUTH_HEADER_SHOULD_NOT_APPEAR";
const CONFIG: &str = r#"{
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

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    sink_impact: Option<&str>,
    script_name: &str,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: script_name.to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: sink_impact.map(str::to_string),
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

fn scan_with_classification(
    classification: Option<&str>,
    script_name: &str,
) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            classification,
            script_name,
        )),
    )
    .unwrap();
    (workspace, result)
}

fn open_rw(workspace: &std::path::Path) -> Database {
    Database::open_existing(&workspace.join(".pico").join("pico.db")).unwrap()
}

fn golden_detail_parts(
    workspace: &std::path::Path,
) -> (
    pico::application::FindingList,
    pico::application::FindingDetail,
) {
    let list = FindingQueryService::list_latest(workspace).unwrap();
    let finding_id = list.findings[0].id.clone();
    let detail = FindingQueryService::get(workspace, &finding_id).unwrap();
    (list, detail)
}

#[test]
fn golden_list_selects_complete_scan_and_summary_counts() {
    let (workspace, scan) = scan_with_classification(Some("PRODUCTION"), "checkout");
    assert_eq!(scan.status, ScanStatus::Complete);
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let selected = list.selected_scan.as_ref().expect("selected scan");
    assert_eq!(selected.id, scan.scan_id);
    assert_eq!(selected.status, "COMPLETE");
    assert!(selected.completed_at.is_some());
    assert_eq!(list.newest_scan_attempt.as_ref().unwrap().id, scan.scan_id);
    assert_eq!(list.freshness, Freshness::LatestComplete);
    assert!(list.freshness_warning.is_none());
    assert_eq!(list.findings.len(), 1);
    let summary = &list.findings[0];
    assert_eq!(summary.finding_class, "UNTRUSTED_TO_PRODUCTION");
    assert_eq!(summary.severity, "CRITICAL");
    assert_eq!(summary.confidence, "HIGH");
    assert_eq!(summary.status, "OPEN");
    assert_eq!(summary.attack_path_count, 1);
    assert_eq!(summary.affected_sink_count, 1);
    assert!(!summary.fingerprint.is_empty());
    let serialized = serde_json::to_string(&list).unwrap();
    assert!(!serialized.contains(SECRET_SENTINEL));
}

#[test]
fn golden_detail_renders_traversal_aware_connected_path() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let (_, detail) = golden_detail_parts(workspace.path());
    assert_eq!(detail.currentness, Currentness::LatestComplete);
    assert!(detail.freshness_warning.is_none());
    assert_eq!(detail.finding_version, 1);
    assert_eq!(detail.severity, "CRITICAL");
    assert_eq!(detail.confidence, "HIGH");

    assert_eq!(detail.paths.len(), 1);
    let path = &detail.paths[0];
    assert_eq!(path.disposition, "ACTIVE");
    assert_eq!(path.sink_impact, "PRODUCTION");
    assert_eq!(path.steps.len(), 5);

    let expected_phases = [
        "INFLUENCE",
        "INFLUENCE",
        "AUTHORITY",
        "AUTHORITY",
        "AUTHORITY",
    ];
    let expected_traversals = ["REVERSE", "REVERSE", "FORWARD", "FORWARD", "FORWARD"];
    for (index, step) in path.steps.iter().enumerate() {
        assert_eq!(step.position, index as u32);
        assert_eq!(step.phase, expected_phases[index]);
        assert_eq!(step.traversal, expected_traversals[index]);
        assert!(
            !step.evidence_ids.is_empty(),
            "step {index} has no same-scan evidence"
        );
    }

    // One connected chain across six historical nodes.
    assert_eq!(path.steps[0].from_resource.id, path.source_resource_id);
    for pair in path.steps.windows(2) {
        assert_eq!(pair[0].to_resource.id, pair[1].from_resource.id);
    }
    assert_eq!(path.steps[4].to_resource.id, path.sink_resource_id);
    let node_names: Vec<&str> = path
        .steps
        .iter()
        .flat_map(|step| {
            [
                step.from_resource.name.as_str(),
                step.to_resource.name.as_str(),
            ]
        })
        .collect::<Vec<_>>();
    let mut unique_nodes = node_names.clone();
    unique_nodes.sort_unstable();
    unique_nodes.dedup();
    assert_eq!(unique_nodes.len(), 6);
    assert_eq!(node_names[0], "Public GitHub issue content");
    assert_eq!(node_names[1], "issue_read");
    assert_eq!(node_names[3], "OpenCode");
    assert_eq!(node_names[5], "Bash");
    assert_eq!(node_names[7], "Cloudflare API Token");
    assert_eq!(node_names[9], "checkout");
    assert!(!unique_nodes.contains(&"Renamed Worker"));

    // The phase transition lands exactly on the declared actor.
    assert_eq!(path.steps[2].from_resource.id, path.actor_resource_id);

    assert_eq!(detail.reasons.len(), 6);
    let expected_codes = [
        "EXTERNAL_INFLUENCE_SOURCE",
        "AGENT_RETRIEVABLE_CONTENT",
        "AUTONOMOUS_EXECUTION_CAPABILITY",
        "REACHABLE_CREDENTIAL_AUTHORITY",
        "PRODUCTION_MUTATION_AUTHORITY",
        "NO_ENFORCED_BOUNDARY",
    ];
    for (index, reason) in detail.reasons.iter().enumerate() {
        assert_eq!(reason.position, index as u32);
        assert_eq!(reason.code, expected_codes[index]);
        assert!(!reason.explanation.is_empty());
    }

    assert!(!detail.evidence.is_empty());
    for evidence in &detail.evidence {
        if let Some(locator) = &evidence.safe_source_locator {
            let lowered = locator.to_ascii_lowercase();
            assert!(!lowered.contains("token"));
            assert!(!lowered.contains("secret"));
            assert!(!lowered.contains("/home/"));
            assert!(!locator.contains('\\'));
        }
    }

    assert_eq!(
        detail.boundary_summary,
        "No proven enforced boundary recorded for this scan interrupts this path."
    );
    for path in &detail.paths {
        for boundary in &path.boundaries {
            assert_eq!(boundary.decision, "DOES_NOT_INTERRUPT");
        }
    }

    assert_eq!(detail.remediations.len(), 4);
    let rule_ids: Vec<&str> = detail
        .remediations
        .iter()
        .map(|remediation| remediation.rule_id.as_str())
        .collect();
    let mut sorted = rule_ids.clone();
    sorted.sort_unstable();
    assert_eq!(rule_ids, sorted);
    for remediation in &detail.remediations {
        assert_eq!(
            remediation.target_resources.len(),
            remediation.target_resource_ids.len()
        );
        assert!(!remediation.target_relationship_ids.is_empty());
        for resource in &remediation.target_resources {
            assert!(!resource.name.is_empty());
        }
    }
    assert_eq!(
        detail.remediation_note,
        "Recommendations only. Pico did not apply these changes."
    );

    assert!(detail.scope_note.contains("potential exposure"));
    assert!(detail.severity_basis.contains("PUBLIC_EXTERNAL"));
    assert!(detail.confidence_basis.contains("CONFIRMED/DERIVED"));
    assert_eq!(detail.uncertainties.len(), 4);
}

#[test]
fn queries_are_deterministic_and_perform_zero_writes() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let db_path = workspace.path().join(".pico").join("pico.db");
    let before = fs::read(&db_path).unwrap();

    let first_list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let finding_id = first_list.findings[0].id.clone();
    let first_detail = FindingQueryService::get(workspace.path(), &finding_id).unwrap();
    let second_list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let second_detail = FindingQueryService::get(workspace.path(), &finding_id).unwrap();

    let after = fs::read(&db_path).unwrap();
    assert_eq!(before, after);
    assert_eq!(
        serde_json::to_string(&first_list).unwrap(),
        serde_json::to_string(&second_list).unwrap()
    );
    assert_eq!(
        serde_json::to_string(&first_detail).unwrap(),
        serde_json::to_string(&second_detail).unwrap()
    );
    assert!(!serde_json::to_string(&first_list)
        .unwrap()
        .contains(SECRET_SENTINEL));
    assert!(!serde_json::to_string(&first_detail)
        .unwrap()
        .contains(SECRET_SENTINEL));
    assert!(!serde_json::to_string(&first_detail)
        .unwrap()
        .contains(AUTH_HEADER_SENTINEL));
}

#[test]
fn uninitialized_and_scan_free_states_are_distinct() {
    let dir = tempdir().unwrap();
    let error = FindingQueryService::list_latest(dir.path()).unwrap_err();
    assert!(error.to_string().contains("pico init"));

    let initialized = tempdir().unwrap();
    InitService::run(initialized.path()).unwrap();
    let list = FindingQueryService::list_latest(initialized.path()).unwrap();
    assert!(list.selected_scan.is_none());
    assert!(list.newest_scan_attempt.is_none());
    assert!(list.findings.is_empty());
    assert!(list.freshness_warning.is_none());
}

#[test]
fn scans_without_a_complete_scan_report_the_newest_attempt() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let db = open_rw(workspace.path());
    db.connection()
        .execute_batch(
            "DELETE FROM finding_paths; DELETE FROM finding_evidence;
             DELETE FROM finding_reasons; DELETE FROM finding_remediations;
             DELETE FROM findings;
             DELETE FROM attack_path_edges; DELETE FROM attack_path_evidence;
             DELETE FROM attack_paths;
             DELETE FROM scan_analyses;
             DELETE FROM scan_diagnostics;
             DELETE FROM observations;
             DELETE FROM relationship_evidence; DELETE FROM evidence;
             DELETE FROM scans;",
        )
        .unwrap();
    let scans = ScanRepo::new(db.connection());
    let running = pico::domain::Scan::start(pico::shared::PICO_VERSION).unwrap();
    scans.insert(&running).unwrap();
    let partial = pico::domain::Scan::start(pico::shared::PICO_VERSION)
        .unwrap()
        .partial()
        .unwrap();
    scans.insert(&partial).unwrap();
    drop(db);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    assert!(list.selected_scan.is_none());
    let newest_attempt = list.newest_scan_attempt.expect("newest attempt reported");
    assert_eq!(newest_attempt.status, "PARTIAL");
    assert!(list.findings.is_empty());
}

#[test]
fn complete_scan_with_zero_findings_is_scoped_not_global_safety() {
    let dir = tempdir().unwrap();
    InitService::run(dir.path()).unwrap();
    let scan = ScanService::run_with_home(dir.path(), None).unwrap();
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(scan.finding_count, 0);
    let list = FindingQueryService::list_latest(dir.path()).unwrap();
    assert_eq!(list.selected_scan.unwrap().id, scan.scan_id);
    assert!(list.findings.is_empty());
    assert_eq!(list.freshness, Freshness::LatestComplete);
}

fn insert_newer_attempt(workspace: &std::path::Path, status: AttemptStatus) -> String {
    let db = open_rw(workspace);
    let repo = ScanRepo::new(db.connection());
    let attempt = match status {
        AttemptStatus::Running => pico::domain::Scan::start(pico::shared::PICO_VERSION).unwrap(),
        AttemptStatus::Partial => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .partial()
            .unwrap(),
        AttemptStatus::Failed => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .fail()
            .unwrap(),
    };
    repo.insert(&attempt).unwrap();
    drop(db);
    attempt.id
}

enum AttemptStatus {
    Running,
    Partial,
    Failed,
}

#[test]
fn newer_incomplete_attempts_produce_exact_freshness_warnings() {
    for status in [
        (AttemptStatus::Running, "RUNNING"),
        (AttemptStatus::Partial, "PARTIAL"),
        (AttemptStatus::Failed, "FAILED"),
    ] {
        let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
        let attempt_id = insert_newer_attempt(workspace.path(), status.0);
        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        assert_eq!(list.freshness, Freshness::NewerIncomplete);
        assert_eq!(
            list.freshness_warning.unwrap(),
            format!(
                "Freshness: A newer scan {attempt_id} is {}.\nShowing the last COMPLETE scan; these results may not describe current state.",
                status.1
            )
        );
        let finding_id = list.findings[0].id.clone();
        let detail = FindingQueryService::get(workspace.path(), &finding_id).unwrap();
        assert_eq!(detail.currentness, Currentness::LatestComplete);
        assert_eq!(
            detail.freshness_warning.unwrap(),
            format!(
                "Freshness: A newer scan {attempt_id} is {}.\nShowing the last COMPLETE scan; these results may not describe current state.",
                status.1
            )
        );
    }
}

#[test]
fn unknown_and_empty_finding_ids_fail_exactly() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let error =
        FindingQueryService::get(workspace.path(), "finding_does_not_exist:abc").unwrap_err();
    assert!(error.to_string().contains("finding_does_not_exist:abc"));

    // Prefixes must not resolve.
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let full_id = list.findings[0].id.clone();
    let prefix = &full_id[..full_id.len() - 4];
    assert!(FindingQueryService::get(workspace.path(), prefix).is_err());

    let empty = FindingQueryService::get(workspace.path(), "").unwrap_err();
    assert!(matches!(empty, pico::shared::PicoError::Usage(_)));
    let blank = FindingQueryService::get(workspace.path(), "   ").unwrap_err();
    assert!(matches!(blank, pico::shared::PicoError::Usage(_)));
}

#[test]
fn historical_finding_uses_originating_scan_snapshot_names() {
    let (workspace, first) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let second = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            Some("PRODUCTION"),
            "checkout",
        )),
    )
    .unwrap();
    assert_ne!(first.scan_id, second.scan_id);

    // Mutate the stable worker row after both scans. Historical projections
    // must ignore the mutable label and use the originating snapshot.
    let db = open_rw(workspace.path());
    let resources = ResourceRepo::new(db.connection());
    let worker_key = "cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456";
    let mut worker = resources.get_by_canonical_key(worker_key).unwrap().unwrap();
    worker.name = "Renamed Worker".to_string();
    resources.upsert(&worker).unwrap();

    let first_finding_id: String = db
        .connection()
        .query_row(
            "SELECT id FROM findings WHERE scan_id = ?1",
            [first.scan_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    assert_eq!(list.selected_scan.unwrap().id, second.scan_id);

    let detail = FindingQueryService::get(workspace.path(), &first_finding_id).unwrap();
    assert_eq!(
        detail.currentness,
        Currentness::Historical {
            newer_complete_scan_id: second.scan_id.clone()
        }
    );
    let path = &detail.paths[0];
    let sink_step = path.steps.last().unwrap();
    assert_eq!(sink_step.to_resource.name, "checkout");
    assert_ne!(sink_step.to_resource.name, "Renamed Worker");

    let current = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    assert_eq!(current.currentness, Currentness::LatestComplete);
}

struct FindingBuilder {
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    fingerprint: &'static str,
    id: &'static str,
}

fn finding_result(findings: Vec<Finding>) -> FindingResult {
    FindingResult {
        scan_id: "scan_navigation".to_string(),
        finding_version: 1,
        status: FindingGenerationStatus::Complete,
        findings,
        diagnostics: Vec::new(),
    }
}

fn built(builder: FindingBuilder) -> Finding {
    Finding {
        id: builder.id.to_string(),
        scan_id: "scan_navigation".to_string(),
        fingerprint: builder.fingerprint.to_string(),
        family_fingerprint: format!("family:{}", builder.fingerprint),
        finding_version: 1,
        finding_class: FindingClass::UntrustedToProduction,
        status: FindingStatus::Open,
        title: builder.title.to_string(),
        summary: "summary".to_string(),
        severity: builder.severity,
        confidence: builder.confidence,
        source_resource_ids: vec![],
        actor_resource_ids: vec![],
        sink_resource_ids: vec![],
        attack_path_ids: vec![],
        attack_path_fingerprints: vec![],
        evidence_ids: vec![],
        reasons: Vec::new(),
        remediations: vec![Remediation {
            rule_id: "ENFORCE_BASH_APPROVAL_OR_DENY".to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            security_effect: "e".to_string(),
            cut_phase: "AUTHORITY".to_string(),
            target_resource_ids: vec![],
            target_relationship_ids: vec![],
        }],
        created_at: chrono::Utc::now(),
    }
}

#[test]
fn navigation_ids_follow_severity_confidence_title_order() {
    let result = finding_result(vec![
        built(FindingBuilder {
            severity: Severity::High,
            confidence: Confidence::High,
            title: "b",
            fingerprint: "fp-high",
            id: "id-high",
        }),
        built(FindingBuilder {
            severity: Severity::Critical,
            confidence: Confidence::Medium,
            title: "a",
            fingerprint: "fp-crit-med",
            id: "id-crit-med",
        }),
        built(FindingBuilder {
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "zeta",
            fingerprint: "fp-crit-high-z",
            id: "id-crit-high-z",
        }),
        built(FindingBuilder {
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "alpha",
            fingerprint: "fp-crit-high-a",
            id: "id-crit-high-a",
        }),
        built(FindingBuilder {
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "omega",
            fingerprint: "fp-info",
            id: "id-info",
        }),
    ]);
    assert_eq!(
        finding_navigation_ids(&result),
        vec![
            "id-crit-high-a",
            "id-crit-high-z",
            "id-crit-med",
            "id-high",
            "id-info",
        ]
    );
}

#[test]
fn reason_codes_map_to_fixed_provider_neutral_text() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let (_, detail) = golden_detail_parts(workspace.path());
    for reason in &detail.reasons {
        match reason.code.as_str() {
            "EXTERNAL_INFLUENCE_SOURCE" => {
                assert!(reason.explanation.starts_with("The path begins at content"));
            }
            "NO_ENFORCED_BOUNDARY" => {
                assert!(reason.explanation.contains("No proven enforced boundary"));
            }
            _ => {}
        }
        // Reasons are fixed prose only; they never embed persisted payloads.
        assert!(!reason.explanation.contains("TEST_"));
    }
    assert!(detail.evidence.iter().all(|item| item
        .support_roles
        .iter()
        .all(|role| { role == "SUPPORTING" || role == "SINK_CLASSIFICATION" })));
}
