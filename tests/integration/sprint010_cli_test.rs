//! Sprint 010 CLI rendering fixtures.
//!
//! These assert the `pico findings` and `pico finding <id>` terminal contract
//! (SPRINT-010.md §7/§10) through the controlled application seam: golden
//! provider-injected scans plus deterministic renderer output. No network or
//! provider call is involved, and every persisted string is terminal-safe.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanResult, ScanService};
use pico::cli::render::{render_finding_detail, render_findings_list};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::persistence::{Database, RelationshipRepo, ScanRepo};
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

#[test]
fn list_rendering_contains_all_required_semantics() {
    let (workspace, scan) = scan_with_classification(Some("PRODUCTION"), "checkout");
    assert_eq!(scan.status, ScanStatus::Complete);
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let rendered = render_findings_list(&list);

    assert!(rendered.contains("Pico Findings"));
    assert!(rendered.contains(&format!("Scan: {}", scan.scan_id)));
    assert!(rendered.contains("Status: COMPLETE"));
    assert!(rendered.contains("Completed:"));
    assert!(rendered.contains("Freshness: LATEST COMPLETE"));
    assert!(rendered.contains("Findings: 1"));
    assert!(rendered.contains("CRITICAL · HIGH confidence"));
    assert!(rendered.contains("External content can reach production mutation authority"));
    assert!(rendered.contains("Class: UNTRUSTED_TO_PRODUCTION"));
    assert!(rendered.contains("Status: OPEN"));
    assert!(rendered.contains("Paths: 1"));
    assert!(rendered.contains("Affected production resources: 1"));
    let id = list.findings[0].id.clone();
    assert!(rendered.contains(&format!("ID: {id}")));
    assert!(rendered.contains(&format!("pico finding {id}")));
    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains(AUTH_HEADER_SENTINEL));
}

#[test]
fn detail_rendering_presents_sections_in_deterministic_order() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);

    let headings = [
        "Finding",
        "What Pico found",
        "Why it matters",
        "Path or Paths",
        "Severity and Confidence",
        "Evidence",
        "Boundaries and Uncertainty",
        "Recommended cuts",
        "Scope note",
    ];
    let mut position = 0;
    for heading in headings {
        let index = rendered[position..].find(heading).expect(heading);
        assert!(position + index < rendered.len(), "{heading} after start");
        position += index + heading.len();
    }

    assert!(rendered.contains("Currentness: LATEST_COMPLETE"));
    assert!(rendered.contains("Path 1"));
    assert!(rendered.contains("Public GitHub issue content"));
    assert!(rendered.contains("issue_read"));
    assert!(rendered.contains("OpenCode"));
    assert!(rendered.contains("Bash"));
    assert!(rendered.contains("Cloudflare API Token"));
    assert!(rendered.contains("checkout"));
    assert!(rendered.contains(" → "));
    assert!(rendered.contains("INFLUENCE REVERSE"));
    assert!(rendered.contains("AUTHORITY FORWARD"));
    assert!(rendered.contains("Supporting evidence:"));

    assert!(
        rendered.contains("Authority resolution: EXACT"),
        "explained-path view must surface the EXACT authority-resolution tier"
    );

    for code in [
        "EXTERNAL_INFLUENCE_SOURCE",
        "AGENT_RETRIEVABLE_CONTENT",
        "AUTONOMOUS_EXECUTION_CAPABILITY",
        "REACHABLE_CREDENTIAL_AUTHORITY",
        "PRODUCTION_MUTATION_AUTHORITY",
        "NO_ENFORCED_BOUNDARY",
    ] {
        assert!(rendered.contains(code), "{code} reason rendered");
    }

    assert!(rendered.contains("Severity: CRITICAL"));
    assert!(rendered.contains("Confidence: HIGH"));
    assert!(rendered.contains("Severity — what could happen if the established path is usable."));
    assert!(
        rendered.contains("Confidence — how strongly Pico established that this Finding exists.")
    );

    assert!(rendered.contains("Evidence: ev_"));
    assert!(rendered.contains("Support roles:"));

    assert!(rendered
        .contains("No proven enforced boundary recorded for this scan interrupts this path."));
    assert!(rendered.contains("observed potential reachability"));
    assert!(rendered.contains("supported scan scope"));
    assert!(rendered.contains("Evidence freshness is UNKNOWN"));

    for rule in [
        "ENFORCE_BASH_APPROVAL_OR_DENY",
        "REMOVE_AGENT_CREDENTIAL_REACHABILITY",
        "RESTRICT_EXTERNAL_RETRIEVAL",
        "SCOPE_PRODUCTION_MUTATION_AUTHORITY",
    ] {
        assert!(rendered.contains(rule), "{rule} remediation rendered");
    }
    assert!(rendered.contains("Recommendations only. Pico did not apply these changes."));
    assert!(rendered.contains("Potential exposure, not exploitation"));
    assert!(rendered.contains("does not establish exploitation, malicious content, or compromise"));

    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains(AUTH_HEADER_SENTINEL));
}

#[test]
fn newer_incomplete_attempts_render_exact_freshness_warnings() {
    for status in ["RUNNING", "PARTIAL", "FAILED"] {
        let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
        let attempt_id = insert_newer_attempt(workspace.path(), status);
        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        let rendered_list = render_findings_list(&list);
        assert!(rendered_list.contains("Freshness: NEWER INCOMPLETE ATTEMPT"));
        assert!(rendered_list.contains(&format!(
            "Freshness: A newer scan {attempt_id} is {status}."
        )));
        assert!(rendered_list.contains(
            "Showing the last COMPLETE scan; these results may not describe current state."
        ));

        let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
        let rendered_detail = render_finding_detail(&detail);
        assert!(rendered_detail.contains(&format!(
            "Freshness: A newer scan {attempt_id} is {status}."
        )));
    }
}

fn insert_newer_attempt(workspace: &std::path::Path, status: &str) -> String {
    let db = open_rw(workspace);
    let repo = ScanRepo::new(db.connection());
    let attempt = match status {
        "RUNNING" => pico::domain::Scan::start(pico::shared::PICO_VERSION).unwrap(),
        "PARTIAL" => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .partial()
            .unwrap(),
        "FAILED" => pico::domain::Scan::start(pico::shared::PICO_VERSION)
            .unwrap()
            .fail()
            .unwrap(),
        _ => panic!("unknown attempt status"),
    };
    repo.insert(&attempt).unwrap();
    drop(db);
    attempt.id
}

#[test]
fn historical_detail_renders_currentness_with_newer_complete_scan() {
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

    let first_finding_id: String = {
        let db = open_rw(workspace.path());
        db.connection()
            .query_row(
                "SELECT id FROM findings WHERE scan_id = ?1",
                [first.scan_id.as_str()],
                |row| row.get(0),
            )
            .unwrap()
    };

    let detail = FindingQueryService::get(workspace.path(), &first_finding_id).unwrap();
    let rendered = render_finding_detail(&detail);
    assert!(rendered.contains("Currentness: HISTORICAL"));
    assert!(rendered.contains(&format!("Newer COMPLETE scan: {}", second.scan_id)));
}

#[test]
fn empty_and_uninitialized_states_render_distinct_guidance() {
    let initialized = tempdir().unwrap();
    InitService::run(initialized.path()).unwrap();
    let list = FindingQueryService::list_latest(initialized.path()).unwrap();
    let rendered = render_findings_list(&list);
    assert!(rendered.contains("No scans have been run"));
    assert!(rendered.contains("pico scan"));

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
             DELETE FROM relationships; DELETE FROM resources;
             DELETE FROM scans;",
        )
        .unwrap();
    let repo = ScanRepo::new(db.connection());
    let running = pico::domain::Scan::start(pico::shared::PICO_VERSION)
        .unwrap()
        .partial()
        .unwrap();
    repo.insert(&running).unwrap();
    drop(db);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let rendered = render_findings_list(&list);
    assert!(rendered.contains("No COMPLETE scan exists"));
    assert!(rendered.contains(&running.id));
    assert!(rendered.contains("PARTIAL"));
    assert!(rendered.contains("This is not an all-clear"));
}

#[test]
fn zero_findings_is_scoped_and_never_global_safety() {
    let dir = tempdir().unwrap();
    InitService::run(dir.path()).unwrap();
    let scan = ScanService::run_with_home(dir.path(), None).unwrap();
    assert_eq!(scan.status, ScanStatus::Complete);
    let list = FindingQueryService::list_latest(dir.path()).unwrap();
    let rendered = render_findings_list(&list);
    assert!(rendered.contains(&format!("Scan: {}", scan.scan_id)));
    assert!(rendered.contains(
        "No Findings were produced for this COMPLETE scan within Pico's supported scope."
    ));
    for forbidden in [
        "Your environment is secure",
        "No risk found",
        "No attack paths exist",
    ] {
        assert!(!rendered.contains(forbidden), "{forbidden} must not appear");
    }
}

#[test]
fn unknown_and_empty_ids_fail_exactly() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let error =
        FindingQueryService::get(workspace.path(), "finding_does_not_exist:abc").unwrap_err();
    assert!(error.to_string().contains("finding_does_not_exist:abc"));

    let empty = FindingQueryService::get(workspace.path(), "").unwrap_err();
    assert!(matches!(empty, pico::shared::PicoError::Usage(_)));
}

#[test]
fn explained_path_surfaces_per_edge_evidence_provenance() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);

    assert!(rendered.contains("freshness=FRESH"));
    assert!(rendered.contains("captured="));
    assert!(rendered.contains("locator="));
    assert!(rendered.contains("Weakest evidence:"));
}

#[test]
fn rendered_finding_explanation_flags_oldest_evidence() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);
    assert!(rendered.contains("Weakest evidence:"));
    assert!(rendered.contains("freshness="));
}

#[test]
fn surfaced_finding_exposes_fingerprint_and_remediation_cut_point() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let summary = &list.findings[0];
    let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();

    let rendered_list = render_findings_list(&list);
    let rendered_detail = render_finding_detail(&detail);

    // The finding fingerprint must be surfaced in both the list and the detail.
    assert!(
        !summary.fingerprint.is_empty(),
        "summary fingerprint must be populated"
    );
    assert_eq!(summary.fingerprint, detail.fingerprint);
    assert!(
        rendered_list.contains(&format!("Fingerprint: {}", summary.fingerprint)),
        "list must surface the finding fingerprint"
    );
    assert!(
        rendered_detail.contains(&format!("Fingerprint: {}", detail.fingerprint)),
        "detail must surface the finding fingerprint"
    );

    // The grouped-path count (len of attack_path_fingerprints) must be exposed.
    assert_eq!(
        detail.attack_path_fingerprints.len() as u64,
        summary.attack_path_count
    );
    assert!(
        rendered_detail.contains(&format!(
            "Grouped paths: {}",
            detail.attack_path_fingerprints.len()
        )),
        "detail must surface the grouped-path count"
    );

    // The remediation cut point must carry the rule_id and a human-readable
    // target relationship derived from the cut edge endpoints.
    assert!(!detail.remediations.is_empty());
    for remediation in &detail.remediations {
        assert!(
            rendered_detail.contains(&remediation.rule_id),
            "remediation rule_id {} must be rendered",
            remediation.rule_id
        );
        assert!(
            !remediation.target_relationship_descriptions.is_empty(),
            "remediation {} must have a human-readable cut point",
            remediation.rule_id
        );
        for description in &remediation.target_relationship_descriptions {
            assert!(
                rendered_detail.contains(description),
                "human-readable cut point '{}' must be rendered",
                description
            );
        }
    }
}

#[test]
fn finding_fingerprint_and_remediation_targets_contain_no_raw_secret() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let summary = &list.findings[0];
    assert!(!summary.fingerprint.contains(SECRET_SENTINEL));
    assert!(!summary.fingerprint.contains("synthetic-token"));
    assert_ne!(summary.fingerprint, "synthetic-token");

    let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
    assert!(!detail.fingerprint.contains(SECRET_SENTINEL));
    assert!(!detail.fingerprint.contains("synthetic-token"));

    for remediation in &detail.remediations {
        for id in &remediation.target_relationship_ids {
            assert!(
                !id.contains(SECRET_SENTINEL),
                "remediation relationship id leaked the secret sentinel: {id}"
            );
            assert!(
                !id.contains("synthetic-token"),
                "remediation relationship id leaked the token value: {id}"
            );
        }
        for description in &remediation.target_relationship_descriptions {
            assert!(!description.contains(SECRET_SENTINEL));
            assert!(!description.contains("synthetic-token"));
        }
    }

    // Canonical credential keys carry only the credential fingerprint, never the
    // raw token value.
    let mut saw_credential = false;
    let mut check_key = |key: &str| {
        assert!(!key.contains("synthetic-token"));
        if key.starts_with("credential:") {
            saw_credential = true;
            assert!(
                key.starts_with("credential:cloudflare:"),
                "credential key must be the fingerprint form, got {key}"
            );
            assert!(
                !key.contains("synthetic-token"),
                "credential key must not embed the token value: {key}"
            );
        }
    };
    for path in &detail.paths {
        for step in &path.steps {
            check_key(&step.from_resource.canonical_key);
            check_key(&step.to_resource.canonical_key);
        }
    }
    for remediation in &detail.remediations {
        for resource in &remediation.target_resources {
            check_key(&resource.canonical_key);
        }
    }
    assert!(
        saw_credential,
        "expected a credential resource in the golden path"
    );
}

#[test]
fn evidence_source_locators_never_contain_raw_secrets() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let db = open_rw(workspace.path());
    let locators: String = db
        .connection()
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(source_locator), '') FROM evidence",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!locators.contains(SECRET_SENTINEL));
    assert!(!locators.contains("synthetic-token"));
}

#[test]
fn persisted_can_mutate_relationship_exposes_authority_resolution_tier() {
    let (workspace, scan) = scan_with_classification(Some("PRODUCTION"), "checkout");
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.authority_resolution.as_deref(),
        Some("EXACT"),
        "the in-memory scan summary must carry the tier the CLI surfaces"
    );

    let db = open_rw(workspace.path());
    let relationships = RelationshipRepo::new(db.connection());
    let can_mutate: Vec<_> = relationships
        .list()
        .unwrap()
        .into_iter()
        .filter(|relationship| relationship.kind == "can_mutate")
        .collect();
    assert_eq!(can_mutate.len(), 1, "exactly one can_mutate relationship");

    let metadata = can_mutate[0]
        .metadata
        .as_ref()
        .expect("can_mutate relationship must carry metadata");
    let persisted = metadata
        .get("authority_resolution")
        .and_then(serde_json::Value::as_str)
        .expect("authority_resolution must be present in the persisted metadata");
    assert_eq!(
        persisted, "EXACT",
        "the authority-resolution tier must be independently retrievable from the relationship store"
    );
    assert_eq!(persisted, scan.authority_resolution.as_deref().unwrap());
}

#[test]
fn rendering_escapes_terminal_control_strings_and_is_deterministic() {
    let (workspace, _) = scan_with_classification(Some("PRODUCTION"), "checkout");
    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();

    let mut spoofed_list = list.clone();
    spoofed_list.findings[0].title = "\u{1b}[31mSPOOF\u{1b}[0m\nline2".to_string();
    let rendered_list = render_findings_list(&spoofed_list);
    assert!(!rendered_list.contains('\u{1b}'));
    assert!(rendered_list.contains("\\x1B[31mSPOOF\\x1B[0m"));
    assert!(rendered_list.contains("line2"));
    assert!(!rendered_list.contains("SPOOF\nline2"));

    let mut spoofed_detail = detail.clone();
    spoofed_detail.title = "\u{1b}[31mSPOOF\u{1b}[0m".to_string();
    spoofed_detail.paths[0].steps[0].from_resource.name = "evil\u{1b}[0m".to_string();
    spoofed_detail.paths[0].steps[0].to_resource.name = "col\ttab".to_string();
    spoofed_detail.evidence[0].observation = "line1\nline2".to_string();
    let rendered_detail = render_finding_detail(&spoofed_detail);
    assert!(!rendered_detail.contains('\u{1b}'));
    assert!(rendered_detail.contains("evil\\x1B[0m"));
    assert!(rendered_detail.contains("col\\x09tab"));
    assert!(rendered_detail.contains("line1\\x0Aline2"));
    assert!(!rendered_detail.contains("evil\u{1b}"));

    let again = render_finding_detail(&spoofed_detail);
    assert_eq!(rendered_detail, again);
    let list_again = render_findings_list(&spoofed_list);
    assert_eq!(rendered_list, list_again);
}
