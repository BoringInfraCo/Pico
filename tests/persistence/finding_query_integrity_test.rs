//! Sprint 010 Finding query integrity: broken references, unsupported
//! versions, and schema gates fail closed without partial explanations.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{Evidence, EvidenceClass, RelationshipState, Sensitivity};
use pico::persistence::{require_schema_version, Database, SUPPORTED_SCHEMA_VERSION};
use tempfile::tempdir;

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

fn run_golden_scan(workspace: &std::path::Path) {
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace,
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
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(ProviderResult {
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
        }),
    )
    .unwrap();
    assert_eq!(result.finding_count, 1);
}

fn open_rw(workspace: &std::path::Path) -> Database {
    Database::open_existing(&workspace.join(".pico").join("pico.db")).unwrap()
}

fn detail_error_after(mutate: impl FnOnce(&Database)) -> String {
    let workspace = setup();
    run_golden_scan(workspace.path());
    let db = open_rw(workspace.path());
    mutate(&db);
    let finding_id: String = db
        .connection()
        .query_row("SELECT id FROM findings LIMIT 1", [], |row| row.get(0))
        .unwrap();
    drop(db);
    FindingQueryService::get(workspace.path(), &finding_id)
        .expect_err("corrupted state must fail closed")
        .to_string()
}

#[test]
fn read_only_open_requires_an_existing_database() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(".pico").join("pico.db");
    let error = match Database::open_read_only(&path) {
        Ok(_) => panic!("missing database must fail"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        !message.contains(path.display().to_string().as_str()),
        "read-only open must not leak the absolute database path: {message}"
    );
    assert!(message.contains("no Pico state in this workspace"));
    assert!(message.contains("pico init"));
}

#[test]
fn require_schema_version_accepts_only_the_supported_version() {
    let workspace = setup();
    let db = open_rw(workspace.path());
    assert_eq!(
        require_schema_version(db.connection()).unwrap(),
        SUPPORTED_SCHEMA_VERSION
    );
}

#[test]
fn unsupported_older_schema_version_fails_without_migrating() {
    let workspace = setup();
    {
        let db = open_rw(workspace.path());
        db.connection()
            .pragma_update(None, "user_version", 3)
            .unwrap();
    }
    let error = FindingQueryService::list_latest(workspace.path()).unwrap_err();
    assert!(error.to_string().contains("unsupported schema version 3"));
    let db = open_rw(workspace.path());
    let version: i64 = db
        .connection()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3);
}

#[test]
fn unsupported_newer_schema_version_fails_closed() {
    let workspace = setup();
    {
        let db = open_rw(workspace.path());
        db.connection()
            .pragma_update(None, "user_version", SUPPORTED_SCHEMA_VERSION + 1)
            .unwrap();
    }
    let error = FindingQueryService::list_latest(workspace.path()).unwrap_err();
    assert!(error.to_string().contains("unsupported schema version"));
    let detail_error =
        FindingQueryService::get(workspace.path(), "finding_anything:x").unwrap_err();
    assert!(detail_error
        .to_string()
        .contains("unsupported schema version"));
}

#[test]
fn missing_path_link_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch("DELETE FROM finding_paths;")
            .unwrap();
    });
    assert!(message.contains("no linked attack paths"));
}

#[test]
fn foreign_scan_evidence_link_is_an_integrity_error() {
    // SAFETY: the same-scan trigger is dropped only inside this throwaway
    // fixture database and is recreated immediately after planting the
    // cross-scan link; no real state is touched.
    let message = detail_error_after(|db| {
        let conn = db.connection();
        let scan = pico::domain::Scan::start(pico::shared::PICO_VERSION).unwrap();
        pico::persistence::ScanRepo::new(conn)
            .insert(&scan)
            .unwrap();
        let evidence = Evidence::new(
            &scan.id,
            EvidenceClass::Declared,
            "fixture",
            "fixture",
            "fixture-subject",
            "fixture observation",
            Sensitivity::Internal,
        )
        .unwrap();
        pico::persistence::EvidenceRepo::new(conn)
            .insert(&evidence)
            .unwrap();
        conn.execute_batch(
            "DROP TRIGGER finding_evidence_same_scan_insert;
             CREATE TRIGGER finding_evidence_same_scan_insert_recreated
             AFTER INSERT ON finding_evidence BEGIN SELECT 1; END;",
        )
        .unwrap();
        let position: i64 = conn
            .query_row("SELECT COUNT(*) FROM finding_evidence", [], |row| {
                row.get(0)
            })
            .unwrap();
        let finding_id: String = conn
            .query_row("SELECT id FROM findings LIMIT 1", [], |row| row.get(0))
            .unwrap();
        conn.execute(
            "INSERT INTO finding_evidence (finding_id, evidence_id, position, support_role)
             VALUES (?1, ?2, ?3, 'SUPPORTING')",
            rusqlite::params![finding_id, evidence.id, position],
        )
        .unwrap();
        conn.execute_batch(
            "DROP TRIGGER finding_evidence_same_scan_insert_recreated;
             CREATE TRIGGER finding_evidence_same_scan_insert
             BEFORE INSERT ON finding_evidence
             FOR EACH ROW
             WHEN (SELECT scan_id FROM findings WHERE id = NEW.finding_id) IS NOT NULL
              AND (SELECT scan_id FROM evidence WHERE id = NEW.evidence_id) IS NOT NULL
              AND (SELECT scan_id FROM findings WHERE id = NEW.finding_id)
                  != (SELECT scan_id FROM evidence WHERE id = NEW.evidence_id)
             BEGIN
                 SELECT RAISE(ABORT, 'finding evidence must reference evidence from the same scan');
             END;",
        )
        .unwrap();
    });
    assert!(message.contains("belongs to another scan"));
}

#[test]
fn unsupported_finding_version_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch("UPDATE findings SET finding_version = '2';")
            .unwrap();
    });
    assert!(message.contains("unsupported finding version 2"));
}

#[test]
fn null_boundary_metadata_on_active_path_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch("UPDATE attack_paths SET boundary_metadata = NULL;")
            .unwrap();
    });
    assert!(message.contains("has no boundary metadata"));
}

#[test]
fn interrupting_boundary_on_linked_path_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch(
                r#"UPDATE attack_paths SET boundary_metadata = '[
                    {
                        "kind": "HardDeny",
                        "affected_resource_ids": [],
                        "affected_relationship_ids": [],
                        "enforcement": "fixture",
                        "interrupted_phase": null,
                        "decision": "Interrupts",
                        "evidence_ids": []
                    }
                ]';"#,
            )
            .unwrap();
    });
    assert!(message.contains("violates active-Finding eligibility"));
}

#[test]
fn unresolved_boundary_on_linked_path_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch(
                r#"UPDATE attack_paths SET boundary_metadata = '[
                    {
                        "kind": "MandatoryApproval",
                        "affected_resource_ids": [],
                        "affected_relationship_ids": [],
                        "enforcement": "fixture",
                        "interrupted_phase": "Authority",
                        "decision": "Unresolved",
                        "evidence_ids": []
                    }
                ]';"#,
            )
            .unwrap();
    });
    assert!(message.contains("violates active-Finding eligibility"));
}

#[test]
fn malformed_boundary_metadata_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch(r#"UPDATE attack_paths SET boundary_metadata = '{"not":"an array"}';"#)
            .unwrap();
    });
    assert!(message.contains("malformed boundary metadata"));
}

#[test]
fn gapped_edge_positions_are_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch("UPDATE attack_path_edges SET position = 9 WHERE position = 1;")
            .unwrap();
    });
    assert!(message.contains("positions are not zero-based contiguous"));
}

#[test]
fn disconnected_edges_are_an_integrity_error() {
    let message = detail_error_after(|db| {
        let conn = db.connection();
        let unrelated_relationship: String = conn
            .query_row(
                "SELECT id FROM relationships WHERE canonical_key LIKE '%|scoped_to|%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE attack_path_edges
             SET relationship_id = ?1
             WHERE position = (SELECT MAX(position) FROM attack_path_edges)",
            rusqlite::params![unrelated_relationship],
        )
        .unwrap();
    });
    assert!(message.contains("does not reach its declared sink"));
}

#[test]
fn remediation_targeting_unlinked_relationship_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch(
                r#"UPDATE finding_remediations SET target_relationship_ids = '["rel_missing"]'
                   WHERE rule_id = 'ENFORCE_BASH_APPROVAL_OR_DENY';"#,
            )
            .unwrap();
    });
    assert!(message.contains("outside its declared phase"));
}

#[test]
fn missing_historical_observation_snapshot_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch(
                "UPDATE observations SET metadata = NULL
                 WHERE subject_type = 'resource' AND id = (
                   SELECT id FROM observations WHERE subject_type = 'resource' LIMIT 1
                 );",
            )
            .unwrap();
    });
    assert!(message.contains("missing graph snapshot"));
}

#[test]
fn non_production_sink_impact_on_linked_path_is_an_integrity_error() {
    let message = detail_error_after(|db| {
        db.connection()
            .execute_batch("UPDATE attack_paths SET sink_impact = 'STAGING';")
            .unwrap();
    });
    assert!(message.contains("does not impact PRODUCTION"));

    let workspace = setup();
    run_golden_scan(workspace.path());
    {
        let db = open_rw(workspace.path());
        db.connection()
            .execute_batch("UPDATE attack_paths SET sink_impact = 'STAGING';")
            .unwrap();
    }
    let list_error = FindingQueryService::list_latest(workspace.path()).unwrap_err();
    assert!(list_error
        .to_string()
        .contains("does not impact PRODUCTION"));
}

#[test]
fn missing_provenance_on_security_critical_edge_is_integrity_error() {
    let message = detail_error_after(|db| {
        let conn = db.connection();
        let relationship_id: String = conn
            .query_row(
                "SELECT relationship_id FROM attack_path_edges LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let evidence_id: String = conn
            .query_row(
                "SELECT evidence_id FROM relationship_evidence WHERE relationship_id = ?1 LIMIT 1",
                [relationship_id],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute(
            "UPDATE evidence SET freshness = NULL WHERE id = ?1",
            [evidence_id],
        )
        .unwrap();
    });
    assert!(message.contains("security-critical edge lacks provenance"));
}
