//! Controlled offline end-to-end v0.4 captures, not independent comprehension.
//! Opt in to transcripts with PICO_DOGFOOD_OUTPUT=/absolute/output/directory.
use std::fs;
use std::path::Path;
use std::process::Command;

use pico::application::{FindingQueryService, InitService, ScanService};
use pico::cli::render::{render_scan_diagnostics, render_scan_effective_bash};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::discover_with_environment;
use pico::discovery::EnvironmentReachability;
use pico::domain::RelationshipState;
use pico::domain::ScanStatus;
use pico::mcp::handle_line;
use pico::persistence::{Database, ScanRepo};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn capture(name: &str, bytes: &[u8]) {
    assert!(!bytes
        .windows(b"DF35_SECRET_SENTINEL".len())
        .any(|w| w == b"DF35_SECRET_SENTINEL"));
    assert!(!bytes
        .iter()
        .any(|b| *b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t')));
    if let Some(dir) = std::env::var_os("PICO_DOGFOOD_OUTPUT") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(Path::new(&dir).join(name), bytes).unwrap();
    }
}

fn configuration(path: &Path, posture: &str) {
    fs::write(
        path.join("opencode.json"),
        json!({"permission":{"bash":posture}}).to_string(),
    )
    .unwrap();
}

fn scan(path: &Path, home: &Path, label: &str, expected: ScanStatus) -> String {
    let result = ScanService::run_with_home_and_environment(
        path,
        Some(home),
        Some(&[]),
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    assert_eq!(result.status, expected);
    let mut report = format!(
        "Controlled offline ScanService run (empty home and environment; no provider injection)\nScan: {}\nStatus: {}\nFindings: {}\n{}",
        result.scan_id, result.status.as_str(), result.finding_count, render_scan_effective_bash(&result),
    );
    if let Some(diagnostics) = &result.diagnostics_detail {
        report.push_str(&render_scan_diagnostics(diagnostics));
    }
    capture(&format!("df35-{label}-scan-service.txt"), report.as_bytes());
    result.scan_id
}

fn command(path: &Path, label: &str, args: &[&str], success: bool) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_pico"))
        .args(args)
        .current_dir(path)
        .output()
        .unwrap();
    assert_eq!(
        out.status.success(),
        success,
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    capture(&format!("df35-{label}-stdout.txt"), &out.stdout);
    capture(&format!("df35-{label}-stderr.txt"), &out.stderr);
    capture(
        &format!("df35-{label}-command.json"),
        &serde_json::to_vec_pretty(&json!({"args":args,"exit_code":out.status.code()})).unwrap(),
    );
    out.stdout
}

fn query(
    path: &Path,
    label: &str,
    args: &[&str],
    tool: &str,
    parameters: Value,
    success: bool,
) -> Value {
    let dbpath = path.join(".pico/pico.db");
    let before = fs::read(&dbpath).unwrap();
    command(path, &format!("{label}-human"), args, success);
    let mut json_args = args.to_vec();
    json_args.push("--json");
    let bytes = command(path, &format!("{label}-json"), &json_args, success);
    let payload: Value = serde_json::from_slice(&bytes).unwrap();
    let repeated = command(path, &format!("{label}-repeat-json"), &json_args, success);
    assert_eq!(bytes, repeated, "repeated public output changed");
    let request = json!({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":tool,"arguments":parameters}});
    let frame = handle_line(&request.to_string(), path).unwrap();
    capture(
        &format!("df35-{label}-mcp-request.json"),
        &serde_json::to_vec_pretty(&request).unwrap(),
    );
    capture(&format!("df35-{label}-mcp-response.json"), frame.as_bytes());
    let frame: Value = serde_json::from_str(&frame).unwrap();
    assert!(frame.get("error").is_none());
    let decoded: Value =
        serde_json::from_str(frame["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, payload, "CLI/MCP semantic mismatch");
    assert_eq!(frame["result"]["isError"] == true, !success);
    let after = fs::read(&dbpath).unwrap();
    assert_eq!(before, after, "query changed database bytes");
    capture(&format!("df35-{label}-read-only.json"), &serde_json::to_vec_pretty(&json!({
        "method":"SHA-256 of closed rollback-journal SQLite main file before/after all queries",
        "before":format!("{:x}",Sha256::digest(&before)),"after":format!("{:x}",Sha256::digest(&after)),"equal":true
    })).unwrap());
    payload
}

fn diff(path: &Path, label: &str) -> Value {
    query(path, label, &["diff"], "diff_scans", json!({}), true)
}

#[test]
fn controlled_scan_history_diff_mcp_and_retention_sequence() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = workspace.path();
    InitService::run(path).unwrap();
    capture("df35-fixture-manifest.json", &serde_json::to_vec_pretty(&json!({
        "fixture":"tests/sprint035_dogfood.rs::controlled_scan_history_diff_mcp_and_retention_sequence",
        "binary_sha256":format!("{:x}",Sha256::digest(fs::read(env!("CARGO_BIN_EXE_pico")).unwrap())),
        "observation_mode":"real local discovery using ScanService fixture seam; empty home and environment; no network providers",
        "synthetic_mutation":"comparison_contract_version=999 on final scan after observation",
        "independent_comprehension":"NOT RUN",
        "limitations":["No live provider authority evidence","No active production Finding in this fixture","Main-file byte digest assumes default rollback journal; not a general WAL digest"]
    })).unwrap());
    assert_eq!(diff(path, "empty")["status"], "insufficient_history");
    query(
        path,
        "empty-history",
        &["history"],
        "list_history",
        json!({}),
        true,
    );
    configuration(path, "allow");
    let first = scan(path, home.path(), "baseline", ScanStatus::Complete);
    assert_eq!(diff(path, "one-scan")["status"], "insufficient_history");
    scan(path, home.path(), "unchanged", ScanStatus::Complete);
    let unchanged = diff(path, "unchanged");
    assert_eq!(unchanged["status"], "ready");
    for subject in ["resources", "relationships"] {
        for state in ["changed", "first_seen", "reappeared", "not_observed"] {
            assert!(unchanged["graph"][subject][state]
                .as_array()
                .unwrap()
                .is_empty());
        }
    }
    configuration(path, "deny");
    let denied = scan(path, home.path(), "deny", ScanStatus::Complete);
    let changed = diff(path, "deny");
    assert_eq!(changed["status"], "ready");
    assert!(!changed["graph"]["relationships"]["changed"]
        .as_array()
        .unwrap()
        .is_empty());

    // Invalid config is collection loss, not an observed deny/removal transition.
    fs::write(
        path.join("opencode.json"),
        "{ DF35_SECRET_SENTINEL malformed",
    )
    .unwrap();
    let partial = scan(path, home.path(), "evidence-loss", ScanStatus::Partial);
    let stale = diff(path, "evidence-loss");
    assert_eq!(stale["to"]["id"], denied);
    assert_eq!(stale["newest_attempt"]["id"], partial);
    assert_eq!(stale["freshness"], "newer_incomplete_attempt");
    configuration(path, "deny");
    let recovered = scan(path, home.path(), "recovery", ScanStatus::Complete);
    let recovery = diff(path, "recovery");
    assert_eq!(recovery["from"]["id"], denied);
    assert_eq!(recovery["to"]["id"], recovered);
    assert!(recovery["graph"]["relationships"]["not_observed"]
        .as_array()
        .unwrap()
        .is_empty());
    query(
        path,
        "before-prune-history",
        &["history"],
        "list_history",
        json!({}),
        true,
    );
    let retained_before = retained_digest(path, &[&denied, &recovered]);
    command(path, "prune", &["prune", "--keep", "2"], true);
    let retained_after = retained_digest(path, &[&denied, &recovered]);
    assert_eq!(retained_before, retained_after);
    capture("df35-retained-row-digests.json", &serde_json::to_vec_pretty(&json!({
        "method":"S031 canonical SQL quote serialization of all columns, ordered rows across 16 tables; globals unfiltered, scoped rows and links filtered to retained units",
        "before":retained_before,"after":retained_after,"equal":true
    })).unwrap());
    let after_prune = fs::read(path.join(".pico/pico.db")).unwrap();
    command(path, "prune-noop", &["prune", "--keep", "2"], true);
    assert_eq!(fs::read(path.join(".pico/pico.db")).unwrap(), after_prune);
    let retained = diff(path, "retained");
    assert_eq!(retained["status"], "ready");
    for field in ["from", "to", "provenance", "findings", "attribution"] {
        assert_eq!(
            retained[field], recovery[field],
            "pruning altered retained {field}"
        );
    }
    // Compare every graph field after accounting solely for window-relative
    // first-seen IDs. Security deltas and evidence provenance must remain exact.
    let mut prior_graph = recovery["graph"].clone();
    for kind in ["resources", "relationships"] {
        for subject in prior_graph[kind]["unchanged"].as_array_mut().unwrap() {
            subject["first_seen_scan_id"] = json!(denied);
        }
    }
    assert_eq!(retained["graph"], prior_graph);
    // first_seen_scan_id may move forward when its earlier retained witness is
    // pruned; that is the documented retained-history boundary, not row mutation.
    query(
        path,
        "pruned-pair",
        &["diff", &first, &recovered],
        "diff_scans",
        json!({"from":first,"to":recovered}),
        false,
    );
    for subject in retained["graph"]["resources"]["unchanged"]
        .as_array()
        .unwrap()
    {
        assert_eq!(subject["first_seen_scan_id"], denied);
    }
    let history = query(
        path,
        "retained-history",
        &["history"],
        "list_history",
        json!({}),
        true,
    );
    assert_eq!(history["complete_scan_count"], 2);
    command(path, "doctor", &["doctor"], true);

    // Only this scenario seeds a persisted value; it is explicitly not a real upgrade.
    {
        let db = Database::open_existing(&path.join(".pico/pico.db")).unwrap();
        let mut row = ScanRepo::new(db.connection())
            .get(&recovered)
            .unwrap()
            .unwrap();
        row.metadata.as_mut().unwrap()["comparison_contract_version"] = json!(999);
        ScanRepo::new(db.connection()).update(&row).unwrap();
    }
    assert_eq!(diff(path, "contract-mismatch")["status"], "not_comparable");
    let bytes = fs::read(path.join(".pico/pico.db")).unwrap();
    assert!(!bytes
        .windows(b"DF35_SECRET_SENTINEL".len())
        .any(|w| w == b"DF35_SECRET_SENTINEL"));
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
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
        worker_tag: Some(format!("worker-tag-{script_name}")),
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

fn scan_named(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace, home, script_name)),
    )
    .unwrap()
}

#[test]
fn synthetic_provider_finding_packet_and_boundary_transition() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = workspace.path();
    InitService::run(path).unwrap();
    let config = json!({"permission":{"bash":"allow"}, "mcp":{"servers":{"github":{
        "type":"local","command":["docker","run","ghcr.io/github/github-mcp-server:0.1.0"],
        "environment":{"GITHUB_PERSONAL_ACCESS_TOKEN":"DF35_SECRET_SENTINEL"}
    }}}});
    fs::write(path.join("opencode.json"), config.to_string()).unwrap();
    let baseline = scan_named(path, home.path(), "production-fixture");
    assert_eq!(baseline.status, ScanStatus::Complete);
    assert_eq!(baseline.finding_count, 1);
    let repeated = scan_named(path, home.path(), "production-fixture");
    assert_eq!(repeated.finding_count, 1);
    let unchanged = diff(path, "provider-unchanged");
    assert_eq!(
        unchanged["findings"]["unchanged"].as_array().unwrap().len(),
        1
    );
    assert!(unchanged["findings"]["appeared"]
        .as_array()
        .unwrap()
        .is_empty());
    let before = fs::read(path.join(".pico/pico.db")).unwrap();
    let list = FindingQueryService::list_latest(path).unwrap();
    assert_eq!(list.findings.len(), 1);
    let id = &list.findings[0].id;
    command(path, "provider-findings", &["findings"], true);
    let human = command(path, "provider-finding-detail", &["finding", id], true);
    let human = String::from_utf8(human).unwrap();
    assert!(human.contains("PRODUCTION"));
    assert!(human.contains("Pico did not apply"));
    for (label, name, args) in [
        ("list", "list_findings", json!({})),
        ("detail", "get_finding", json!({"id":id})),
    ] {
        let request = json!({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":name,"arguments":args}});
        let frame = handle_line(&request.to_string(), path).unwrap();
        let value: Value = serde_json::from_str(&frame).unwrap();
        assert!(value.get("error").is_none());
        assert!(value["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(id));
        capture(
            &format!("df35-provider-finding-{label}-mcp.json"),
            frame.as_bytes(),
        );
    }
    assert_eq!(fs::read(path.join(".pico/pico.db")).unwrap(), before);
    let mut denied_config = config;
    denied_config["permission"]["bash"] = json!("deny");
    fs::write(path.join("opencode.json"), denied_config.to_string()).unwrap();
    let denied = scan_named(path, home.path(), "production-fixture");
    assert_eq!(denied.status, ScanStatus::Complete);
    assert_eq!(denied.finding_count, 0);
    let transition = diff(path, "provider-deny");
    assert_eq!(
        transition["findings"]["not_observed"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Provider inventory coverage is deliberately unknown: the fixture cannot
    // justify a confirmed environmental disappearance just from this set delta.
    for attribution in transition["attribution"]["finding_changes"]
        .as_array()
        .unwrap()
    {
        assert_ne!(attribution["disappearance_confirmed"], true);
    }
    capture("df35-provider-fixture-manifest.json", &serde_json::to_vec_pretty(&json!({
        "fixture":"tests/sprint035_dogfood.rs::synthetic_provider_finding_packet_and_boundary_transition",
        "observation_mode":"real OpenCode/GitHub MCP config discovery with SYNTHETIC Cloudflare provider result injection; no network calls or production infrastructure",
        "baseline_scan":baseline.scan_id,"repeat_scan":repeated.scan_id,"denied_scan":denied.scan_id,
        "finding_count_before":1,"finding_count_after":0,
        "independent_comprehension":"NOT RUN",
        "provider_coverage":"unknown; no confirmed environmental disappearance implied"
    })).unwrap());
    let bytes = fs::read(path.join(".pico/pico.db")).unwrap();
    assert!(!bytes
        .windows(b"DF35_SECRET_SENTINEL".len())
        .any(|w| w == b"DF35_SECRET_SENTINEL"));
    assert!(!bytes
        .windows(b"synthetic-token".len())
        .any(|w| w == b"synthetic-token"));
}

// Retained-unit digest pattern shared with the S031 regression evidence.
fn open_read_only(workspace: &Path) -> Connection {
    Connection::open_with_flags(
        workspace.join(".pico").join("pico.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

/// Canonical row serialization for one table: all columns via `quote()`, rows
/// in rowid order, optionally restricted by a WHERE filter.
fn table_rows(conn: &Connection, table: &str, filter: Option<&str>) -> String {
    let column_names: Vec<String> = {
        let mut columns = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
            ))
            .unwrap();
        columns
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    };
    let mut out = format!("table {table} [{}]\n", column_names.join(","));
    let projection = column_names
        .iter()
        .map(|column| format!("quote({column})"))
        .collect::<Vec<_>>()
        .join(", ");
    let where_clause = filter.map(|f| format!(" WHERE {f}")).unwrap_or_default();
    let mut rows = conn
        .prepare(&format!(
            "SELECT {projection} FROM \"{table}\"{where_clause} ORDER BY rowid"
        ))
        .unwrap();
    let column_count = column_names.len();
    for row in rows
        .query_map([], |row| {
            let mut values = Vec::with_capacity(column_count);
            for index in 0..column_count {
                values.push(row.get::<_, String>(index)?);
            }
            Ok(values.join("\u{1}"))
        })
        .unwrap()
    {
        out.push_str(&row.unwrap());
        out.push('\n');
    }
    out
}

fn sha256_hex(digest: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn retained_digest(workspace: &Path, retained: &[&str]) -> String {
    let conn = open_read_only(workspace);
    let set = format!(
        "({})",
        retained
            .iter()
            .map(|id| format!("'{id}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut digest = String::new();
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    digest.push_str(&format!("user_version {user_version}\n"));
    let scoped_tables: [(&str, Option<String>); 16] = [
        ("scans", Some(format!("id IN {set}"))),
        ("resources", None),
        ("relationships", None),
        ("observations", Some(format!("scan_id IN {set}"))),
        ("evidence", Some(format!("scan_id IN {set}"))),
        (
            "relationship_evidence",
            Some(format!(
                "evidence_id IN (SELECT id FROM evidence WHERE scan_id IN {set})"
            )),
        ),
        ("scan_analyses", Some(format!("scan_id IN {set}"))),
        ("attack_paths", Some(format!("scan_id IN {set}"))),
        (
            "attack_path_edges",
            Some(format!(
                "attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id IN {set})"
            )),
        ),
        (
            "attack_path_evidence",
            Some(format!(
                "attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id IN {set})"
            )),
        ),
        ("findings", Some(format!("scan_id IN {set}"))),
        (
            "finding_paths",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_evidence",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_reasons",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_remediations",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        ("scan_diagnostics", Some(format!("scan_id IN {set}"))),
    ];
    for (table, filter) in scoped_tables {
        digest.push_str(&table_rows(&conn, table, filter.as_deref()));
    }
    sha256_hex(digest)
}

#[test]
fn supported_local_variants_and_coverage_limits() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = workspace.path();
    InitService::run(path).unwrap();
    configuration(path, "allow");
    scan(path, home.path(), "isolated-allow", ScanStatus::Complete);
    configuration(path, "ask");
    scan(path, home.path(), "isolated-ask", ScanStatus::Complete);
    let ask = diff(path, "isolated-ask");
    // Strict S032: allow->ask crosses DERIVED->UNKNOWN (ApprovalGated UNKNOWN is
    // knowledge, not environment), so the strict contract yields Mixed with both
    // paired_field_observation and knowledge_changed reasons present.
    let ask_changes = ask["attribution"]["graph_changes"].as_array().unwrap();
    assert!(ask_changes.iter().any(|c| c["classification"] == "mixed"
        && c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("paired_field_observation"))
        && c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("knowledge_changed"))));
    configuration(path, "deny");
    scan(path, home.path(), "isolated-deny", ScanStatus::Complete);
    let deny = diff(path, "isolated-deny");
    // Strict S032: ask->deny compares latest-two so UNKNOWN->BLOCKED is knowledge
    // per strict S032 (same DERIVED->UNKNOWN-state reasoning as allow->ask), so the
    // strict contract yields Mixed with both paired_field_observation and
    // knowledge_changed reasons present.
    let deny_changes = deny["attribution"]["graph_changes"].as_array().unwrap();
    assert!(deny_changes.iter().any(|c| c["classification"] == "mixed"
        && c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("paired_field_observation"))
        && c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("knowledge_changed"))));

    fs::create_dir_all(path.join(".claude")).unwrap();
    fs::write(
        path.join(".claude/settings.json"),
        json!({"permissions":{"allow":["Bash"]}}).to_string(),
    )
    .unwrap();
    scan(path, home.path(), "claude-allow", ScanStatus::Complete);
    fs::write(
        path.join(".claude/settings.json"),
        json!({"permissions":{"deny":["Bash"]}}).to_string(),
    )
    .unwrap();
    scan(path, home.path(), "claude-deny", ScanStatus::Complete);
    let claude = diff(path, "claude-deny");
    assert!(claude["attribution"]["graph_changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["classification"] == "observed_environment_change"));

    let mut config = json!({"permission":{"bash":"deny"},"mcp":{"servers":{"github":{"type":"local","command":["docker","run","ghcr.io/github/github-mcp-server:0.1.0"],"enabled":true}}}});
    fs::write(path.join("opencode.json"), config.to_string()).unwrap();
    scan(path, home.path(), "mcp-enabled", ScanStatus::Complete);
    config["mcp"]["servers"]["github"]["enabled"] = json!(false);
    fs::write(path.join("opencode.json"), config.to_string()).unwrap();
    scan(path, home.path(), "mcp-disabled", ScanStatus::Complete);
    let mcp = diff(path, "mcp-disabled");
    assert!(!mcp["attribution"]["graph_changes"]
        .as_array()
        .unwrap()
        .is_empty());

    configuration(path, "allow");
    scan(path, home.path(), "scope-baseline", ScanStatus::Complete);
    configuration(path, "deny");
    let reduced = ScanService::run_with_home_and_environment(
        path,
        None,
        Some(&[]),
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    assert_eq!(reduced.status, ScanStatus::Complete);
    let reduced_diff = diff(path, "reduced-home-scope");
    assert!(reduced_diff["attribution"]["graph_changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("coverage_changed"))));
    let db = Database::open_existing(&path.join(".pico/pico.db")).unwrap();
    let mut row = ScanRepo::new(db.connection())
        .get(&reduced.scan_id)
        .unwrap()
        .unwrap();
    row.metadata
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("coverage");
    ScanRepo::new(db.connection()).update(&row).unwrap();
    drop(db);
    let legacy = diff(path, "seeded-legacy-coverage");
    assert!(legacy["attribution"]["graph_changes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("coverage_unavailable"))));
    assert!(legacy["attribution"]["graph_changes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["disappearance_confirmed"] != true));
    capture("df35-local-variants-manifest.json", &serde_json::to_vec_pretty(&json!({"mode":"Real offline local discovery with empty environment, explicit home then absent home; only final legacy coverage removal is seeded metadata mutation","variants":["isolated OpenCode allow/ask/deny","Claude allow/deny","MCP enabled/disabled","COMPLETE with reduced home scope","seeded missing coverage"]})).unwrap());
}

#[test]
fn synthetic_provider_scope_authority_and_rating_variants() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = workspace.path();
    InitService::run(path).unwrap();
    let config = json!({"permission":{"bash":"allow"},"mcp":{"servers":{"github":{"type":"local","command":["docker","run","ghcr.io/github/github-mcp-server:0.1.0"]}}}});
    fs::write(path.join("opencode.json"), config.to_string()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let run = |provider| {
        ScanService::run_with_home_and_environment_and_provider(
            path,
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            Some(provider),
        )
        .unwrap()
    };
    for label in [
        "account-scope",
        "authority-scope",
        "credential-status",
        "authority-resolution",
        "resource-identity",
        "multiple-changes",
    ] {
        run(provider(path, home.path(), "variant-worker"));
        let mut changed = provider(path, home.path(), "variant-worker");
        match label {
            "account-scope" => changed.accounts[0].scope = ScopeState::OutOfScope,
            "authority-scope" => changed.authorities[0].scope_state = ScopeState::OutOfScope,
            "credential-status" => changed.credential_status = Some(CredentialStatus::Inactive),
            "authority-resolution" => {
                changed.authorities[0].resolution = AuthorityResolution::Unknown
            }
            "resource-identity" => changed = provider(path, home.path(), "replacement-worker"),
            "multiple-changes" => {
                changed.authorities[0].scope_state = ScopeState::OutOfScope;
                changed.authorities[0].resolution = AuthorityResolution::Unknown;
                changed.credential_status = Some(CredentialStatus::Inactive);
            }
            _ => unreachable!(),
        }
        run(changed);
        let result = diff(path, &format!("synthetic-{label}"));
        assert_eq!(result["status"], "ready");
        assert!(!result["attribution"]["graph_changes"]
            .as_array()
            .unwrap()
            .is_empty());
        for c in result["attribution"]["finding_changes"].as_array().unwrap() {
            assert_ne!(c["disappearance_confirmed"], true);
        }
    }
    let baseline = run(provider(path, home.path(), "variant-worker"));
    assert_eq!(baseline.finding_count, 1);
    let latest = run(provider(path, home.path(), "variant-worker"));
    assert_eq!(latest.finding_count, 1);
    let db = Database::open_existing(&path.join(".pico/pico.db")).unwrap();
    // Seeded rating-only mutation: change severity AND fingerprint (keeping
    // family_fingerprint unchanged) so Phase1 fingerprint== misses while Phase2
    // family pairing matches; classify(Greater,Equal)=>Weakened stays Unattributed.
    db.connection()
        .execute(
            "UPDATE findings SET severity = 'LOW', fingerprint = fingerprint || '-seeded' WHERE scan_id = ?1",
            [&latest.scan_id],
        )
        .unwrap();
    drop(db);
    let rating = diff(path, "seeded-rating-movement");
    assert_eq!(rating["findings"]["weakened"].as_array().unwrap().len(), 1);
    assert!(rating["attribution"]["finding_changes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["classification"] != "observed_environment_change"));
    capture("df35-provider-variants-manifest.json", &serde_json::to_vec_pretty(&json!({"mode":"Synthetic normalized Cloudflare provider results, real local discovery, no live calls","variants":["account scope","authority scope","credential status","authority resolution","resource identity","multiple simultaneous changes"],"seeded_mutation":"Final finding severity changed to LOW in persisted snapshot solely to exercise rating-only attribution; not observed environment change"})).unwrap());
}

#[test]
fn error_and_argument_capture_matrix() {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = workspace.path();
    InitService::run(path).unwrap();
    configuration(path, "allow");
    let older = scan(path, home.path(), "errors-older", ScanStatus::Complete);
    let newer = scan(path, home.path(), "errors-newer", ScanStatus::Complete);
    query(
        path,
        "reversed-pair",
        &["diff", &newer, &older],
        "diff_scans",
        json!({"from":newer,"to":older}),
        false,
    );
    query(
        path,
        "missing-pair",
        &["diff", "missing", &newer],
        "diff_scans",
        json!({"from":"missing","to":newer}),
        false,
    );
    fs::write(path.join("opencode.json"), "{ invalid").unwrap();
    let partial = scan(path, home.path(), "errors-partial", ScanStatus::Partial);
    query(
        path,
        "incomplete-pair",
        &["diff", &older, &partial],
        "diff_scans",
        json!({"from":older,"to":partial}),
        false,
    );
    let before = fs::read(path.join(".pico/pico.db")).unwrap();
    for (index, parameters) in [
        Value::Null,
        json!([]),
        json!({"from":"only"}),
        json!({"from":3,"to":"x"}),
        json!({"extra":true}),
    ]
    .into_iter()
    .enumerate()
    {
        let request = json!({"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"diff_scans","arguments":parameters}});
        let response = handle_line(&request.to_string(), path).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&response).unwrap()["error"]["code"],
            -32602
        );
        capture(
            &format!("df35-invalid-args-{index}-mcp-request.json"),
            request.to_string().as_bytes(),
        );
        capture(
            &format!("df35-invalid-args-{index}-mcp-response.json"),
            response.as_bytes(),
        );
    }
    command(path, "parser-error", &["diff", "--bogus", "--json"], false);
    assert_eq!(before, fs::read(path.join(".pico/pico.db")).unwrap());
    let db = Database::open_existing(&path.join(".pico/pico.db")).unwrap();
    db.connection()
        .pragma_update(None, "user_version", 999)
        .unwrap();
    drop(db);
    query(
        path,
        "unsupported-schema-history",
        &["history"],
        "list_history",
        json!({}),
        false,
    );
    query(
        path,
        "unsupported-schema-diff",
        &["diff"],
        "diff_scans",
        json!({}),
        false,
    );
}
