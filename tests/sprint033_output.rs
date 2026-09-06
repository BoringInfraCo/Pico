//! Public schema contract and actual JSON CLI behavior.
use pico::application::compare_contract::{
    DiffProvenance, DiffSideProvenance, CURRENT_COMPARISON_CONTRACT,
};
use pico::application::diff::{ComparedVia, DiffNotComparable, DiffNotComparableReason};
use pico::application::graph_diff::{GraphDelta, GraphDiff, GraphSubject, TypedValue};
use pico::application::{
    ComparisonAttribution, DiffFinding, FindingDiff, FindingDiffResult, Freshness, ScanBrief,
    ScanHistory, ScanSummary,
};
use pico::{output, shared::PicoError};
use serde_json::{json, Value};
use std::process::Command;

fn scan(id: &str) -> ScanBrief {
    ScanBrief {
        id: id.into(),
        status: "COMPLETE".into(),
        completed_at: Some("2026-09-05T00:00:00Z".into()),
    }
}
fn provenance() -> DiffProvenance {
    let side = DiffSideProvenance {
        pico_version: "0.1.0".into(),
        contract: Some(CURRENT_COMPARISON_CONTRACT),
    };
    DiffProvenance {
        from: side.clone(),
        to: side,
    }
}
fn ready() -> FindingDiff {
    FindingDiff {
        from: scan("older"),
        to: scan("newer"),
        newest_attempt: None,
        freshness: Freshness::LatestComplete,
        freshness_warning: None,
        compared_via: ComparedVia::ExplicitPair,
        provenance: provenance(),
        unchanged: vec![],
        appeared: vec![],
        disappeared: vec![],
        weakened: vec![],
        strengthened: vec![],
        uncertain: vec![],
        graph: GraphDiff::default(),
        attribution: ComparisonAttribution::default(),
    }
}
fn payloads() -> Vec<Value> {
    vec![
        serde_json::to_value(output::diff(&FindingDiffResult::NoCompleteScan)).unwrap(),
        serde_json::to_value(output::diff(&FindingDiffResult::NeedPrevious {
            newest_complete: scan("only"),
            newest_attempt: None,
        }))
        .unwrap(),
        serde_json::to_value(output::diff(&FindingDiffResult::NotComparable(
            DiffNotComparable {
                from: scan("older"),
                to: scan("newer"),
                newest_attempt: None,
                freshness: Freshness::LatestComplete,
                freshness_warning: None,
                compared_via: ComparedVia::ExplicitPair,
                provenance: provenance(),
                reason: DiffNotComparableReason::ContractChanged,
                gaps: vec![],
            },
        )))
        .unwrap(),
        serde_json::to_value(output::diff(&FindingDiffResult::Ready(ready()))).unwrap(),
        serde_json::to_value(output::history(&ScanHistory { scans: vec![] })).unwrap(),
        serde_json::to_value(output::error(
            "diff",
            &PicoError::database("SECRET_SENTINEL\n\u{1b}[0m"),
        ))
        .unwrap(),
    ]
}

// Validate every keyword used by our checked-in JSON Schema, failing closed
// for unknown validation keywords. This is deliberately a schema-subset
// validator for this artifact, not a general JSON Schema implementation.
fn valid(schema: &Value, value: &Value, root: &Value) -> bool {
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
        return valid(
            root.pointer(reference.as_str().unwrap().strip_prefix('#').unwrap())
                .unwrap(),
            value,
            root,
        );
    }
    if let Some(branches) = schema.get("oneOf") {
        if branches
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| valid(s, value, root))
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
            .any(|s| valid(s, value, root))
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
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
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
fn schema() -> Value {
    serde_json::from_str(include_str!("../docs/public/output-v1.schema.json")).unwrap()
}
fn check(value: &Value) {
    let schema = schema();
    assert!(valid(&schema, value, &schema), "schema rejected {value}");
}

#[test]
fn all_result_shapes_validate_and_match_frozen_goldens() {
    let values = payloads();
    for value in &values {
        check(value);
    }
    if std::env::var_os("PICO_UPDATE_GOLDENS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/goldens/sprint033/outcomes.json"
            ),
            serde_json::to_string_pretty(&values).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let golden: Value =
        serde_json::from_str(include_str!("goldens/sprint033/outcomes.json")).unwrap();
    assert_eq!(Value::Array(values), golden);
}

#[test]
fn schema_rejects_missing_extra_wrong_type_and_unknown_outcome() {
    let schema = schema();
    let good = payloads()[3].clone();
    for mutation in 0..5 {
        let mut value = good.clone();
        match mutation {
            0 => {
                value.as_object_mut().unwrap().remove("attribution");
            }
            1 => value["raw_snapshot"] = json!({"secret":"sentinel"}),
            2 => value["graph"]["resources"]["changed"] = json!(false),
            3 => value["status"] = json!("all_clear"),
            _ => value["provenance"]["from"]["contract"]["analysis_version"] = json!(-1),
        }
        assert!(
            !valid(&schema, &value, &schema),
            "mutation {mutation} accepted"
        );
    }
}

#[test]
fn safe_typed_projection_distinguishes_missing_null_and_redacted_objects() {
    let mut d = ready();
    d.graph.resources.changed.push(GraphSubject {
        canonical_key: "agent:opencode".into(),
        kind: "agent".into(),
        provider: None,
        name: None,
        state: None,
        first_seen_scan_id: "older".into(),
        last_seen_scan_id: "newer".into(),
        deltas: vec![
            GraphDelta {
                field: "enabled".into(),
                from: "unused".into(),
                to: "unused".into(),
                before: TypedValue::Missing,
                after: TypedValue::Null,
            },
            GraphDelta {
                field: "permission".into(),
                from: "unused".into(),
                to: "unused".into(),
                before: TypedValue::Value(json!("null")),
                after: TypedValue::Value(json!({"nested":"SECRET_SENTINEL"})),
            },
            GraphDelta {
                field: "granted_permissions".into(),
                from: "unused".into(),
                to: "unused".into(),
                before: TypedValue::Value(json!(["read"])),
                after: TypedValue::Value(json!(["ghp_SECRET_SENTINEL"])),
            },
        ],
    });
    d.disappeared.push(DiffFinding {
        id: "finding\u{1b}[31m".into(),
        fingerprint: "fp".into(),
        family_fingerprint: "family".into(),
        title: "token ghp_SECRET_SENTINEL".into(),
        severity: "HIGH".into(),
        confidence: "LOW".into(),
        cause: None,
    });
    let value = serde_json::to_value(output::diff(&FindingDiffResult::Ready(d))).unwrap();
    check(&value);
    let deltas = &value["graph"]["resources"]["changed"][0]["deltas"];
    assert_eq!(deltas[0]["before"], json!({"state":"missing"}));
    assert_eq!(deltas[0]["after"], json!({"state":"null"}));
    assert_eq!(deltas[1]["before"], json!({"state":"value","value":"null"}));
    assert_eq!(deltas[1]["after"], json!({"state":"redacted"}));
    assert_eq!(deltas[2]["after"], json!({"state":"redacted"}));
    assert_eq!(
        value["findings"]["not_observed"][0]["id"],
        "finding\\x1B[31m"
    );
    assert!(value["findings"].get("disappeared").is_none());
    assert!(!value.to_string().contains("SECRET_SENTINEL"));
    assert_eq!(value["freshness"], "not_assessed");
}

#[test]
fn history_sorting_and_complete_window_use_distinct_chronologies() {
    let summary = |id: &str, started: &str, completed: &str| ScanSummary {
        id: id.into(),
        status: "COMPLETE".into(),
        started_at: Some(started.into()),
        completed_at: Some(completed.into()),
        finding_count: 0,
    };
    let value = serde_json::to_value(output::history(&ScanHistory {
        scans: vec![summary("b", "1", "3"), summary("a", "1", "4")],
    }))
    .unwrap();
    check(&value);
    assert_eq!(value["scans"][0]["id"], "a");
    assert_eq!(value["oldest_complete_scan_id"], "b");
    assert_eq!(value["newest_complete_scan_id"], "a");
    assert_eq!(value["complete_scan_count"], 2);
    assert_eq!(value["retained_history_only"], true);
}

#[test]
fn cli_json_is_deterministic_read_only_and_parser_errors_stay_text() {
    let workspace = tempfile::tempdir().unwrap();
    pico::application::InitService::run(workspace.path()).unwrap();
    let db_path = workspace.path().join(".pico/pico.db");
    let before = std::fs::read(&db_path).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pico"))
            .current_dir(workspace.path())
            .args(args)
            .output()
            .unwrap()
    };
    for args in [vec!["diff", "--json"], vec!["history", "--json"]] {
        let first = run(&args);
        let second = run(&args);
        assert!(first.status.success());
        assert!(first.stderr.is_empty());
        assert_eq!(first.stdout, second.stdout);
        check(&serde_json::from_slice(&first.stdout).unwrap());
        assert_eq!(std::fs::read(&db_path).unwrap(), before);
    }
    let invalid = run(&["diff", "SECRET_SENTINEL", "--json"]);
    assert_eq!(invalid.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    check(&error);
    assert_eq!(error["error"]["code"], "usage_error");
    assert!(!String::from_utf8_lossy(&invalid.stdout).contains("SECRET_SENTINEL"));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("SECRET_SENTINEL"));
    let parser = run(&["diff", "--json", "--unknown"]);
    assert_eq!(parser.status.code(), Some(2));
    assert!(parser.stdout.is_empty());
    assert!(!parser.stderr.is_empty());
    assert_eq!(std::fs::read(&db_path).unwrap(), before);
}

#[test]
fn missing_database_returns_redacted_json_without_creating_state() {
    let workspace = tempfile::tempdir().unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_pico"))
        .current_dir(workspace.path())
        .args(["history", "--json"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    check(&value);
    assert_eq!(value["error"]["code"], "database_error");
    assert!(!workspace.path().join(".pico").exists());
}

#[test]
fn attribution_projects_both_sides_and_all_closed_categories() {
    use pico::application::attribution::CoverageState;
    use pico::application::{AttributionClass, ChangeAttribution, SideEvidence};
    let mut d = ready();
    for (classification, coverage) in [
        (
            AttributionClass::ObservedEnvironmentChange,
            CoverageState::Inspected,
        ),
        (AttributionClass::EvidenceChange, CoverageState::Incomplete),
        (AttributionClass::Mixed, CoverageState::NotAttempted),
        (AttributionClass::Unattributed, CoverageState::Unknown),
    ] {
        d.attribution.graph_changes.push(ChangeAttribution {
            key: "agent:claude".into(),
            lifecycle: "disappeared".into(),
            classification,
            reasons: vec!["coverage_not_comparable".into()],
            before: SideEvidence {
                source_types: vec!["claude_config".into()],
                coverage,
                evidence_ids: vec!["ev-old".into()],
                supported_fields: vec!["enabled".into()],
            },
            after: SideEvidence {
                source_types: vec![],
                coverage: CoverageState::Unknown,
                evidence_ids: vec![],
                supported_fields: vec![],
            },
            disappearance_confirmed: false,
        });
    }
    let value = serde_json::to_value(output::diff(&FindingDiffResult::Ready(d))).unwrap();
    check(&value);
    let changes = value["attribution"]["graph_changes"].as_array().unwrap();
    for (index, (class, coverage)) in [
        ("observed_environment_change", "inspected"),
        ("evidence_change", "incomplete"),
        ("mixed", "not_attempted"),
        ("unattributed", "unknown"),
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(changes[index]["classification"], *class);
        assert_eq!(changes[index]["lifecycle"], "not_observed");
        assert_eq!(
            changes[index]["before"],
            json!({"source_types":["claude_config"],"evidence_ids":["ev-old"],"supported_fields":["enabled"],"coverage":coverage})
        );
        assert_eq!(
            changes[index]["after"],
            json!({"source_types":[],"evidence_ids":[],"supported_fields":[],"coverage":"unknown"})
        );
        assert_eq!(changes[index]["disappearance_confirmed"], false);
    }
    let schema = schema();
    for field in ["classification", "before"] {
        let mut malformed = value.clone();
        malformed["attribution"]["graph_changes"][0][field] = json!("unknown_future_value");
        assert!(!valid(&schema, &malformed, &schema));
    }
}

#[test]
fn public_error_categories_never_include_internal_details() {
    for (error, code) in [
        (PicoError::usage("SECRET_SENTINEL"), "usage_error"),
        (PicoError::database("SECRET_SENTINEL"), "database_error"),
        (PicoError::migration("SECRET_SENTINEL"), "database_error"),
        (PicoError::io("SECRET_SENTINEL"), "io_error"),
        (PicoError::scan("SECRET_SENTINEL"), "database_error"),
        (PicoError::init("SECRET_SENTINEL"), "database_error"),
    ] {
        let value = serde_json::to_value(output::error("diff", &error)).unwrap();
        check(&value);
        assert_eq!(value["error"]["code"], code);
        assert!(!value.to_string().contains("SECRET_SENTINEL"));
    }
}

#[test]
fn provenance_gaps_and_latest_freshness_remain_explicit() {
    use pico::application::compare_contract::{
        ComparisonContractField, ComparisonProvenanceGap, DiffSide,
    };
    for (reason, expected) in [
        (
            DiffNotComparableReason::ProvenanceUnavailable,
            "provenance_unavailable",
        ),
        (DiffNotComparableReason::ContractChanged, "contract_changed"),
        (
            DiffNotComparableReason::ContractUnsupported,
            "contract_unsupported",
        ),
    ] {
        let mut provenance = provenance();
        provenance.from.contract = None;
        let d = DiffNotComparable {
            from: scan("older"),
            to: scan("newer"),
            newest_attempt: Some(ScanBrief {
                id: "failed".into(),
                status: "FAILED".into(),
                completed_at: None,
            }),
            freshness: Freshness::NewerIncomplete,
            freshness_warning: None,
            compared_via: ComparedVia::LatestTwo,
            provenance,
            reason,
            gaps: vec![ComparisonProvenanceGap {
                side: DiffSide::From,
                field: ComparisonContractField::GraphSnapshotVersion,
            }],
        };
        let value =
            serde_json::to_value(output::diff(&FindingDiffResult::NotComparable(d))).unwrap();
        check(&value);
        assert_eq!(value["reason"], expected);
        assert_eq!(value["freshness"], "newer_incomplete_attempt");
        assert_eq!(value["compared_via"], "latest_two");
        assert_eq!(value["provenance"]["from"]["contract"], Value::Null);
        assert_eq!(
            value["gaps"],
            json!([{"side":"from","field":"graph_snapshot_version"}])
        );
        assert_eq!(value["newest_attempt"]["completed_at"], Value::Null);
    }
}

#[test]
fn schema_rejects_raw_objects_and_unknown_validation_rules() {
    let root = schema();
    let typed = &root["$defs"]["typed_value"];
    for bad in [
        json!({"state":"value","value":{"raw":"secret"}}),
        json!({"state":"missing","value":null}),
        json!({"state":"null","value":"null"}),
        json!({"state":"future"}),
        json!({"state":"value","value":[1]}),
    ] {
        assert!(!valid(typed, &bad, &root));
    }
    assert!(std::panic::catch_unwind(|| valid(
        &json!({"pattern":"^closed$"}),
        &json!("anything"),
        &root
    ))
    .is_err());
}
