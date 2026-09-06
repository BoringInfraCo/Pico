//! Versioned interpretation of persisted observations. No network or discovery.
use crate::application::graph_diff::{typed_field, TypedValue};
use crate::application::{FindingDiff, GraphSubject};
use crate::discovery::coverage::CoverageEntry;
pub use crate::discovery::coverage::CoverageState;
use crate::domain::{Evidence, Scan};
use crate::persistence::EvidenceRepo;
use crate::shared::PicoError;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionClass {
    ObservedEnvironmentChange,
    EvidenceChange,
    Mixed,
    Unattributed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SideEvidence {
    pub source_types: Vec<String>,
    pub coverage: CoverageState,
    pub evidence_ids: Vec<String>,
    pub supported_fields: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeAttribution {
    pub key: String,
    pub lifecycle: String,
    pub classification: AttributionClass,
    pub reasons: Vec<String>,
    pub before: SideEvidence,
    pub after: SideEvidence,
    pub disappearance_confirmed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComparisonAttribution {
    pub version: u32,
    pub graph_changes: Vec<ChangeAttribution>,
    pub finding_changes: Vec<ChangeAttribution>,
}
impl Default for ComparisonAttribution {
    fn default() -> Self {
        Self {
            version: 1,
            graph_changes: vec![],
            finding_changes: vec![],
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    entries: Vec<CoverageEntry>,
    provider_enumeration: String,
    credential_enumeration: String,
}
fn manifest(scan: &Scan) -> Option<Manifest> {
    let manifest: Manifest =
        serde_json::from_value(scan.metadata.as_ref()?.get("coverage")?.clone()).ok()?;
    let mut scopes = BTreeSet::new();
    let valid = manifest.version == 1
        && manifest.provider_enumeration == "unknown"
        && manifest.credential_enumeration == "unknown"
        && !manifest.entries.is_empty()
        && manifest.entries.iter().all(|entry| {
            let known_scope = match entry.provider.as_str() {
                "opencode" => matches!(
                    entry.scope.as_str(),
                    "user"
                        | "user:opencode.json"
                        | "user:opencode.jsonc"
                        | "project:opencode.json"
                        | "project:opencode.jsonc"
                        | "project:.opencode/opencode.json"
                        | "project:.opencode/opencode.jsonc"
                ),
                "claude" => matches!(
                    entry.scope.as_str(),
                    "user"
                        | "user:.claude/settings.json"
                        | "project:.claude/settings.json"
                        | "project:.claude/settings.local.json"
                        | "project:.mcp.json"
                ),
                _ => false,
            };
            let fingerprint = if entry.scope == "user" {
                entry.scope_fingerprint == "not_attempted"
                    && entry.state == CoverageState::NotAttempted
            } else {
                entry.scope_fingerprint.len() == 64
                    && entry
                        .scope_fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit())
            };
            known_scope
                && fingerprint
                && entry.operation == "static_config"
                && scopes.insert((&entry.provider, &entry.scope))
        });
    valid.then_some(manifest)
}
fn coverage(scan: &Scan, sources: &[&Evidence]) -> CoverageState {
    let Some(manifest) = manifest(scan) else {
        return CoverageState::Unknown;
    };
    let providers: BTreeSet<&str> = sources
        .iter()
        .filter_map(|e| {
            if e.source_type.starts_with("opencode_") {
                Some("opencode")
            } else if e.source_type.starts_with("claude_") {
                Some("claude")
            } else {
                None
            }
        })
        .collect();
    if providers.is_empty() {
        return CoverageState::Unknown;
    }
    let entries: Vec<_> = manifest
        .entries
        .iter()
        .filter(|entry| providers.contains(entry.provider.as_str()))
        .collect();
    if entries.is_empty() {
        CoverageState::Unknown
    } else if entries
        .iter()
        .any(|entry| entry.state == CoverageState::Incomplete)
    {
        CoverageState::Incomplete
    } else if entries
        .iter()
        .any(|entry| entry.state == CoverageState::NotAttempted)
    {
        CoverageState::NotAttempted
    } else if entries
        .iter()
        .all(|entry| entry.state == CoverageState::Inspected)
    {
        CoverageState::Inspected
    } else {
        CoverageState::Unknown
    }
}
fn side(scan: &Scan, evidence: &[Evidence], key: &str) -> SideEvidence {
    let exact: Vec<_> = evidence
        .iter()
        .filter(|item| item.subject == key && item.scan_id == scan.id)
        .collect();
    let source_types = exact
        .iter()
        .map(|item| safe_source(&item.source_type))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let evidence_ids = exact
        .iter()
        .map(|e| e.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let supported_fields = exact
        .iter()
        .filter(|e| affirmative(e))
        .filter_map(|e| e.metadata.as_ref().and_then(serde_json::Value::as_object))
        .flat_map(|fields| fields.keys())
        .filter(|field| environment_field(field) || evidence_field(field))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    SideEvidence {
        source_types,
        coverage: coverage(scan, &exact),
        evidence_ids,
        supported_fields,
    }
}
fn safe_source(source: &str) -> String {
    // Source types are producer identifiers, never a channel for arbitrary
    // persisted text. Unknown values stay structural and cannot echo secrets.
    match source {
        "opencode_config"
        | "opencode_effective_permission"
        | "claude_settings"
        | "claude_effective_permission"
        | "environment"
        | "environment_variable"
        | "cloudflare_api"
        | "github_api"
        | "github_authority"
        | "cloudflare_authority"
        | "cloudflare_authority_resolution"
        | "github_authority_resolution"
        | "cloudflare_account_inventory"
        | "cloudflare_worker_inventory"
        | "github_mcp_influence"
        | "opencode_credential_reachability"
        | "claude_credential_reachability"
        | "cloudflare_credential_reachability"
        | "mcp_config"
        | "mcp_tool_catalog"
        | "opencode_mcp_config"
        | "claude_mcp_config" => source.to_string(),
        _ => "other".into(),
    }
}
fn known(value: &TypedValue) -> bool {
    match value {
        TypedValue::Missing | TypedValue::Null => false,
        TypedValue::Value(serde_json::Value::String(value)) => !matches!(
            value.to_ascii_uppercase().as_str(),
            "UNKNOWN" | "UNRESOLVED" | "UNAVAILABLE" | "UNSUPPORTED" | "NOT_ATTEMPTED" | ""
        ),
        TypedValue::Value(_) => true,
    }
}
fn environment_field(field: &str) -> bool {
    matches!(
        field,
        "effective_permission"
            | "effective_state"
            | "scope"
            | "runtime_mode"
            | "boundary_kind"
            | "enabled"
            | "transport"
            | "permission"
            | "permission_pattern"
            | "granted_permissions"
            | "zone_scoped"
            | "permission_state"
            | "account_scope_state"
    )
}
fn evidence_field(field: &str) -> bool {
    matches!(
        field,
        "authority_resolution"
            | "credential_status"
            | "unknown_reasons"
            | "validity"
            | "environment_reachability"
            | "identity_precision"
    )
}
fn affirmative(item: &Evidence) -> bool {
    item.class != crate::domain::EvidenceClass::Inferred
        && item.sensitivity != crate::domain::Sensitivity::Secret
        && !matches!(
            item.freshness.as_deref(),
            Some("STALE" | "UNKNOWN" | "AGING")
        )
}
fn supported_pair(
    from: &Scan,
    to: &Scan,
    before: &[Evidence],
    after: &[Evidence],
    key: &str,
    delta: &crate::application::GraphDelta,
) -> bool {
    before
        .iter()
        .filter(|e| {
            e.scan_id == from.id
                && e.subject == key
                && affirmative(e)
                && typed_field(e.metadata.as_ref(), &delta.field) == delta.before
        })
        .any(|left| {
            after.iter().any(|right| {
                right.scan_id == to.id
                    && right.subject == key
                    && affirmative(right)
                    && right.source_type == left.source_type
                    && right.source_locator == left.source_locator
                    && typed_field(right.metadata.as_ref(), &delta.field) == delta.after
            })
        })
}
fn same_local_scope(from: &Scan, to: &Scan, evidence: &[Evidence], key: &str) -> bool {
    let local = evidence.iter().any(|e| {
        e.subject == key
            && (e.source_type.starts_with("opencode_")
                || e.source_type.starts_with("claude_")
                || e.source_type == "github_mcp_influence")
    });
    if !local {
        return true;
    }
    match (manifest(from), manifest(to)) {
        (None, None) => {
            from.metadata
                .as_ref()
                .is_none_or(|m| m.get("coverage").is_none())
                && to
                    .metadata
                    .as_ref()
                    .is_none_or(|m| m.get("coverage").is_none())
        } // True legacy only.
        (Some(left), Some(right)) => {
            left.entries == right.entries
                && left
                    .entries
                    .iter()
                    .all(|e| e.state == CoverageState::Inspected)
        }
        _ => false,
    }
}
fn classify(
    subject: &GraphSubject,
    lifecycle: &str,
    from: &Scan,
    to: &Scan,
    before: &[Evidence],
    after: &[Evidence],
) -> ChangeAttribution {
    let mut environment = false;
    let mut evidence = false;
    let mut reasons = BTreeSet::new();
    let before_side = side(from, before, &subject.canonical_key);
    let after_side = side(to, after, &subject.canonical_key);
    if lifecycle != "changed" {
        reasons.insert("observation_presence_only".to_string());
        if before_side.coverage != after_side.coverage
            || before_side.source_types != after_side.source_types
        {
            evidence = true;
            reasons.insert("observation_support_changed".into());
        }
        if lifecycle == "disappeared" {
            reasons.insert("absence_not_proven".into());
        }
    }
    if !same_local_scope(from, to, before, &subject.canonical_key) {
        reasons.insert(
            if manifest(from).is_some() && manifest(to).is_some() {
                "coverage_changed"
            } else {
                "coverage_unavailable"
            }
            .into(),
        );
        evidence = true;
    }
    for delta in &subject.deltas {
        if !known(&delta.before) || !known(&delta.after) || evidence_field(&delta.field) {
            evidence = true;
            reasons.insert("knowledge_changed".into());
        } else if environment_field(&delta.field)
            && supported_pair(from, to, before, after, &subject.canonical_key, delta)
            && same_local_scope(from, to, before, &subject.canonical_key)
        {
            environment = true;
            reasons.insert("paired_field_observation".into());
        } else {
            reasons.insert(
                if delta.field == "name" {
                    "display_only"
                } else {
                    "field_support_unavailable"
                }
                .into(),
            );
        }
    }
    let classification = match (environment, evidence) {
        (true, true) => AttributionClass::Mixed,
        (true, false) => AttributionClass::ObservedEnvironmentChange,
        (false, true) => AttributionClass::EvidenceChange,
        _ => AttributionClass::Unattributed,
    };
    ChangeAttribution {
        key: subject.canonical_key.clone(),
        lifecycle: lifecycle.into(),
        classification,
        reasons: reasons.into_iter().collect(),
        before: before_side,
        after: after_side,
        disappearance_confirmed: false,
    }
}

pub fn attach_attribution(
    conn: &Connection,
    from: &Scan,
    to: &Scan,
    diff: &mut FindingDiff,
) -> Result<(), PicoError> {
    let before = EvidenceRepo::new(conn).get_for_scan(&from.id)?;
    let after = EvidenceRepo::new(conn).get_for_scan(&to.id)?;
    let mut result = ComparisonAttribution::default();
    for subjects in [&diff.graph.resources, &diff.graph.relationships] {
        for (lifecycle, bucket) in [
            ("first_seen", &subjects.first_seen),
            ("reappeared", &subjects.reappeared),
            ("changed", &subjects.changed),
            ("disappeared", &subjects.disappeared),
        ] {
            for subject in bucket {
                result
                    .graph_changes
                    .push(classify(subject, lifecycle, from, to, &before, &after));
            }
        }
    }
    result
        .graph_changes
        .sort_by(|a, b| (&a.key, &a.lifecycle).cmp(&(&b.key, &b.lifecycle)));
    for (lifecycle, bucket) in [
        ("appeared", &diff.appeared),
        ("disappeared", &diff.disappeared),
    ] {
        for finding in bucket {
            result.finding_changes.push(finding_attribution(
                conn,
                &result.graph_changes,
                &finding.id,
                &finding.fingerprint,
                lifecycle,
            )?);
        }
    }
    for (lifecycle, bucket) in [
        ("weakened", &diff.weakened),
        ("strengthened", &diff.strengthened),
        ("uncertain", &diff.uncertain),
    ] {
        for pair in bucket {
            let mut value = finding_attribution(
                conn,
                &result.graph_changes,
                &pair.to.id,
                &pair.to.fingerprint,
                lifecycle,
            )?;
            let older = finding_attribution(
                conn,
                &result.graph_changes,
                &pair.from.id,
                &pair.to.fingerprint,
                lifecycle,
            )?;
            if value.classification != older.classification {
                value.classification = AttributionClass::Unattributed;
                value.reasons.push("multiple_possible_causes".into());
            }
            let keys = crate::application::cause::load_finding_keys(conn, &pair.from.id)?;
            let new_keys = crate::application::cause::load_finding_keys(conn, &pair.to.id)?;
            if pair.from.severity == pair.to.severity
                && pair.from.confidence != pair.to.confidence
                && keys.keys == new_keys.keys
                && !keys.keys.is_empty()
                && support_signature(&before, &keys.keys)
                    != support_signature(&after, &new_keys.keys)
            {
                value.classification = match value.classification {
                    AttributionClass::ObservedEnvironmentChange | AttributionClass::Mixed => {
                        AttributionClass::Mixed
                    }
                    _ => AttributionClass::EvidenceChange,
                };
                value
                    .reasons
                    .push("finding_evidence_support_changed".into());
            }
            result.finding_changes.push(value);
        }
    }
    result
        .finding_changes
        .sort_by(|a, b| (&a.key, &a.lifecycle).cmp(&(&b.key, &b.lifecycle)));
    // S027 prose is contextual; unsupported absence must not retain its earlier
    // affirmative 'no longer present' wording as a remediation claim.
    for finding in &mut diff.disappeared {
        if let Some(cause) = &mut finding.cause {
            if cause.summary.contains("no longer present") {
                cause.summary =
                    "Finding not observed in the newer scan; remediation is not established".into();
            }
        }
    }
    diff.attribution = result;
    Ok(())
}
fn support_signature(evidence: &[Evidence], keys: &BTreeSet<String>) -> BTreeSet<String> {
    evidence
        .iter()
        .filter(|e| keys.contains(&e.subject))
        .map(|e| {
            let fields: std::collections::BTreeMap<_, _> = e
                .metadata
                .as_ref()
                .and_then(serde_json::Value::as_object)
                .into_iter()
                .flatten()
                .filter(|(key, _)| evidence_field(key))
                .collect();
            serde_json::json!([
                e.subject,
                e.source_type,
                e.source_locator,
                e.class,
                e.freshness,
                fields
            ])
            .to_string()
        })
        .collect()
}

fn finding_attribution(
    conn: &Connection,
    graph: &[ChangeAttribution],
    id: &str,
    key: &str,
    lifecycle: &str,
) -> Result<ChangeAttribution, PicoError> {
    let keys = crate::application::cause::load_finding_keys(conn, id)?;
    let hits: Vec<_> = graph
        .iter()
        .filter(|change| keys.keys.contains(&change.key))
        .collect();
    let selected = if hits.len() == 1 { Some(hits[0]) } else { None };
    if let Some(selected) = selected {
        let mut result = selected.clone();
        result.key = key.into();
        result.lifecycle = lifecycle.into();
        result.disappearance_confirmed = false;
        if lifecycle == "disappeared" {
            result
                .reasons
                .push("finding_absence_not_remediation".into());
        }
        return Ok(result);
    }
    let merge_side = |before: bool| {
        let sides: Vec<_> = hits
            .iter()
            .map(|hit| if before { &hit.before } else { &hit.after })
            .collect();
        SideEvidence {
            coverage: sides
                .first()
                .map(|first| first.coverage)
                .filter(|coverage| sides.iter().all(|side| side.coverage == *coverage))
                .unwrap_or(CoverageState::Unknown),
            source_types: sides
                .iter()
                .flat_map(|side| side.source_types.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            evidence_ids: sides
                .iter()
                .flat_map(|side| side.evidence_ids.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            supported_fields: sides
                .iter()
                .flat_map(|side| side.supported_fields.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    };
    let has_environment = hits.iter().any(|hit| {
        matches!(
            hit.classification,
            AttributionClass::ObservedEnvironmentChange | AttributionClass::Mixed
        )
    });
    let has_evidence = hits.iter().any(|hit| {
        matches!(
            hit.classification,
            AttributionClass::EvidenceChange | AttributionClass::Mixed
        )
    });
    let classification = if has_environment && has_evidence {
        AttributionClass::Mixed
    } else {
        AttributionClass::Unattributed
    };
    Ok(ChangeAttribution {
        key: key.into(),
        lifecycle: lifecycle.into(),
        classification,
        reasons: vec![if hits.is_empty() {
            "no_supported_graph_cause"
        } else {
            "multiple_possible_causes"
        }
        .into()],
        before: merge_side(true),
        after: merge_side(false),
        disappearance_confirmed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EvidenceClass, Sensitivity};
    use serde_json::json;

    fn scan() -> Scan {
        Scan::start("0.1.0").unwrap()
    }
    fn observation(scan: &Scan, key: &str, field: &str, value: serde_json::Value) -> Evidence {
        let mut item = Evidence::new(
            &scan.id,
            EvidenceClass::Direct,
            "cloudflare_api",
            "same_operation",
            key,
            "safe fact",
            Sensitivity::Internal,
        )
        .unwrap();
        item.metadata = Some(json!({field: value}));
        item
    }
    fn subject(field: &str, before: serde_json::Value, after: serde_json::Value) -> GraphSubject {
        GraphSubject {
            canonical_key: "exact:key".into(),
            kind: "can_mutate".into(),
            provider: None,
            name: None,
            state: None,
            first_seen_scan_id: "old".into(),
            last_seen_scan_id: "new".into(),
            deltas: vec![crate::application::GraphDelta {
                field: field.into(),
                from: before.to_string(),
                to: after.to_string(),
                before: TypedValue::Value(before),
                after: TypedValue::Value(after),
            }],
        }
    }
    #[test]
    fn affirmative_policy_pairs_need_exact_subject_and_fresh_support() {
        let from = scan();
        let to = scan();
        let change = subject("permission_state", json!("READ"), json!("WRITE"));
        let left = observation(&from, "exact:key", "permission_state", json!("READ"));
        let mut right = observation(&to, "exact:key", "permission_state", json!("WRITE"));
        let classify_pair = |right: &Evidence| {
            classify(
                &change,
                "changed",
                &from,
                &to,
                std::slice::from_ref(&left),
                std::slice::from_ref(right),
            )
            .classification
        };
        assert_eq!(
            classify_pair(&right),
            AttributionClass::ObservedEnvironmentChange
        );
        right.subject = "prefix:exact:key:suffix".into();
        assert_eq!(classify_pair(&right), AttributionClass::Unattributed);
        right.subject = "exact:key".into();
        right.freshness = Some("STALE".into());
        assert_eq!(classify_pair(&right), AttributionClass::Unattributed);
        right.freshness = None;
        right.class = EvidenceClass::Inferred;
        assert_eq!(classify_pair(&right), AttributionClass::Unattributed);
    }
    #[test]
    fn unknown_recovery_is_evidence_and_mixed_requires_both_components() {
        let from = scan();
        let to = scan();
        let mut change = subject("permission_state", json!("UNKNOWN"), json!("WRITE"));
        assert_eq!(
            classify(&change, "changed", &from, &to, &[], &[]).classification,
            AttributionClass::EvidenceChange
        );
        change.deltas.extend(
            subject(
                "granted_permissions",
                json!(["read"]),
                json!(["read", "write"]),
            )
            .deltas,
        );
        let left = observation(&from, "exact:key", "granted_permissions", json!(["read"]));
        let right = observation(
            &to,
            "exact:key",
            "granted_permissions",
            json!(["read", "write"]),
        );
        assert_eq!(
            classify(&change, "changed", &from, &to, &[left], &[right]).classification,
            AttributionClass::Mixed
        );
    }
    #[test]
    fn absence_is_not_remediation_even_for_complete_scans() {
        let from = scan().complete().unwrap();
        let to = scan().complete().unwrap();
        let mut change = subject("enabled", json!(true), json!(false));
        change.deltas.clear();
        let result = classify(&change, "disappeared", &from, &to, &[], &[]);
        assert!(!result.disappearance_confirmed);
        assert!(result.reasons.contains(&"absence_not_proven".into()));
        assert_eq!(result.classification, AttributionClass::Unattributed);
    }
    #[test]
    fn malformed_coverage_is_not_legacy() {
        let from = scan();
        let mut to = scan();
        let mut item = observation(&from, "exact:key", "permission", json!("allow"));
        item.source_type = "opencode_effective_permission".into();
        assert!(same_local_scope(&from, &to, &[item.clone()], "exact:key"));
        to.metadata = Some(json!({"coverage": {"version": 999}}));
        assert!(!same_local_scope(&from, &to, &[item], "exact:key"));
    }
    #[test]
    fn wrong_scan_cannot_support_field_or_side() {
        let from = scan();
        let to = scan();
        let foreign = scan();
        let change = subject("permission_state", json!("READ"), json!("WRITE"));
        let left = observation(&from, "exact:key", "permission_state", json!("READ"));
        let right = observation(&foreign, "exact:key", "permission_state", json!("WRITE"));
        let result = classify(&change, "changed", &from, &to, &[left], &[right]);
        assert_eq!(result.classification, AttributionClass::Unattributed);
        assert!(result.after.evidence_ids.is_empty());
    }
    #[test]
    fn scope_requires_valid_unique_fingerprints_and_inspected_entries() {
        let mut from = scan();
        let mut to = scan();
        let entry = CoverageEntry::candidate(
            "opencode",
            "project:opencode.json",
            std::path::Path::new("/nonexistent/s032/opencode.json"),
        );
        let metadata = json!({"coverage":{"version":1,"entries":[entry],"provider_enumeration":"unknown","credential_enumeration":"unknown"}});
        from.metadata = Some(metadata.clone());
        to.metadata = Some(metadata.clone());
        let mut item = observation(&from, "exact:key", "permission", json!("allow"));
        item.source_type = "opencode_effective_permission".into();
        assert!(same_local_scope(&from, &to, &[item.clone()], "exact:key"));
        to.metadata.as_mut().unwrap()["coverage"]["entries"][0]["scope_fingerprint"] = json!("bad");
        assert!(manifest(&to).is_none());
        to.metadata = Some(metadata.clone());
        let duplicate = to.metadata.as_ref().unwrap()["coverage"]["entries"][0].clone();
        to.metadata.as_mut().unwrap()["coverage"]["entries"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(manifest(&to).is_none());
        to.metadata = Some(metadata);
        to.metadata.as_mut().unwrap()["coverage"]["entries"][0]["state"] = json!("incomplete");
        assert!(!same_local_scope(&from, &to, &[item], "exact:key"));
    }
    #[test]
    fn support_signature_ignores_ids_but_detects_evidence_quality() {
        let from = scan();
        let to = scan();
        let left = observation(&from, "exact:key", "permission_state", json!("WRITE"));
        let mut right = observation(&to, "exact:key", "permission_state", json!("WRITE"));
        let keys = BTreeSet::from(["exact:key".into()]);
        assert_eq!(
            support_signature(&[left.clone()], &keys),
            support_signature(&[right.clone()], &keys)
        );
        right.class = EvidenceClass::Inferred;
        assert_ne!(
            support_signature(&[left], &keys),
            support_signature(&[right], &keys)
        );
    }
}
