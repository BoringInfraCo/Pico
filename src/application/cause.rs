//! Causal explanation of Finding diffs (SPRINT-027.md).
//!
//! Joins a Finding's persisted attack-path keys to S026 GraphDiff.
//! Does not re-run discovery. PARTIAL scans are never operands.

use std::collections::{BTreeSet, HashSet};

use rusqlite::Connection;
use serde::Serialize;

use crate::application::graph_diff::{GraphDelta, GraphDiff, GraphSubject};
use crate::application::DiffFinding;
use crate::persistence::{
    AttackPathRepo, EvidenceRepo, FindingRepo, RelationshipRepo, ResourceRepo,
};
use crate::shared::PicoError;

const UNKNOWN_CAUSE: &str = "No single observed graph cause was identified";

/// Smallest observed graph change that explains a Finding delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingCause {
    pub summary: String,
    pub graph_key: Option<String>,
    pub field: Option<String>,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
    pub evidence_source_types: Vec<String>,
}

struct FindingKeys {
    source: Option<String>,
    actor: Option<String>,
    sink: Option<String>,
    keys: BTreeSet<String>,
}

/// Attach a primary cause to appeared and disappeared Findings.
pub fn attach_causes(
    conn: &Connection,
    from_scan_id: &str,
    to_scan_id: &str,
    appeared: &mut [DiffFinding],
    disappeared: &mut [DiffFinding],
    graph: &GraphDiff,
) -> Result<(), PicoError> {
    let mut appeared_keys = Vec::new();
    for finding in appeared.iter() {
        appeared_keys.push(load_finding_keys(conn, &finding.id)?);
    }
    let mut disappeared_keys = Vec::new();
    for finding in disappeared.iter() {
        disappeared_keys.push(load_finding_keys(conn, &finding.id)?);
    }

    let mut used_appeared = HashSet::new();
    for (index, from_keys) in disappeared_keys.iter().enumerate() {
        if let Some(pair) = pair_sink_flip(from_keys, &appeared_keys, &used_appeared) {
            used_appeared.insert(pair);
            let cause = sink_identity_cause(
                conn,
                from_scan_id,
                to_scan_id,
                from_keys.sink.as_deref().unwrap_or(""),
                appeared_keys[pair].sink.as_deref().unwrap_or(""),
            )?;
            disappeared[index].cause = Some(cause.clone());
            appeared[pair].cause = Some(cause);
        }
    }

    for (index, keys) in disappeared_keys.iter().enumerate() {
        if disappeared[index].cause.is_some() {
            continue;
        }
        disappeared[index].cause = Some(ranked_cause(conn, from_scan_id, to_scan_id, keys, graph)?);
    }
    for (index, keys) in appeared_keys.iter().enumerate() {
        if appeared[index].cause.is_some() {
            continue;
        }
        appeared[index].cause = Some(ranked_cause(conn, from_scan_id, to_scan_id, keys, graph)?);
    }
    Ok(())
}

fn load_finding_keys(conn: &Connection, finding_id: &str) -> Result<FindingKeys, PicoError> {
    let finding_repo = FindingRepo::new(conn);
    let paths_repo = AttackPathRepo::new(conn);
    let resources = ResourceRepo::new(conn);
    let relationships = RelationshipRepo::new(conn);
    let links = finding_repo.list_paths(finding_id)?;
    let mut keys = FindingKeys {
        source: None,
        actor: None,
        sink: None,
        keys: BTreeSet::new(),
    };
    for link in links {
        let Some(path) = paths_repo.get(&link.attack_path_id)? else {
            continue;
        };
        if let Some(resource) = resources.get(&path.source_resource_id)? {
            keys.source
                .get_or_insert_with(|| resource.canonical_key.clone());
            keys.keys.insert(resource.canonical_key);
        }
        if let Some(resource) = resources.get(&path.actor_resource_id)? {
            keys.actor
                .get_or_insert_with(|| resource.canonical_key.clone());
            keys.keys.insert(resource.canonical_key);
        }
        if let Some(resource) = resources.get(&path.sink_resource_id)? {
            keys.sink
                .get_or_insert_with(|| resource.canonical_key.clone());
            keys.keys.insert(resource.canonical_key);
        }
        for edge in paths_repo.list_edges(&link.attack_path_id)? {
            if let Some(relationship) = relationships.get(&edge.relationship_id)? {
                keys.keys.insert(relationship.canonical_key);
            }
        }
    }
    Ok(keys)
}

fn pair_sink_flip(
    from_keys: &FindingKeys,
    appeared_keys: &[FindingKeys],
    used_appeared: &HashSet<usize>,
) -> Option<usize> {
    let source = from_keys.source.as_ref()?;
    let actor = from_keys.actor.as_ref()?;
    let sink = from_keys.sink.as_ref()?;
    appeared_keys
        .iter()
        .enumerate()
        .find_map(|(index, to_keys)| {
            if used_appeared.contains(&index) {
                return None;
            }
            if to_keys.source.as_ref() == Some(source)
                && to_keys.actor.as_ref() == Some(actor)
                && to_keys.sink.as_ref().is_some_and(|value| value != sink)
            {
                Some(index)
            } else {
                None
            }
        })
}

fn sink_identity_cause(
    conn: &Connection,
    from_scan_id: &str,
    to_scan_id: &str,
    from_sink: &str,
    to_sink: &str,
) -> Result<FindingCause, PicoError> {
    let mut evidence = evidence_types(conn, from_scan_id, from_sink)?;
    evidence.extend(evidence_types(conn, to_scan_id, to_sink)?);
    evidence.sort();
    evidence.dedup();
    Ok(FindingCause {
        summary: format!("Sink identity changed: {from_sink} → {to_sink}"),
        graph_key: Some(to_sink.to_string()),
        field: Some("sink".to_string()),
        from_value: Some(from_sink.to_string()),
        to_value: Some(to_sink.to_string()),
        evidence_source_types: evidence,
    })
}

fn ranked_cause(
    conn: &Connection,
    from_scan_id: &str,
    to_scan_id: &str,
    keys: &FindingKeys,
    graph: &GraphDiff,
) -> Result<FindingCause, PicoError> {
    let mut hits: Vec<(u8, &GraphSubject, &'static str)> = Vec::new();
    for (bucket, subject) in moving_subjects(graph) {
        if !keys.keys.contains(&subject.canonical_key) {
            continue;
        }
        if let Some(rank) = cause_rank(subject, bucket) {
            hits.push((rank, subject, bucket));
        }
    }
    hits.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.canonical_key.cmp(&right.1.canonical_key))
    });
    let Some((_, subject, bucket)) = hits.first() else {
        return Ok(FindingCause {
            summary: UNKNOWN_CAUSE.to_string(),
            graph_key: None,
            field: None,
            from_value: None,
            to_value: None,
            evidence_source_types: Vec::new(),
        });
    };
    let mut evidence = evidence_types(conn, from_scan_id, &subject.canonical_key)?;
    evidence.extend(evidence_types(conn, to_scan_id, &subject.canonical_key)?);
    evidence.sort();
    evidence.dedup();
    Ok(cause_from_hit(subject, bucket, evidence))
}

fn moving_subjects(graph: &GraphDiff) -> Vec<(&'static str, &GraphSubject)> {
    let mut subjects = Vec::new();
    for (bucket, list) in [
        ("first_seen", &graph.resources.first_seen),
        ("reappeared", &graph.resources.reappeared),
        ("changed", &graph.resources.changed),
        ("disappeared", &graph.resources.disappeared),
        ("first_seen", &graph.relationships.first_seen),
        ("reappeared", &graph.relationships.reappeared),
        ("changed", &graph.relationships.changed),
        ("disappeared", &graph.relationships.disappeared),
    ] {
        for subject in list {
            subjects.push((bucket, subject));
        }
    }
    subjects
}

fn cause_rank(subject: &GraphSubject, bucket: &str) -> Option<u8> {
    if subject.kind == "can_execute" && bucket == "changed" {
        return Some(0);
    }
    if matches!(
        subject.kind.as_str(),
        "can_retrieve"
            | "can_call"
            | "configured_with"
            | "mcp_server"
            | "mcp_tool"
            | "external_source"
    ) {
        return Some(1);
    }
    if subject.canonical_key.contains("mcp:github") {
        return Some(1);
    }
    if matches!(subject.kind.as_str(), "can_access" | "credential") {
        return Some(2);
    }
    if subject.kind == "can_mutate" {
        return Some(3);
    }
    if subject.kind == "worker" {
        return Some(4);
    }
    None
}

fn cause_from_hit(subject: &GraphSubject, bucket: &str, evidence: Vec<String>) -> FindingCause {
    let (field, from_value, to_value, summary) = if subject.kind == "can_execute" {
        if let Some(delta) = preferred_delta(&subject.deltas, &["effective_state", "state"]) {
            (
                Some(delta.field.clone()),
                Some(delta.from.clone()),
                Some(delta.to.clone()),
                if delta.field == "effective_state" {
                    format!("Bash effective state {} → {}", delta.from, delta.to)
                } else {
                    format!("Bash execution state {} → {}", delta.from, delta.to)
                },
            )
        } else {
            (
                None,
                None,
                None,
                "Bash execution capability changed".to_string(),
            )
        }
    } else if subject.canonical_key.contains("mcp:github")
        || matches!(
            subject.kind.as_str(),
            "can_retrieve" | "can_call" | "configured_with" | "mcp_server" | "mcp_tool"
        )
    {
        let summary = match bucket {
            "disappeared" => "GitHub MCP influence is no longer present",
            "reappeared" => "GitHub MCP influence reappeared",
            _ => "GitHub MCP influence became present",
        };
        (None, None, None, summary.to_string())
    } else if subject.kind == "can_access" || subject.kind == "credential" {
        let summary = if bucket == "disappeared" {
            "Credential reachability is no longer present"
        } else {
            "Credential reachability changed"
        };
        (None, None, None, summary.to_string())
    } else if subject.kind == "can_mutate" {
        if let Some(delta) = preferred_delta(&subject.deltas, &["authority_resolution", "state"]) {
            (
                Some(delta.field.clone()),
                Some(delta.from.clone()),
                Some(delta.to.clone()),
                format!("Worker mutation authority {} → {}", delta.from, delta.to),
            )
        } else if bucket == "disappeared" {
            (
                None,
                None,
                None,
                "Worker mutation authority is no longer present".to_string(),
            )
        } else {
            (
                None,
                None,
                None,
                "Worker mutation authority changed".to_string(),
            )
        }
    } else if subject.kind == "worker" {
        (
            Some("sink".to_string()),
            None,
            None,
            format!("Production sink {} {bucket}", subject.canonical_key),
        )
    } else {
        (None, None, None, UNKNOWN_CAUSE.to_string())
    };
    FindingCause {
        summary,
        graph_key: Some(subject.canonical_key.clone()),
        field,
        from_value,
        to_value,
        evidence_source_types: evidence,
    }
}

fn preferred_delta<'a>(deltas: &'a [GraphDelta], fields: &[&str]) -> Option<&'a GraphDelta> {
    for field in fields {
        if let Some(delta) = deltas.iter().find(|delta| delta.field == *field) {
            return Some(delta);
        }
    }
    deltas.first()
}

fn evidence_types(conn: &Connection, scan_id: &str, key: &str) -> Result<Vec<String>, PicoError> {
    if key.is_empty() {
        return Ok(Vec::new());
    }
    let mut types = Vec::new();
    for item in EvidenceRepo::new(conn).get_for_scan(scan_id)? {
        if item.subject == key || item.subject.contains(key) {
            types.push(item.source_type);
        }
    }
    types.sort();
    types.dedup();
    Ok(types)
}

#[cfg(test)]
mod tests {
    use super::UNKNOWN_CAUSE;

    #[test]
    fn unknown_cause_sentence_is_explicit() {
        assert!(!UNKNOWN_CAUSE.is_empty());
        assert!(UNKNOWN_CAUSE.contains("No single observed graph cause"));
    }
}
