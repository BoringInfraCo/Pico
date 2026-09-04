//! Comparison-contract provenance for `pico diff` (SPRINT-029.md §5.1–§5.2).
//!
//! The contract tuple versions the four semantic layers a comparison depends
//! on: the comparison envelope, the observation graph snapshot, the
//! analysis/AttackPath summary, and the Finding serialization. Provenance is
//! loaded per diff side from the persisted declarations and rows. Absence of
//! a derivable component is a supported legacy state (a gap); malformed or
//! internally contradictory persisted provenance fails closed as a database
//! integrity error.

use rusqlite::OptionalExtension;
use serde::Serialize;

use crate::analysis::ANALYSIS_VERSION;
use crate::domain::{Scan, GRAPH_SNAPSHOT_VERSION};
use crate::findings::FINDING_VERSION;
use crate::shared::PicoError;

/// Version of the comparison-contract tuple and its validation semantics.
pub const COMPARISON_CONTRACT_VERSION: u32 = 1;

/// The four contract components a comparison depends on (SPRINT-029 §5.1).
///
/// Field declaration order is the deterministic tuple-field order used for
/// gap reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ComparisonContractVersions {
    pub comparison_contract_version: u32,
    pub graph_snapshot_version: u64,
    pub analysis_version: u32,
    pub finding_version: u32,
}

/// The comparison contract produced by this build.
pub const CURRENT_COMPARISON_CONTRACT: ComparisonContractVersions = ComparisonContractVersions {
    comparison_contract_version: COMPARISON_CONTRACT_VERSION,
    graph_snapshot_version: GRAPH_SNAPSHOT_VERSION,
    analysis_version: ANALYSIS_VERSION,
    finding_version: FINDING_VERSION,
};

/// One tuple component, named for gap reporting in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ComparisonContractField {
    ComparisonContractVersion,
    GraphSnapshotVersion,
    AnalysisVersion,
    FindingVersion,
}

impl ComparisonContractField {
    /// Machine-readable component name used in rendered gap lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            ComparisonContractField::ComparisonContractVersion => "comparison_contract_version",
            ComparisonContractField::GraphSnapshotVersion => "graph_snapshot_version",
            ComparisonContractField::AnalysisVersion => "analysis_version",
            ComparisonContractField::FindingVersion => "finding_version",
        }
    }
}

/// Which side of a comparison a provenance value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiffSide {
    From,
    To,
}

impl DiffSide {
    /// Machine-readable side name used in rendered gap lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            DiffSide::From => "FROM",
            DiffSide::To => "TO",
        }
    }
}

/// One missing provenance component on one side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ComparisonProvenanceGap {
    pub side: DiffSide,
    pub field: ComparisonContractField,
}

/// Persisted provenance for one comparison side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffSideProvenance {
    pub pico_version: String,
    pub contract: Option<ComparisonContractVersions>,
}

/// Persisted provenance for both comparison sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffProvenance {
    pub from: DiffSideProvenance,
    pub to: DiffSideProvenance,
}

/// Provenance outcome for one diff side.
///
/// `Unavailable` carries the missing fields only (no side): the loader is
/// called per side and the guard attaches the `DiffSide` when composing
/// `ComparisonProvenanceGap` values. Fields are ordered by
/// `ComparisonContractField` declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SideProvenance {
    Available(ComparisonContractVersions),
    Unavailable(Vec<ComparisonContractField>),
}

/// Comparison-contract components declared in Scan metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeclaredComponents {
    comparison_contract_version: u32,
    graph_snapshot_version: u64,
    finding_version: u32,
}

fn db_err(error: rusqlite::Error) -> PicoError {
    PicoError::Database(error.to_string())
}

/// Parse a persisted version column as a canonical base-10 positive `u32`.
///
/// Canonical means: non-empty ASCII digits only, no sign, whitespace,
/// leading zeroes, or alternate representation, and a value above zero.
/// Anything else is a database integrity failure that names the scan and
/// component without echoing the rejected value.
pub(crate) fn parse_canonical_u32(
    scan_id: &str,
    component: &str,
    raw: &str,
) -> Result<u32, PicoError> {
    let malformed = raw.is_empty()
        || raw == "0"
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_digit());
    let parsed = if malformed {
        None
    } else {
        raw.parse::<u32>().ok()
    };
    parsed.ok_or_else(|| {
        PicoError::database(format!(
            "scan {scan_id} {component} is not a canonical version string"
        ))
    })
}

/// Validate the persisted `pico_version` grammar (SPRINT-029 §5.1): 1–64
/// printable ASCII characters from `[0-9A-Za-z.+-]`, no whitespace or
/// control bytes. The rejected value is never echoed back.
pub fn validate_pico_version(scan_id: &str, pico_version: &str) -> Result<(), PicoError> {
    let valid = !pico_version.is_empty()
        && pico_version.len() <= 64
        && pico_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(PicoError::database(format!(
            "scan {scan_id} pico_version is not a valid package version string"
        )))
    }
}

/// Load and validate the comparison-contract provenance for one diff side
/// (SPRINT-029 §5.2, frozen order).
///
/// Absence of a derivable component (legacy state) accumulates gaps and
/// returns `Unavailable`; contradiction between declarations and rows,
/// malformed values, or a non-COMPLETE summary on a COMPLETE scan aborts
/// with an integrity error.
pub(crate) fn load_side_provenance(
    conn: &rusqlite::Connection,
    scan: &Scan,
) -> Result<SideProvenance, PicoError> {
    // 1. Package-version grammar before any row is read.
    validate_pico_version(&scan.id, &scan.pico_version)?;

    // 2. The persisted analysis summary is the authoritative analysis version.
    let analysis: Option<(String, String)> = conn
        .query_row(
            "SELECT analysis_version, status FROM scan_analyses WHERE scan_id = ?1",
            [&scan.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(db_err)?;
    let analysis_version = match analysis {
        None => None,
        Some((raw_version, status)) => {
            let version = parse_canonical_u32(&scan.id, "analysis_version", &raw_version)?;
            if status != "COMPLETE" {
                return Err(PicoError::database(format!(
                    "scan {} analysis summary status is not COMPLETE",
                    scan.id
                )));
            }
            Some(version)
        }
    };

    // 3. Scan metadata declarations. Absent metadata is legacy state; a
    // present non-object is corruption. A declared envelope requires every
    // declared sibling to be present and well-formed.
    let metadata_object = match scan.metadata.as_ref() {
        None => None,
        Some(value) => Some(value.as_object().ok_or_else(|| {
            PicoError::database(format!("scan {} metadata is not a JSON object", scan.id))
        })?),
    };
    let declared: Option<DeclaredComponents> = match metadata_object {
        Some(object) => match object.get("comparison_contract_version") {
            Some(envelope_value) => {
                let comparison_contract_version =
                    json_positive_u32(&scan.id, "comparison_contract_version", envelope_value)?;
                let graph_snapshot_version = json_positive_u64(
                    &scan.id,
                    "graph_snapshot_version",
                    require_declared(&scan.id, object, "graph_snapshot_version")?,
                )?;
                let finding_version = json_positive_u32(
                    &scan.id,
                    "finding_version",
                    require_declared(&scan.id, object, "finding_version")?,
                )?;
                Some(DeclaredComponents {
                    comparison_contract_version,
                    graph_snapshot_version,
                    finding_version,
                })
            }
            None => None,
        },
        None => None,
    };

    // 4. Graph component: declaration, legacy graph declaration, or
    // observation derivation, always cross-checked against the scan-scoped
    // observation snapshots.
    let observed = scan_observation_snapshot_versions(conn, &scan.id)?;
    let graph_version = match declared {
        Some(components) => {
            let declared_graph = components.graph_snapshot_version;
            if observed.iter().any(|version| *version != declared_graph) {
                return Err(PicoError::database(format!(
                    "scan {} observation snapshot version contradicts the declared graph_snapshot_version",
                    scan.id
                )));
            }
            Some(declared_graph)
        }
        None => match metadata_object.and_then(|object| object.get("graph_snapshot_version")) {
            Some(value) => {
                let declared_graph = json_positive_u64(&scan.id, "graph_snapshot_version", value)?;
                if observed.iter().any(|version| *version != declared_graph) {
                    return Err(PicoError::database(format!(
                        "scan {} observation snapshot version contradicts the declared graph_snapshot_version",
                        scan.id
                    )));
                }
                Some(declared_graph)
            }
            None => match observed.as_slice() {
                [] => None,
                [only] => Some(*only),
                _ => {
                    return Err(PicoError::database(format!(
                        "scan {} observation snapshot versions disagree",
                        scan.id
                    )))
                }
            },
        },
    };

    // 5. AttackPath analysis versions must agree with the summary; rows
    // without a summary contradict the missing authoritative row.
    let path_versions = distinct_canonical_versions(
        conn,
        &scan.id,
        "attack_paths",
        "analysis_version",
        "attack_paths analysis_version",
    )?;
    match analysis_version {
        Some(summary) => {
            if path_versions.iter().any(|version| *version != summary) {
                return Err(PicoError::database(format!(
                    "scan {} attack_paths analysis_version contradicts the analysis summary",
                    scan.id
                )));
            }
        }
        None => {
            if !path_versions.is_empty() {
                return Err(PicoError::database(format!(
                    "scan {} attack paths contradict missing analysis summary",
                    scan.id
                )));
            }
        }
    }

    // 6. Finding versions: at most one distinct persisted value, agreeing
    // with a declaration when present. A legacy scan with zero Finding rows
    // cannot derive one; the binary must not guess a historical contract.
    let finding_versions = distinct_canonical_versions(
        conn,
        &scan.id,
        "findings",
        "finding_version",
        "findings finding_version",
    )?;
    let finding_version = match finding_versions.as_slice() {
        [] => declared.map(|components| components.finding_version),
        [only] => match declared {
            Some(components) => {
                if components.finding_version != *only {
                    return Err(PicoError::database(format!(
                        "scan {} finding_version contradicts the declared finding version",
                        scan.id
                    )));
                }
                Some(components.finding_version)
            }
            None => Some(*only),
        },
        _ => {
            return Err(PicoError::database(format!(
                "scan {} finding_version values disagree",
                scan.id
            )))
        }
    };

    // 7. Compose the tuple; any absent component leaves the side
    // unavailable with gaps in tuple-field declaration order.
    match (graph_version, analysis_version, finding_version) {
        (Some(graph), Some(analysis), Some(finding)) => {
            Ok(SideProvenance::Available(ComparisonContractVersions {
                comparison_contract_version: declared
                    .map(|components| components.comparison_contract_version)
                    .unwrap_or(COMPARISON_CONTRACT_VERSION),
                graph_snapshot_version: graph,
                analysis_version: analysis,
                finding_version: finding,
            }))
        }
        _ => {
            let mut gaps = Vec::new();
            if graph_version.is_none() {
                gaps.push(ComparisonContractField::GraphSnapshotVersion);
            }
            if analysis_version.is_none() {
                gaps.push(ComparisonContractField::AnalysisVersion);
            }
            if finding_version.is_none() {
                gaps.push(ComparisonContractField::FindingVersion);
            }
            Ok(SideProvenance::Unavailable(gaps))
        }
    }
}

/// Require a declared metadata key; a missing key is an integrity failure.
fn require_declared<'a>(
    scan_id: &str,
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &'static str,
) -> Result<&'a serde_json::Value, PicoError> {
    object.get(field).ok_or_else(|| {
        PicoError::database(format!(
            "scan {scan_id} declared metadata is missing {field}"
        ))
    })
}

/// Parse a declared metadata value as a positive JSON integer fitting u32.
/// Strings, floats, zero, negatives, and overflow are integrity failures.
fn json_positive_u32(
    scan_id: &str,
    field: &str,
    value: &serde_json::Value,
) -> Result<u32, PicoError> {
    let parsed = value
        .as_u64()
        .filter(|parsed| *parsed > 0)
        .and_then(|parsed| u32::try_from(parsed).ok());
    parsed.ok_or_else(|| {
        PicoError::database(format!(
            "scan {scan_id} {field} is not a positive JSON integer"
        ))
    })
}

/// Parse a declared metadata value as a positive JSON integer fitting u64.
/// Strings, floats, zero, and negatives are integrity failures.
fn json_positive_u64(
    scan_id: &str,
    field: &str,
    value: &serde_json::Value,
) -> Result<u64, PicoError> {
    value.as_u64().filter(|parsed| *parsed > 0).ok_or_else(|| {
        PicoError::database(format!(
            "scan {scan_id} {field} is not a positive JSON integer"
        ))
    })
}

/// Distinct positive graph-snapshot versions across the scan's resource and
/// relationship observation snapshots, sorted. Every such row must carry a
/// well-formed snapshot version; anything else is integrity corruption.
fn scan_observation_snapshot_versions(
    conn: &rusqlite::Connection,
    scan_id: &str,
) -> Result<Vec<u64>, PicoError> {
    let mut statement = conn
        .prepare(
            "SELECT metadata FROM observations
             WHERE scan_id = ?1 AND subject_type IN ('resource', 'relationship')",
        )
        .map_err(db_err)?;
    let rows = statement
        .query_map([scan_id], |row| row.get::<_, Option<String>>(0))
        .map_err(db_err)?;
    let mut versions = Vec::new();
    for row in rows {
        let metadata = row.map_err(db_err)?;
        versions.push(observation_snapshot_version(scan_id, metadata)?);
    }
    versions.sort_unstable();
    versions.dedup();
    Ok(versions)
}

/// Extract the positive graph-snapshot version from one observation's
/// snapshot metadata.
fn observation_snapshot_version(scan_id: &str, metadata: Option<String>) -> Result<u64, PicoError> {
    let Some(text) = metadata else {
        return Err(PicoError::database(format!(
            "scan {scan_id} observation snapshot metadata is missing graph_snapshot_version"
        )));
    };
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        PicoError::database(format!(
            "scan {scan_id} observation snapshot metadata is not valid JSON"
        ))
    })?;
    let version = value
        .get("graph_snapshot_version")
        .and_then(|raw| raw.as_u64())
        .filter(|version| *version > 0);
    version.ok_or_else(|| {
        PicoError::database(format!(
            "scan {scan_id} observation snapshot metadata is missing a positive graph_snapshot_version"
        ))
    })
}

/// Distinct canonical u32 values of one version column for the scan.
/// `table` and `column` are compile-time literals from the call sites.
fn distinct_canonical_versions(
    conn: &rusqlite::Connection,
    scan_id: &str,
    table: &str,
    column: &str,
    component: &str,
) -> Result<Vec<u32>, PicoError> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT DISTINCT {column} FROM {table} WHERE scan_id = ?1"
        ))
        .map_err(db_err)?;
    let rows = statement
        .query_map([scan_id], |row| row.get::<_, String>(0))
        .map_err(db_err)?;
    let mut versions = Vec::new();
    for row in rows {
        let raw = row.map_err(db_err)?;
        versions.push(parse_canonical_u32(scan_id, component, &raw)?);
    }
    versions.sort_unstable();
    versions.dedup();
    Ok(versions)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use rusqlite::{params, Connection};

    use crate::domain::{Observation, Resource};
    use crate::persistence::codec;
    use crate::persistence::{ObservationRepo, ResourceRepo, ScanRepo};
    use crate::shared::PICO_VERSION;

    use super::*;

    fn test_conn() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        crate::persistence::db::migrate(&mut conn).unwrap();
        conn
    }

    fn scan_with(metadata: Option<serde_json::Value>) -> Scan {
        let mut scan = Scan::start(PICO_VERSION).unwrap();
        scan.metadata = metadata;
        scan
    }

    fn seed_scan(conn: &Connection, scan: &Scan) {
        ScanRepo::new(conn).insert(scan).unwrap();
    }

    fn seed_analysis(conn: &Connection, scan_id: &str, version: &str, status: &str) {
        conn.execute(
            "INSERT INTO scan_analyses (scan_id, analysis_version, status, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![scan_id, version, status, codec::ts_to_text(Utc::now())],
        )
        .unwrap();
    }

    fn seed_attack_path(conn: &Connection, scan_id: &str, version: &str) {
        let resources = ResourceRepo::new(conn);
        let source = Resource::new(
            &format!("external_source:{scan_id}"),
            "external_source",
            "t",
            "S",
        )
        .unwrap();
        let actor = Resource::new(&format!("agent:{scan_id}"), "agent", "t", "A").unwrap();
        let sink = Resource::new(&format!("sink:{scan_id}"), "worker", "t", "K").unwrap();
        for resource in [&source, &actor, &sink] {
            resources.upsert(resource).unwrap();
        }
        conn.execute(
            "INSERT INTO attack_paths
             (id, scan_id, fingerprint, analysis_version, source_resource_id,
              actor_resource_id, sink_resource_id, disposition, source_trust,
              influence_strength, capability, authority_resolution, sink_impact, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ACTIVE', 'PUBLIC_EXTERNAL',
                     'AGENT_RETRIEVABLE', 'CAN_EXECUTE', 'EXACT', 'CONSEQUENTIAL', ?8)",
            params![
                format!("path_{scan_id}"),
                scan_id,
                format!("fp_{scan_id}"),
                version,
                source.id,
                actor.id,
                sink.id,
                codec::ts_to_text(Utc::now())
            ],
        )
        .unwrap();
    }

    fn seed_finding(conn: &Connection, scan_id: &str, version: &str) {
        conn.execute(
            "INSERT INTO findings
             (id, scan_id, fingerprint, family_fingerprint, finding_version, finding_class,
              title, summary, severity, confidence, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'UNTRUSTED_TO_PRODUCTION', 't', 's', 'LOW',
                     'HIGH', 'OPEN', ?6)",
            params![
                format!("finding_{scan_id}"),
                scan_id,
                format!("fp_{scan_id}"),
                format!("fam_{scan_id}"),
                version,
                codec::ts_to_text(Utc::now())
            ],
        )
        .unwrap();
    }

    fn seed_observation(conn: &Connection, scan_id: &str, metadata: &str) {
        let mut observation =
            Observation::new(scan_id, "resource", "res_1", "present", "fixture").unwrap();
        observation.metadata = Some(serde_json::from_str(metadata).unwrap());
        ObservationRepo::new(conn).insert(&observation).unwrap();
    }

    fn declared_current() -> serde_json::Value {
        serde_json::json!({
            "comparison_contract_version": COMPARISON_CONTRACT_VERSION,
            "graph_snapshot_version": GRAPH_SNAPSHOT_VERSION,
            "finding_version": FINDING_VERSION,
        })
    }

    fn legacy_metadata() -> serde_json::Value {
        serde_json::json!({ "graph_snapshot_version": GRAPH_SNAPSHOT_VERSION })
    }

    // (a) Canonical parsing.

    #[test]
    fn canonical_version_accepts_positive_decimal() {
        assert_eq!(parse_canonical_u32("s1", "c", "1").unwrap(), 1);
        assert_eq!(
            parse_canonical_u32("s1", "c", "4294967295").unwrap(),
            4_294_967_295
        );
    }

    #[test]
    fn canonical_version_rejects_non_canonical_text() {
        for raw in [
            "",
            " 1",
            "+1",
            "-1",
            "01",
            "1.0",
            "1_0",
            "\u{0661}",
            "v1",
            "0",
            "4294967296",
        ] {
            let error = parse_canonical_u32("s1", "c", raw).unwrap_err();
            assert!(
                matches!(error, PicoError::Database(_)),
                "expected integrity failure for {raw:?}"
            );
            if !raw.is_empty() {
                assert!(
                    !error.to_string().contains(raw),
                    "error must not echo the rejected value"
                );
            }
        }
    }

    // (b) Tuple equality is structural.

    #[test]
    fn tuple_equality_is_structural() {
        let base = ComparisonContractVersions {
            comparison_contract_version: 1,
            graph_snapshot_version: 1,
            analysis_version: 1,
            finding_version: 1,
        };
        assert_eq!(base, base);
        assert_eq!(base, ComparisonContractVersions { ..base });
        for drift in [
            ComparisonContractVersions {
                comparison_contract_version: 2,
                graph_snapshot_version: 1,
                analysis_version: 1,
                finding_version: 1,
            },
            ComparisonContractVersions {
                comparison_contract_version: 1,
                graph_snapshot_version: 2,
                analysis_version: 1,
                finding_version: 1,
            },
            ComparisonContractVersions {
                comparison_contract_version: 1,
                graph_snapshot_version: 1,
                analysis_version: 2,
                finding_version: 1,
            },
            ComparisonContractVersions {
                comparison_contract_version: 1,
                graph_snapshot_version: 1,
                analysis_version: 1,
                finding_version: 2,
            },
        ] {
            assert_ne!(base, drift);
        }
    }

    // (c) Component names and gap ordering.

    #[test]
    fn field_names_follow_declaration_order() {
        assert_eq!(
            [
                ComparisonContractField::ComparisonContractVersion,
                ComparisonContractField::GraphSnapshotVersion,
                ComparisonContractField::AnalysisVersion,
                ComparisonContractField::FindingVersion,
            ]
            .map(|field| field.as_str()),
            [
                "comparison_contract_version",
                "graph_snapshot_version",
                "analysis_version",
                "finding_version",
            ]
        );
        assert_eq!(DiffSide::From.as_str(), "FROM");
        assert_eq!(DiffSide::To.as_str(), "TO");
    }

    // (d) Current-contract construction.

    #[test]
    fn current_comparison_contract_matches_build_constants() {
        assert_eq!(
            CURRENT_COMPARISON_CONTRACT,
            ComparisonContractVersions {
                comparison_contract_version: 1,
                graph_snapshot_version: 1,
                analysis_version: 1,
                finding_version: 1,
            }
        );
    }

    // (e) pico_version grammar.

    #[test]
    fn pico_version_grammar_accepts_package_versions() {
        validate_pico_version("s1", "0.4.0").unwrap();
        validate_pico_version("s1", "1.2.3-beta.1+build").unwrap();
        validate_pico_version("s1", "0").unwrap();
    }

    #[test]
    fn pico_version_grammar_rejects_invalid_text() {
        for raw in [
            "",
            "0.4 0",
            "0\t4",
            "\u{1B}[31m",
            "0.4\u{00B7}0",
            "0.4.0\n",
            "١.٠",
            "v1 extra",
            &"a".repeat(65),
        ] {
            let error = validate_pico_version("s1", raw).unwrap_err();
            assert!(
                matches!(error, PicoError::Database(_)),
                "expected integrity failure for {raw:?}"
            );
            if !raw.is_empty() {
                assert!(
                    !error.to_string().contains(raw),
                    "error must not echo the rejected value"
                );
            }
        }
        validate_pico_version("s1", &"a".repeat(64)).unwrap();
    }

    // (g) Side-provenance derivation outcomes.

    #[test]
    fn declared_current_tuple_is_available() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Available(CURRENT_COMPARISON_CONTRACT)
        );
    }

    #[test]
    fn declared_envelope_is_preserved_for_the_guard() {
        let conn = test_conn();
        let metadata = serde_json::json!({
            "comparison_contract_version": 7,
            "graph_snapshot_version": 1,
            "finding_version": 1,
        });
        let scan = scan_with(Some(metadata));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let provenance = load_side_provenance(&conn, &scan).unwrap();
        assert_eq!(
            provenance,
            SideProvenance::Available(ComparisonContractVersions {
                comparison_contract_version: 7,
                graph_snapshot_version: 1,
                analysis_version: 1,
                finding_version: 1,
            })
        );
    }

    #[test]
    fn legacy_with_declarations_and_rows_is_available() {
        let conn = test_conn();
        let scan = scan_with(Some(legacy_metadata()));
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_attack_path(&conn, &scan.id, "1");
        seed_finding(&conn, &scan.id, "1");
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Available(CURRENT_COMPARISON_CONTRACT)
        );
    }

    #[test]
    fn legacy_graph_derives_from_observation_snapshots() {
        let conn = test_conn();
        let scan = scan_with(None);
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Available(CURRENT_COMPARISON_CONTRACT)
        );
    }

    #[test]
    fn legacy_zero_finding_is_unavailable_finding_version() {
        let conn = test_conn();
        let scan = scan_with(Some(legacy_metadata()));
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Unavailable(vec![ComparisonContractField::FindingVersion])
        );
    }

    #[test]
    fn legacy_missing_everything_is_unavailable_in_declaration_order() {
        let conn = test_conn();
        let scan = scan_with(None);
        seed_scan(&conn, &scan);
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Unavailable(vec![
                ComparisonContractField::GraphSnapshotVersion,
                ComparisonContractField::AnalysisVersion,
                ComparisonContractField::FindingVersion,
            ])
        );
    }

    #[test]
    fn partial_legacy_state_reports_remaining_gaps_in_order() {
        let conn = test_conn();
        let scan = scan_with(Some(legacy_metadata()));
        seed_scan(&conn, &scan);
        // Graph declared; no summary, no findings.
        assert_eq!(
            load_side_provenance(&conn, &scan).unwrap(),
            SideProvenance::Unavailable(vec![
                ComparisonContractField::AnalysisVersion,
                ComparisonContractField::FindingVersion,
            ])
        );
    }

    // Contradiction and malformed-state integrity failures.

    #[test]
    fn declared_finding_contradicting_rows_fails() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "2");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("finding_version"));
    }

    #[test]
    fn declared_graph_contradicting_observations_fails() {
        let conn = test_conn();
        let metadata = serde_json::json!({
            "comparison_contract_version": 1,
            "graph_snapshot_version": 2,
            "finding_version": 1,
        });
        let scan = scan_with(Some(metadata));
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("graph_snapshot_version"));
    }

    #[test]
    fn legacy_graph_declaration_contradicting_observations_fails() {
        let conn = test_conn();
        let metadata = serde_json::json!({ "graph_snapshot_version": 2 });
        let scan = scan_with(Some(metadata));
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        assert!(load_side_provenance(&conn, &scan).is_err());
    }

    #[test]
    fn disagreeing_observation_versions_fail() {
        let conn = test_conn();
        let scan = scan_with(None);
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":1}");
        seed_observation(&conn, &scan.id, "{\"graph_snapshot_version\":2}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error
            .to_string()
            .contains("observation snapshot versions disagree"));
    }

    #[test]
    fn observation_without_snapshot_version_fails() {
        let conn = test_conn();
        let scan = scan_with(None);
        seed_scan(&conn, &scan);
        seed_observation(&conn, &scan.id, "{\"subject_type\":\"resource\"}");
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("graph_snapshot_version"));
    }

    #[test]
    fn attack_path_contradicting_summary_fails() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_attack_path(&conn, &scan.id, "2");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("attack_paths analysis_version"));
    }

    #[test]
    fn attack_paths_without_summary_fail() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_attack_path(&conn, &scan.id, "1");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error
            .to_string()
            .contains("attack paths contradict missing analysis summary"));
    }

    #[test]
    fn non_complete_summary_fails() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "LIMITED");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("not COMPLETE"));
    }

    #[test]
    fn malformed_summary_version_fails_without_echo() {
        let conn = test_conn();
        let scan = scan_with(Some(declared_current()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "v1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("analysis_version"));
        assert!(!error.to_string().contains("v1"));
    }

    #[test]
    fn malformed_finding_version_fails_without_echo() {
        let conn = test_conn();
        let scan = scan_with(Some(legacy_metadata()));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "v1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("finding_version"));
        assert!(!error.to_string().contains("v1"));
    }

    #[test]
    fn analysis_summary_is_validated_before_metadata() {
        let conn = test_conn();
        // Non-object metadata AND a malformed summary; the frozen order
        // reaches the summary first.
        let scan = scan_with(Some(serde_json::json!([])));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "v1", "COMPLETE");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("analysis_version"));
    }

    #[test]
    fn non_object_metadata_fails() {
        let conn = test_conn();
        let scan = scan_with(Some(serde_json::json!([])));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("metadata is not a JSON object"));
    }

    #[test]
    fn declared_envelope_without_sibling_keys_fails() {
        let conn = test_conn();
        let metadata = serde_json::json!({ "comparison_contract_version": 1 });
        let scan = scan_with(Some(metadata));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("declared metadata is missing"));
    }

    #[test]
    fn declared_non_integer_values_fail() {
        for value in [
            serde_json::json!("1"),
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
        ] {
            let conn = test_conn();
            let metadata = serde_json::json!({
                "comparison_contract_version": 1,
                "graph_snapshot_version": 1,
                "finding_version": value,
            });
            let scan = scan_with(Some(metadata));
            seed_scan(&conn, &scan);
            seed_analysis(&conn, &scan.id, "1", "COMPLETE");
            seed_finding(&conn, &scan.id, "1");
            let error = load_side_provenance(&conn, &scan).unwrap_err();
            assert!(error.to_string().contains("finding_version"));
        }
    }

    #[test]
    fn declared_zero_envelope_fails() {
        let conn = test_conn();
        let metadata = serde_json::json!({
            "comparison_contract_version": 0,
            "graph_snapshot_version": 1,
            "finding_version": 1,
        });
        let scan = scan_with(Some(metadata));
        seed_scan(&conn, &scan);
        seed_analysis(&conn, &scan.id, "1", "COMPLETE");
        seed_finding(&conn, &scan.id, "1");
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("comparison_contract_version"));
    }

    #[test]
    fn invalid_pico_version_fails_first() {
        let conn = test_conn();
        let mut scan = scan_with(Some(declared_current()));
        scan.pico_version = "0.4 0".to_string();
        seed_scan(&conn, &scan);
        let error = load_side_provenance(&conn, &scan).unwrap_err();
        assert!(error.to_string().contains("pico_version"));
    }
}
