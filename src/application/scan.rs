//! `pico scan` application service (SPRINT-001.md §12).

use std::path::Path;

use crate::discovery;
use crate::domain::{
    Evidence, EvidenceClass, Observation, Resource, Scan, ScanStatus, Sensitivity,
};
use crate::persistence::{
    Database, EvidenceRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanRepo,
};
use crate::shared::{PicoError, PICO_VERSION};

/// Structured result of a scan, rendered by the CLI.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resource_count: u64,
    pub agent_count: u64,
    pub relationship_count: u64,
    pub evidence_count: u64,
    pub finding_count: u64,
}

/// Runs bounded local discovery in an initialized workspace.
pub struct ScanService;

impl ScanService {
    pub fn run(workspace: &Path) -> Result<ScanResult, PicoError> {
        Self::run_with_home(
            workspace,
            std::env::var_os("HOME").as_deref().map(Path::new),
        )
    }

    /// Runs discovery with an explicit home directory, primarily enabling
    /// deterministic local-fixture tests without inspecting a real user home.
    pub fn run_with_home(workspace: &Path, home: Option<&Path>) -> Result<ScanResult, PicoError> {
        let mut db = Database::open_existing(&workspace.join(".pico").join("pico.db"))?;
        db.migrate()?;

        let scan_repo = ScanRepo::new(db.connection());
        let scan = Scan::start(PICO_VERSION)?;
        scan_repo.insert(&scan)?;

        let discovered = discovery::discover(workspace, home)?;
        let resource_repo = ResourceRepo::new(db.connection());
        let evidence_repo = EvidenceRepo::new(db.connection());
        let observation_repo = ObservationRepo::new(db.connection());
        let mut actor_seen = false;
        for actor in discovered.actors {
            if actor.provider != "opencode" {
                continue;
            }
            let resource = match resource_repo.get_by_canonical_key("agent:opencode")? {
                Some(resource) => resource,
                None => Resource::new("agent:opencode", "agent", "opencode", "OpenCode")?,
            };
            resource_repo.upsert(&resource)?;
            evidence_repo.insert(&Evidence::new(
                &scan.id,
                EvidenceClass::Direct,
                actor.source_type,
                &actor.source_locator,
                "agent:opencode",
                "supported OpenCode configuration observed",
                Sensitivity::Internal,
            )?)?;
            if !actor_seen {
                observation_repo.insert(&Observation::new(
                    &scan.id,
                    "resource",
                    &resource.id,
                    "present",
                    "opencode_adapter",
                )?)?;
                actor_seen = true;
            }
        }

        let completed = if discovered.problems.is_empty() {
            scan.complete()?
        } else {
            scan.partial()?
        };
        scan_repo.update(&completed)?;

        let resource_count = resource_repo.count()?;
        let relationship_count = RelationshipRepo::new(db.connection()).count()?;
        let evidence_count = evidence_repo.count()?;

        Ok(ScanResult {
            scan_id: completed.id,
            status: completed.status,
            started_at: completed.started_at,
            completed_at: completed.completed_at,
            resource_count,
            agent_count: u64::from(actor_seen),
            relationship_count,
            evidence_count,
            finding_count: 0,
        })
    }
}
