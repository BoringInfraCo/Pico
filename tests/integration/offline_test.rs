//! Smoke test documenting the Sprint 001 offline guarantee: init and
//! scan succeed using only tempdir state, with no network access or
//! credentials required.

use pico::application::{InitService, ScanService};
use pico::domain::ScanStatus;
use tempfile::tempdir;

#[test]
fn init_and_scan_work_offline_in_temp_workspace() {
    let dir = tempdir().unwrap();
    let init = InitService::run(dir.path()).unwrap();
    assert_eq!(init.schema_version, 2);
    let scan = ScanService::run_with_home(dir.path(), None).unwrap();
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(scan.resource_count, 0);
    assert_eq!(scan.relationship_count, 0);
    assert_eq!(scan.evidence_count, 0);
    assert_eq!(scan.finding_count, 0);
}
