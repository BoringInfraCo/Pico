//! Persistence integration tests. Each module exercises the SQLite
//! lifecycle and repositories through the public `pico::persistence` API.

#[path = "persistence/analysis_test.rs"]
mod analysis_test;
#[path = "persistence/db_test.rs"]
mod db_test;
#[path = "persistence/finding_query_integrity_test.rs"]
mod finding_query_integrity_test;
#[path = "persistence/finding_query_multi_test.rs"]
mod finding_query_multi_test;
#[path = "persistence/findings_test.rs"]
mod findings_test;
#[path = "persistence/repos_test.rs"]
mod repos_test;
