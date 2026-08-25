//! Domain integration tests. Each module exercises the public
//! `pico::domain` API from outside the crate.

#[path = "domain/evidence_observation_test.rs"]
mod evidence_observation_test;
#[path = "domain/graph_model_test.rs"]
mod graph_model_test;
#[path = "domain/relationship_test.rs"]
mod relationship_test;
#[path = "domain/resource_test.rs"]
mod resource_test;
#[path = "domain/scan_test.rs"]
mod scan_test;
