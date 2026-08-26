//! End-to-end integration tests: the init/scan golden path and the
//! offline guarantee.

#[path = "integration/cloudflare_credential_scan_test.rs"]
mod cloudflare_credential_scan_test;
#[path = "integration/empty_scan_test.rs"]
mod empty_scan_test;
#[path = "integration/github_mcp_scan_test.rs"]
mod github_mcp_scan_test;
#[path = "integration/offline_test.rs"]
mod offline_test;
#[path = "integration/opencode_scan_test.rs"]
mod opencode_scan_test;
#[path = "integration/sprint006_safety_test.rs"]
mod sprint006_safety_test;
#[path = "integration/sprint007_graph_test.rs"]
mod sprint007_graph_test;
#[path = "integration/sprint008_analysis_test.rs"]
mod sprint008_analysis_test;
#[path = "integration/sprint009_finding_test.rs"]
mod sprint009_finding_test;
#[path = "integration/sprint010_cli_test.rs"]
mod sprint010_cli_test;
#[path = "integration/sprint010_finding_query_test.rs"]
mod sprint010_finding_query_test;
#[path = "integration/sprint011_mcp_golden_test.rs"]
mod sprint011_mcp_golden_test;
#[path = "integration/sprint011_mcp_test.rs"]
mod sprint011_mcp_test;
