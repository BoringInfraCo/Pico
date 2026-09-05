//! End-to-end integration tests: the init/scan golden path and the
//! offline guarantee.

#[path = "integration/cloudflare_credential_scan_test.rs"]
mod cloudflare_credential_scan_test;
#[path = "integration/diagnostics_test.rs"]
mod diagnostics_test;
#[path = "integration/dogfood_f1_live_test.rs"]
mod dogfood_f1_live_test;
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
#[path = "integration/sprint016_cli_test.rs"]
mod sprint016_cli_test;
#[path = "integration/sprint016_mcp_test.rs"]
mod sprint016_mcp_test;
#[path = "integration/sprint017_cli_test.rs"]
mod sprint017_cli_test;
#[path = "integration/sprint017_mcp_test.rs"]
mod sprint017_mcp_test;
#[path = "integration/sprint018_cli_test.rs"]
mod sprint018_cli_test;
#[path = "integration/sprint018_mcp_test.rs"]
mod sprint018_mcp_test;
#[path = "integration/sprint019_cli_test.rs"]
mod sprint019_cli_test;
#[path = "integration/sprint019_mcp_test.rs"]
mod sprint019_mcp_test;
#[path = "integration/sprint020_adapter_test.rs"]
mod sprint020_adapter_test;
#[path = "integration/sprint020_cli_test.rs"]
mod sprint020_cli_test;
#[path = "integration/sprint020_mcp_test.rs"]
mod sprint020_mcp_test;
#[path = "integration/sprint021_authority_test.rs"]
mod sprint021_authority_test;
#[path = "integration/sprint021_cli_test.rs"]
mod sprint021_cli_test;
#[path = "integration/sprint021_mcp_test.rs"]
mod sprint021_mcp_test;
#[path = "integration/sprint023_cli_test.rs"]
mod sprint023_cli_test;
#[path = "integration/sprint024_cli_test.rs"]
mod sprint024_cli_test;
#[path = "integration/sprint025_cli_test.rs"]
mod sprint025_cli_test;
#[path = "integration/sprint026_cli_test.rs"]
mod sprint026_cli_test;
#[path = "integration/sprint027_cli_test.rs"]
mod sprint027_cli_test;
#[path = "integration/sprint028_cli_test.rs"]
mod sprint028_cli_test;
#[path = "integration/sprint029_cli_test.rs"]
mod sprint029_cli_test;
#[path = "integration/sprint030_cli_test.rs"]
mod sprint030_cli_test;
