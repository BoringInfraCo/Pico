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
