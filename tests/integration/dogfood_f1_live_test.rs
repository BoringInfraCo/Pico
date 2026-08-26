//! Sprint 012 dogfood failure-injection F1 automation: a live-network probe
//! proving the operator scan path (ScanService::run) degrades honestly with a
//! deliberately invalid Cloudflare token.
//!
//! This test performs real network I/O against api.cloudflare.com using only
//! the allowlisted token-verify operation, so it is `#[ignore]`d by default;
//! run it explicitly during dogfood with:
//!
//! ```text
//! cargo test --test integration dogfood_f1 -- --ignored
//! ```
//!
//! The offline suites (offline_test.rs and every fixture suite) never touch
//! the network by construction — tempdir workspaces, no ambient credentials —
//! and must stay untouched by this file.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::domain::ScanStatus;
use tempfile::tempdir;

const INVALID_TOKEN: &str = "deliberately-invalid-token-for-pico-dogfood-F1";

/// Same shape as tests/integration/sprint010_cli_test.rs CONFIG: exposed
/// variant (bash allow) with the GitHub MCP server declared.
const CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }
    }
  }}
}"#;

#[ignore]
#[test]
fn f1_invalid_token_scan_completes_honestly_without_panic_or_leak() {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    fs::write(
        workspace.path().join(".env"),
        format!("CLOUDFLARE_API_TOKEN={INVALID_TOKEN}\n"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();

    // Every failure mode (HTTP error from the invalid token, DNS failure,
    // timeout) must land in retained provider problems and an honestly
    // degraded scan state. A panic or a fabricated authority is a defect.
    let result = ScanService::run(workspace.path()).unwrap();

    assert!(
        matches!(result.status, ScanStatus::Partial | ScanStatus::Complete),
        "scan must complete without panic; got {:?}",
        result.status
    );
    assert_ne!(
        result.cloudflare_credential_status.as_deref(),
        Some("ACTIVE"),
        "an invalid token must never resolve to ACTIVE credential status"
    );
    assert_eq!(
        result.cloudflare_account_count, 0,
        "no accounts may be fabricated from failed introspection"
    );
    assert_eq!(
        result.cloudflare_worker_count, 0,
        "no workers may be fabricated from failed introspection"
    );
    let debug = format!("{result:?}");
    assert!(
        !debug.contains(INVALID_TOKEN),
        "credential value leaked into ScanResult debug output"
    );
}
