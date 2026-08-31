//! Safe, normalized GitHub provider facts (SPRINT-021).
//!
//! This module mirrors `cloudflare.rs`: it is the boundary between
//! GitHub-specific provider logic and Pico's generic application/domain
//! layers. The only transport capability is a single allowlisted read of
//! `GET /user`; repository write scope is observable only through the
//! `X-OAuth-Scopes` response header of a classic PAT. The default transport is
//! offline (`UnavailableTransport`) so no network access happens unless a
//! caller explicitly supplies a live transport.

use crate::discovery::cloudflare::AuthorityResolution;
use crate::domain::RelationshipState;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;

const API_ORIGIN: &str = "https://api.github.com";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_REQUESTS: usize = 8;
const USER_PATH: &str = "/user";

/// Classify a GitHub credential by its lexical shape. This is a deterministic,
/// best-effort heuristic used only to choose the safe authority projection; it
/// is never a substitute for live scope evidence.
///
/// * `ghp_` identifies a classic personal access token.
/// * `github_pat_` identifies a fine-grained personal access token.
/// * `gho_` identifies an OAuth user token.
/// * `ghs_` / `ghr_` identify user-to-server / refresh tokens.
/// * Anything unrecognized falls back to `unknown` (the safe default).
pub fn classify_credential_type(value: &str) -> &'static str {
    let candidate = value.trim();
    if candidate.starts_with("ghp_") {
        return "classic_pat";
    }
    if candidate.starts_with("github_pat_") {
        return "fine_grained_pat";
    }
    if candidate.starts_with("gho_") {
        return "oauth";
    }
    if candidate.starts_with("ghs_") || candidate.starts_with("ghr_") {
        return "other";
    }
    "unknown"
}

/// GitHub-namespaced credential fingerprint. The Cloudflare fingerprint
/// namespace is intentionally untouched.
pub fn fingerprint(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"pico:credential:github:token:v1:");
    digest.update(value.as_bytes());
    let bytes = digest.finalize();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// A deliberately narrow GET response used by the semantic provider client.
/// `scopes` is parsed from the `X-OAuth-Scopes` response header (default
/// empty). Implementations must redact transport errors and never include an
/// Authorization header or credential value in them.
#[derive(Clone, PartialEq, Eq)]
pub struct GetResponse {
    pub status: u16,
    pub body: String,
    pub scopes: Vec<String>,
    pub redirected_to: Option<String>,
}

impl std::fmt::Debug for GetResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GetResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("scopes", &self.scopes)
            .field("redirected_to", &self.redirected_to)
            .finish()
    }
}

/// The only transport capability exposed to the GitHub adapter. There is no
/// arbitrary method, URL, body, or header API.
pub trait GetTransport {
    fn get(&mut self, path: &str, token: &str) -> Result<GetResponse, String>;
}

/// Production HTTPS transport. It is constructed with a fixed GitHub API
/// origin and rejects redirects before they can cross an origin boundary.
#[derive(Debug, Clone)]
pub struct HttpsTransport {
    client: reqwest::blocking::Client,
}

impl HttpsTransport {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("pico/0.1 github-read-only")
            .build()
            .map_err(|_| "github transport initialization failed".to_string())?;
        Ok(Self { client })
    }
}

impl GetTransport for HttpsTransport {
    fn get(&mut self, path: &str, token: &str) -> Result<GetResponse, String> {
        if path != USER_PATH {
            return Err("github operation is not allowlisted".to_string());
        }
        let response = self
            .client
            .get(format!("{API_ORIGIN}{path}"))
            .bearer_auth(token)
            .send()
            .map_err(|_| "github read request failed".to_string())?;
        let status = response.status().as_u16();
        let redirected_to = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let scopes = response
            .headers()
            .get("x-oauth-scopes")
            .and_then(|value| value.to_str().ok())
            .map(parse_scopes)
            .unwrap_or_default();
        let bytes = read_bounded_body(response)?;
        let body = String::from_utf8(bytes)
            .map_err(|_| "github response was not valid UTF-8".to_string())?;
        Ok(GetResponse {
            status,
            body,
            scopes,
            redirected_to,
        })
    }
}

fn read_bounded_body(response: reqwest::blocking::Response) -> Result<Vec<u8>, String> {
    if let Some(len) = response.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err("github response exceeded bounded size".to_string());
        }
    }
    let mut limited = response.take(MAX_RESPONSE_BYTES as u64 + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|_| "github response could not be read".to_string())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err("github response exceeded bounded size".to_string());
    }
    Ok(bytes)
}

fn parse_scopes(header: &str) -> Vec<String> {
    header
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect()
}

/// A transport that performs no network access. It is the default safe
/// fallback for local scans.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableTransport;

impl GetTransport for UnavailableTransport {
    fn get(&mut self, _path: &str, _token: &str) -> Result<GetResponse, String> {
        Err("github provider transport unavailable".to_string())
    }
}

/// Safe normalized GitHub authority result for one credential. Only
/// credential type, fingerprint, and scope facts enter this value; raw token
/// values never do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAuthorityResult {
    pub credential_fingerprint: String,
    pub credential_type: Option<String>,
    pub resolution: AuthorityResolution,
    pub state: RelationshipState,
    pub permission_state: String,
    pub unknown_reasons: Vec<String>,
    pub source_locator: String,
    pub problems: Vec<String>,
}

impl Default for GitHubAuthorityResult {
    fn default() -> Self {
        Self {
            credential_fingerprint: String::new(),
            credential_type: None,
            resolution: AuthorityResolution::Unknown,
            state: RelationshipState::Unknown,
            permission_state: String::new(),
            unknown_reasons: Vec::new(),
            source_locator: String::new(),
            problems: Vec::new(),
        }
    }
}

impl GitHubAuthorityResult {
    /// The offline-safe default: repository write scope is not observable from
    /// the credential value alone, so authority is UNKNOWN with the
    /// unobservable reason and no write claim. No problem is recorded: this is
    /// the expected static posture, not a provider failure.
    pub fn offline(fingerprint: &str, credential_type: Option<&str>) -> Self {
        Self {
            credential_fingerprint: fingerprint.to_string(),
            credential_type: credential_type.map(str::to_string),
            resolution: AuthorityResolution::Unknown,
            state: RelationshipState::Unknown,
            permission_state: "READ_OR_UNKNOWN".to_string(),
            unknown_reasons: vec!["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()],
            source_locator: "github:scope_probe:offline".to_string(),
            problems: Vec::new(),
        }
    }
}

/// Typed GitHub operations. The token is borrowed only for the duration of
/// each request and is never stored by this client.
pub struct Client<T> {
    transport: T,
    requests: usize,
}

impl<T: GetTransport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            requests: 0,
        }
    }

    fn get(&mut self, path: &str, token: &str) -> Result<GetResponse, String> {
        if path != USER_PATH {
            return Err("github operation is not allowlisted".to_string());
        }
        self.requests = self.requests.saturating_add(1);
        if self.requests > MAX_REQUESTS {
            return Err("github request budget exceeded".to_string());
        }
        self.transport.get(path, token)
    }

    /// Bounded live scope probe: `GET /user` and parse `X-OAuth-Scopes`.
    /// On success the authority is resolved type-aware and scope-aware; on a
    /// transport failure a problem is recorded (the scan surfaces it as
    /// PARTIAL-aware) and no write authority is fabricated.
    pub fn probe(&mut self, token: &str, fingerprint: &str) -> GitHubAuthorityResult {
        let credential_type = classify_credential_type(token);
        let mut result = GitHubAuthorityResult {
            credential_fingerprint: fingerprint.to_string(),
            credential_type: Some(credential_type.to_string()),
            permission_state: "READ_OR_UNKNOWN".to_string(),
            source_locator: "github:scope_probe:/user".to_string(),
            ..GitHubAuthorityResult::default()
        };
        let response = match self.get(USER_PATH, token) {
            Ok(response) => response,
            Err(error) => {
                result.problems.push(error);
                result
                    .unknown_reasons
                    .push("GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string());
                return result;
            }
        };
        if response.redirected_to.is_some() {
            result.problems.push("github redirect rejected".to_string());
            result
                .unknown_reasons
                .push("GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string());
            return result;
        }
        if !(200..300).contains(&response.status) {
            result
                .problems
                .push(format!("github read returned HTTP {}", response.status));
            result
                .unknown_reasons
                .push("GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string());
            return result;
        }
        let (state, resolution, permission_state, unknown_reasons) =
            resolve_authority(credential_type, &response.scopes);
        result.state = state;
        result.resolution = resolution;
        result.permission_state = permission_state.to_string();
        result.unknown_reasons = unknown_reasons;
        result
    }
}

/// Discovery-facing probe helper. Callers supply a transport; the default
/// `UnavailableTransport` performs no network access.
pub fn inspect_scope(
    transport: impl GetTransport,
    token: &str,
    fingerprint: &str,
) -> GitHubAuthorityResult {
    Client::new(transport).probe(token, fingerprint)
}

/// Resolve GitHub repository mutation authority from the credential type and
/// observed OAuth scopes.
///
/// * offline / no probe info / unknown type => UNKNOWN + the unobservable
///   reason (never a fabricated write claim),
/// * classic PAT with `repo`/`public_repo` => EXACT/REPO_WRITE,
/// * classic PAT with read-only or empty scopes => BEHAVIORAL_READ_ONLY,
/// * fine-grained PAT => UNKNOWN (per-repo permissions are unobservable here),
/// * OAuth / other => UNKNOWN (scope not observable through this probe).
pub fn resolve_authority(
    credential_type: &str,
    scopes: &[String],
) -> (
    RelationshipState,
    AuthorityResolution,
    &'static str,
    Vec<String>,
) {
    match credential_type {
        "classic_pat" => {
            let has_write = scopes
                .iter()
                .any(|scope| scope == "repo" || scope == "public_repo");
            if has_write {
                (
                    RelationshipState::Derived,
                    AuthorityResolution::Exact,
                    "REPO_WRITE",
                    Vec::new(),
                )
            } else {
                (
                    RelationshipState::Unknown,
                    AuthorityResolution::BehavioralReadOnly,
                    "READ_ONLY",
                    Vec::new(),
                )
            }
        }
        "fine_grained_pat" => (
            RelationshipState::Unknown,
            AuthorityResolution::Unknown,
            "READ_OR_UNKNOWN",
            vec!["GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE".to_string()],
        ),
        "oauth" | "other" => (
            RelationshipState::Unknown,
            AuthorityResolution::Unknown,
            "READ_OR_UNKNOWN",
            vec!["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()],
        ),
        _ => (
            RelationshipState::Unknown,
            AuthorityResolution::Unknown,
            "READ_OR_UNKNOWN",
            vec!["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureTransport(GetResponse);

    impl GetTransport for FixtureTransport {
        fn get(&mut self, path: &str, _token: &str) -> Result<GetResponse, String> {
            assert_eq!(path, USER_PATH);
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct FailingTransport;

    impl GetTransport for FailingTransport {
        fn get(&mut self, _path: &str, _token: &str) -> Result<GetResponse, String> {
            Err("github provider transport unavailable".to_string())
        }
    }

    fn response(scopes: &[&str]) -> GetResponse {
        GetResponse {
            status: 200,
            body: "{}".to_string(),
            scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
            redirected_to: None,
        }
    }

    #[test]
    fn classifies_github_credential_types_by_prefix() {
        assert_eq!(classify_credential_type("ghp_abc"), "classic_pat");
        assert_eq!(
            classify_credential_type("github_pat_abc"),
            "fine_grained_pat"
        );
        assert_eq!(classify_credential_type("gho_abc"), "oauth");
        assert_eq!(classify_credential_type("ghs_abc"), "other");
        assert_eq!(classify_credential_type("ghr_abc"), "other");
        assert_eq!(classify_credential_type("nonsense"), "unknown");
        assert_eq!(classify_credential_type(""), "unknown");
    }

    #[test]
    fn github_fingerprint_is_namespaced_and_stable() {
        let first = fingerprint("ghp_TESTFAKE0000000000000000000000000000");
        let second = fingerprint("ghp_TESTFAKE0000000000000000000000000000");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64, "fingerprint is a sha256 hex digest");
        assert!(
            !first.contains("cloudflare"),
            "GitHub namespace is distinct"
        );
        assert_ne!(fingerprint("ghp_a"), fingerprint("ghp_b"));
    }

    #[test]
    fn r2_offline_authority_is_unknown_not_fabricated() {
        // The offline default carries no scope evidence and no write claim.
        let offline = GitHubAuthorityResult::offline("fp", Some("classic_pat"));
        assert_eq!(offline.state, RelationshipState::Unknown);
        assert_eq!(offline.resolution, AuthorityResolution::Unknown);
        assert_eq!(offline.permission_state, "READ_OR_UNKNOWN");
        assert!(offline
            .unknown_reasons
            .contains(&"GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()));
        assert!(!offline
            .permission_state
            .to_ascii_lowercase()
            .contains("write"));
        assert!(offline.problems.is_empty(), "offline is not a failure");

        // Probing through the unavailable transport also yields UNKNOWN (the
        // transport failure is recorded so a live probe failure surfaces as
        // PARTIAL-aware), and never fabricates a write claim.
        let mut client = Client::new(FailingTransport);
        let probed = client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(probed.resolution, AuthorityResolution::Unknown);
        assert_eq!(probed.state, RelationshipState::Unknown);
        assert_eq!(probed.permission_state, "READ_OR_UNKNOWN");
        assert!(probed
            .unknown_reasons
            .contains(&"GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()));
        assert!(!probed.problems.is_empty());
        assert_ne!(probed.resolution, AuthorityResolution::Exact);
    }

    #[test]
    fn r3_live_scope_probe_resolution() {
        // Classic PAT with repo scope => EXACT / REPO_WRITE / Derived.
        let mut client = Client::new(FixtureTransport(response(&["repo"])));
        let result = client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(result.credential_type.as_deref(), Some("classic_pat"));
        assert_eq!(result.resolution, AuthorityResolution::Exact);
        assert_eq!(result.state, RelationshipState::Derived);
        assert_eq!(result.permission_state, "REPO_WRITE");
        assert!(result.unknown_reasons.is_empty());
        assert!(result.problems.is_empty());

        // Classic PAT with public_repo scope => EXACT.
        let mut client = Client::new(FixtureTransport(response(&["public_repo", "read:user"])));
        let result = client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(result.resolution, AuthorityResolution::Exact);
        assert_eq!(result.permission_state, "REPO_WRITE");

        // Classic PAT with only read scopes => BEHAVIORAL_READ_ONLY / READ_ONLY.
        let mut client = Client::new(FixtureTransport(response(&["read:org", "read:user"])));
        let result = client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(result.resolution, AuthorityResolution::BehavioralReadOnly);
        assert_eq!(result.state, RelationshipState::Unknown);
        assert_eq!(result.permission_state, "READ_ONLY");
        assert!(result.unknown_reasons.is_empty());

        // Classic PAT with empty scopes => BEHAVIORAL_READ_ONLY (no write
        // fabrication from an absent scope header).
        let mut client = Client::new(FixtureTransport(response(&[])));
        let result = client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(result.resolution, AuthorityResolution::BehavioralReadOnly);
        assert_eq!(result.permission_state, "READ_ONLY");

        // Fine-grained PAT, even with a repo header => UNKNOWN + unobservable.
        let mut client = Client::new(FixtureTransport(response(&["repo"])));
        let result = client.probe("github_pat_TESTFAKE00000000000000000000", "fp");
        assert_eq!(result.credential_type.as_deref(), Some("fine_grained_pat"));
        assert_eq!(result.resolution, AuthorityResolution::Unknown);
        assert_eq!(result.state, RelationshipState::Unknown);
        assert!(result
            .unknown_reasons
            .contains(&"GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE".to_string()));

        // OAuth token => UNKNOWN + unobservable reason.
        let mut client = Client::new(FixtureTransport(response(&["repo"])));
        let result = client.probe("gho_TESTFAKE0000000000000000000000000000", "fp");
        assert_eq!(result.credential_type.as_deref(), Some("oauth"));
        assert_eq!(result.resolution, AuthorityResolution::Unknown);
        assert!(result
            .unknown_reasons
            .contains(&"GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()));
    }

    #[test]
    fn r9_authority_stable_across_identical_env() {
        fn probe_result(scopes: &[&str]) -> GitHubAuthorityResult {
            let mut client = Client::new(FixtureTransport(response(scopes)));
            client.probe("ghp_TESTFAKE0000000000000000000000000000", "fp")
        }
        let first = probe_result(&["repo"]);
        let second = probe_result(&["repo"]);
        assert_eq!(first, second);

        let offline_first = GitHubAuthorityResult::offline("fp", Some("classic_pat"));
        let offline_second = GitHubAuthorityResult::offline("fp", Some("classic_pat"));
        assert_eq!(offline_first, offline_second);
    }

    #[test]
    fn resolve_authority_table() {
        let read_scopes = vec!["read:user".to_string(), "read:org".to_string()];
        let empty: Vec<String> = Vec::new();
        // offline / unknown type.
        let (state, resolution, permission_state, reasons) = resolve_authority("unknown", &empty);
        assert_eq!(state, RelationshipState::Unknown);
        assert_eq!(resolution, AuthorityResolution::Unknown);
        assert_eq!(permission_state, "READ_OR_UNKNOWN");
        assert!(reasons.contains(&"GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()));
        // classic PAT write.
        let (state, resolution, permission_state, reasons) =
            resolve_authority("classic_pat", &["repo".to_string()]);
        assert_eq!(state, RelationshipState::Derived);
        assert_eq!(resolution, AuthorityResolution::Exact);
        assert_eq!(permission_state, "REPO_WRITE");
        assert!(reasons.is_empty());
        // classic PAT read-only.
        let (state, resolution, permission_state, _) =
            resolve_authority("classic_pat", &read_scopes);
        assert_eq!(state, RelationshipState::Unknown);
        assert_eq!(resolution, AuthorityResolution::BehavioralReadOnly);
        assert_eq!(permission_state, "READ_ONLY");
        // fine-grained.
        let (_, resolution, _, reasons) = resolve_authority("fine_grained_pat", &empty);
        assert_eq!(resolution, AuthorityResolution::Unknown);
        assert!(reasons.contains(&"GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE".to_string()));
        // oauth / other.
        for kind in ["oauth", "other"] {
            let (state, resolution, permission_state, reasons) =
                resolve_authority(kind, &["repo".to_string()]);
            assert_eq!(state, RelationshipState::Unknown);
            assert_eq!(resolution, AuthorityResolution::Unknown);
            assert_eq!(permission_state, "READ_OR_UNKNOWN");
            assert!(reasons.contains(&"GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()));
        }
    }
}
