//! Safe, normalized Cloudflare provider facts.
//!
//! This module is the boundary between Cloudflare-specific provider logic and
//! Pico's generic application/domain layers. Provider code may parse API
//! responses internally, but it must emit only these normalized projections.

use crate::domain::RelationshipState;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

const API_ORIGIN: &str = "https://api.cloudflare.com/client/v4";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const MAX_REQUESTS: usize = 64;

/// Safe status projection of a verified Cloudflare API token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    Active,
    Inactive,
    Unknown,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Inactive => "INACTIVE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Resolution precision for a provider authority claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityResolution {
    Exact,
    Scoped,
    BehavioralReadOnly,
    Unknown,
}

impl AuthorityResolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "EXACT",
            Self::Scoped => "SCOPED",
            Self::BehavioralReadOnly => "BEHAVIORAL_READ_ONLY",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Evaluation of a token policy's account selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeState {
    InScope,
    OutOfScope,
    Unknown,
}

impl ScopeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InScope => "IN_SCOPE",
            Self::OutOfScope => "OUT_OF_SCOPE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// A safe account projection from Cloudflare's account inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAccount {
    pub account_id: String,
    pub name: Option<String>,
    pub account_type: Option<String>,
    pub scope: ScopeState,
    pub source_locator: String,
}

/// A safe Worker projection. Source, bindings, secrets, and settings are not
/// represented by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedWorker {
    pub account_id: String,
    pub script_name: String,
    pub worker_tag: Option<String>,
    pub source_locator: String,
    /// Explicit provider classification of the Worker destination. Absence
    /// remains UNKNOWN and must never be inferred from names or presence.
    /// Supported normalized values are `PRODUCTION`, `STAGING`, `LOCAL_DEV`,
    /// and `UNKNOWN`.
    pub sink_impact: Option<String>,
}

impl ObservedWorker {
    /// Stable identity preferred by the Sprint 006 contract.
    pub fn canonical_key(&self) -> String {
        match self.worker_tag.as_deref() {
            Some(tag) if !tag.is_empty() => {
                format!("cloudflare:worker:{}:{}", self.account_id, tag)
            }
            _ => format!(
                "cloudflare:worker:{}:name:{}",
                self.account_id, self.script_name
            ),
        }
    }

    pub fn identity_precision(&self) -> &'static str {
        if self
            .worker_tag
            .as_deref()
            .is_some_and(|tag| !tag.is_empty())
        {
            "IMMUTABLE_TAG"
        } else {
            "NAME_SCOPED"
        }
    }
}

/// A normalized per-Worker authority result. The provider adapter computes
/// this; ScanService only persists the safe projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityObservation {
    pub account_id: String,
    pub worker_key: String,
    pub state: RelationshipState,
    pub resolution: AuthorityResolution,
    pub permission_state: String,
    pub scope_state: ScopeState,
    pub unknown_reasons: Vec<String>,
    /// Names of the permission groups that actually grant the resolved
    /// authority. For write authority this is the write group names; for a
    /// read-only token it is the read group names.
    pub granted_permissions: Vec<String>,
    /// Whether the account/worker authority was resolved through a zone-scoped
    /// (rather than account-wide) policy grant.
    pub zone_scoped: bool,
    pub source_locator: String,
}

/// Safe output of one bounded Cloudflare provider scan.
#[derive(Debug, Clone, Default)]
pub struct ProviderResult {
    /// Local Sprint 005 fingerprint identifying the credential used for this
    /// provider result. This is not the credential value.
    pub credential_fingerprint: String,
    pub credential_status: Option<CredentialStatus>,
    pub verified_token_id: Option<String>,
    pub accounts: Vec<ObservedAccount>,
    pub workers: Vec<ObservedWorker>,
    pub authorities: Vec<AuthorityObservation>,
    pub problems: Vec<String>,
}

/// A deliberately narrow GET response used by the semantic provider client.
/// Implementations must redact transport errors and never include an
/// Authorization header or credential value in them.
#[derive(Clone, PartialEq, Eq)]
pub struct GetResponse {
    pub status: u16,
    pub body: String,
    pub redirected_to: Option<String>,
}

impl std::fmt::Debug for GetResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GetResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("redirected_to", &self.redirected_to)
            .finish()
    }
}

/// The only transport capability exposed to the Cloudflare adapter. There is
/// no arbitrary method, URL, body, or header API.
pub trait GetTransport {
    fn get(&mut self, path: &str, token: &str) -> Result<GetResponse, String>;
}

/// Production HTTPS transport. It is constructed with a fixed Cloudflare API
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
            .user_agent("pico/0.1 cloudflare-read-only")
            .build()
            .map_err(|_| "cloudflare transport initialization failed".to_string())?;
        Ok(Self { client })
    }
}

impl GetTransport for HttpsTransport {
    fn get(&mut self, path: &str, token: &str) -> Result<GetResponse, String> {
        if !is_allowlisted_path(path) {
            return Err("cloudflare operation is not allowlisted".to_string());
        }
        let response = self
            .client
            .get(format!("{API_ORIGIN}{path}"))
            .bearer_auth(token)
            .send()
            .map_err(|_| "cloudflare read request failed".to_string())?;
        let status = response.status().as_u16();
        let redirected_to = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let bytes = response
            .bytes()
            .map_err(|_| "cloudflare response could not be read".to_string())?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err("cloudflare response exceeded bounded size".to_string());
        }
        let body = String::from_utf8(bytes.to_vec())
            .map_err(|_| "cloudflare response was not valid UTF-8".to_string())?;
        Ok(GetResponse {
            status,
            body,
            redirected_to,
        })
    }
}

/// A transport that performs no network access. It is the default safe
/// fallback for local scans and is useful when the caller has no authority to
/// make a provider request.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableTransport;

impl GetTransport for UnavailableTransport {
    fn get(&mut self, _path: &str, _token: &str) -> Result<GetResponse, String> {
        Err("cloudflare provider transport unavailable".to_string())
    }
}

/// Typed Cloudflare operations. The token is borrowed only for the duration
/// of each request and is never stored by this client.
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
        if !is_allowlisted_path(path) {
            return Err("cloudflare operation is not allowlisted".to_string());
        }
        self.requests = self.requests.saturating_add(1);
        if self.requests > MAX_REQUESTS {
            return Err("cloudflare request budget exceeded".to_string());
        }
        self.transport.get(path, token)
    }

    pub fn inspect(&mut self, token: &str, fingerprint: &str) -> ProviderResult {
        let mut result = ProviderResult {
            credential_fingerprint: fingerprint.to_string(),
            ..ProviderResult::default()
        };

        let verify = match self.get("/user/tokens/verify", token) {
            Ok(response) => response,
            Err(error) => {
                result.problems.push(error);
                return result;
            }
        };
        if verify.redirected_to.is_some() {
            result
                .problems
                .push("cloudflare redirect rejected".to_string());
            return result;
        }
        let verify_json = match parse_success(&verify) {
            Ok(value) => value,
            Err(error) => {
                result.problems.push(error);
                return result;
            }
        };
        let Some(verify_result) = verify_json.get("result") else {
            result
                .problems
                .push("cloudflare verification result missing".to_string());
            return result;
        };
        let token_id = verify_result
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .map(str::to_string);
        let status = verify_result.get("status").and_then(Value::as_str);
        result.verified_token_id = token_id.clone();
        result.credential_status = Some(match status {
            Some("active") => CredentialStatus::Active,
            Some("disabled") | Some("expired") => CredentialStatus::Inactive,
            _ => CredentialStatus::Unknown,
        });
        if result.credential_status != Some(CredentialStatus::Active) {
            return result;
        }
        let Some(token_id) = token_id else {
            result
                .problems
                .push("verified token identifier missing".to_string());
            return result;
        };

        // Reading the token's own policy is required only to resolve write
        // authority. A failure here must not discard the safe, read-only
        // account and Worker facts the token is still permitted to list, so it
        // is recorded as a problem and treated as an empty policy instead of
        // aborting the whole inspection.
        let token_details: Option<Value> =
            match self.get(&format!("/user/tokens/{token_id}"), token) {
                Ok(response) => match parse_success(&response) {
                    Ok(value) => value.get("result").cloned(),
                    Err(error) => {
                        result.problems.push(error);
                        None
                    }
                },
                Err(error) => {
                    result.problems.push(error);
                    None
                }
            };

        let permission_groups = match self.get("/user/tokens/permission_groups", token) {
            Ok(response) => match parse_success(&response) {
                Ok(value) => permission_group_map(&value),
                Err(error) => {
                    result.problems.push(error);
                    HashMap::new()
                }
            },
            Err(error) => {
                result.problems.push(error);
                HashMap::new()
            }
        };
        let write_group_ids: HashSet<String> = permission_groups
            .iter()
            .filter(|(_, name)| is_workers_write(name))
            .map(|(id, _)| id.clone())
            .collect();
        let policy_facts = policy_facts(token_details.as_ref(), &write_group_ids);

        let accounts = match self.get("/accounts", token) {
            Ok(response) => match parse_success(&response) {
                Ok(value) => value
                    .get("result")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
                Err(error) => {
                    result.problems.push(error);
                    Vec::new()
                }
            },
            Err(error) => {
                // An account-list permission failure does not erase explicit
                // account selectors already present in the token policy.
                // Those IDs remain safe targets for bounded Worker listing.
                result.problems.push(error);
                Vec::new()
            }
        };
        let mut account_ids: HashSet<String> = accounts
            .iter()
            .filter_map(|account| account.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        for account_id in &policy_facts.explicit_accounts {
            account_ids.insert(account_id.clone());
        }
        let mut account_rows = accounts;
        for account_id in account_ids {
            if !account_rows.iter().any(|account| {
                account.get("id").and_then(Value::as_str) == Some(account_id.as_str())
            }) {
                account_rows.push(serde_json::json!({"id": account_id}));
            }
        }
        for account in account_rows {
            let Some(account_id) = account
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| valid_id(id))
            else {
                continue;
            };
            let scope = policy_facts.scope_for(account_id);
            let source_locator = "/accounts".to_string();
            result.accounts.push(ObservedAccount {
                account_id: account_id.to_string(),
                name: account
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                account_type: account
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                scope,
                source_locator: source_locator.clone(),
            });
            let workers_path = format!("/accounts/{account_id}/workers/scripts");
            let response = match self.get(&workers_path, token) {
                Ok(response) => response,
                Err(error) => {
                    result.problems.push(error);
                    continue;
                }
            };
            let workers_json = match parse_success(&response) {
                Ok(value) => value,
                Err(error) => {
                    result.problems.push(error);
                    continue;
                }
            };
            for worker in workers_json
                .get("result")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(script_name) = worker.get("id").and_then(Value::as_str) else {
                    continue;
                };
                let observed = ObservedWorker {
                    account_id: account_id.to_string(),
                    script_name: script_name.to_string(),
                    worker_tag: worker
                        .get("tag")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    source_locator: workers_path.clone(),
                    sink_impact: None,
                };
                let worker_key = observed.canonical_key();
                let (
                    state,
                    resolution,
                    permission_state,
                    unknown_reasons,
                    zone_scoped,
                    granted_permissions,
                ) = authority_for(&policy_facts, scope, &write_group_ids);
                result.workers.push(observed);
                result.authorities.push(AuthorityObservation {
                    account_id: account_id.to_string(),
                    worker_key,
                    state,
                    resolution,
                    permission_state: permission_state.to_string(),
                    scope_state: scope,
                    unknown_reasons,
                    granted_permissions,
                    zone_scoped,
                    source_locator: workers_path.clone(),
                });
            }
        }
        result
    }
}

/// Perform the bounded live Cloudflare inspection. Callers should invoke this
/// only after Sprint 005 has established credential reachability. The token is
/// borrowed for the duration of the client and never appears in the result.
pub fn inspect_live(token: &str, fingerprint: &str) -> ProviderResult {
    match HttpsTransport::new() {
        Ok(transport) => Client::new(transport).inspect(token, fingerprint),
        Err(error) => ProviderResult {
            credential_fingerprint: fingerprint.to_string(),
            problems: vec![error],
            ..ProviderResult::default()
        },
    }
}

fn is_allowlisted_path(path: &str) -> bool {
    path == "/user/tokens/verify"
        || path == "/user/tokens/permission_groups"
        || path == "/accounts"
        || (path.starts_with("/user/tokens/")
            && path.len() > "/user/tokens/".len()
            && !path.contains('?')
            && valid_id(&path["/user/tokens/".len()..]))
        || (path.starts_with("/accounts/")
            && path.ends_with("/workers/scripts")
            && valid_id(&path["/accounts/".len()..path.len() - "/workers/scripts".len() - 1]))
}

fn valid_id(value: &str) -> bool {
    (16..=64).contains(&value.len()) && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn parse_success(response: &GetResponse) -> Result<Value, String> {
    if response.redirected_to.is_some() {
        return Err("cloudflare redirect rejected".to_string());
    }
    if !(200..300).contains(&response.status) {
        return Err(format!("cloudflare read returned HTTP {}", response.status));
    }
    serde_json::from_str(&response.body)
        .map_err(|_| "cloudflare response was malformed".to_string())
}

fn permission_group_map(value: &Value) -> HashMap<String, String> {
    value
        .get("result")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some((
                item.get("id")?.as_str()?.to_string(),
                item.get("name")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

fn is_workers_write(name: &str) -> bool {
    matches!(name, "Workers Scripts Write" | "Workers Scripts Edit")
}

#[derive(Debug, Default)]
struct PolicyFacts {
    write_allowed: bool,
    write_denied: bool,
    explicit_accounts: HashSet<String>,
    all_accounts: bool,
    scope_known: bool,
    /// Zone ids pulled from `com.cloudflare.api.account.zone.<id>` resources.
    explicit_zones: HashSet<String>,
    /// A `*` zone resource was observed (all zones in the policy's account).
    all_zones: bool,
    /// Names of permission groups that grant Workers write.
    granted_write_groups: Vec<String>,
    /// Names of read-only permission groups observed on the token policy.
    granted_read_groups: Vec<String>,
}

impl PolicyFacts {
    fn scope_for(&self, account: &str) -> ScopeState {
        if self.explicit_accounts.contains(account) || self.all_accounts {
            ScopeState::InScope
        } else if !self.explicit_zones.is_empty() || self.all_zones {
            // A zone-scoped grant pragmatically places the account in scope for
            // the zone's Workers even though no account-wide id was enumerated.
            ScopeState::InScope
        } else if self.scope_known {
            ScopeState::OutOfScope
        } else {
            ScopeState::Unknown
        }
    }
}

fn is_workers_read(name: &str) -> bool {
    name == "Workers Scripts Read"
}

fn policy_facts(token: Option<&Value>, write_group_ids: &HashSet<String>) -> PolicyFacts {
    let mut facts = PolicyFacts::default();
    let Some(policies) = token
        .and_then(|token| token.get("policies"))
        .and_then(Value::as_array)
    else {
        return facts;
    };
    for policy in policies {
        let allow = policy.get("effect").and_then(Value::as_str) == Some("allow");
        let deny = policy.get("effect").and_then(Value::as_str) == Some("deny");
        let groups = policy.get("permission_groups").and_then(Value::as_array);
        let group_items: Vec<&Value> = groups.into_iter().flatten().collect();
        let has_write = group_items.iter().any(|group| {
            group
                .get("id")
                .and_then(Value::as_str)
                .map(|id| write_group_ids.contains(id))
                .unwrap_or(false)
                || group
                    .get("name")
                    .and_then(Value::as_str)
                    .map(is_workers_write)
                    .unwrap_or(false)
        });
        let write_names: Vec<String> = group_items
            .iter()
            .filter(|group| {
                group
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| write_group_ids.contains(id))
                    .unwrap_or(false)
                    || group
                        .get("name")
                        .and_then(Value::as_str)
                        .map(is_workers_write)
                        .unwrap_or(false)
            })
            .filter_map(|group| {
                group
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        let read_names: Vec<String> = group_items
            .iter()
            .filter(|group| {
                group
                    .get("name")
                    .and_then(Value::as_str)
                    .map(is_workers_read)
                    .unwrap_or(false)
            })
            .filter_map(|group| {
                group
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        if has_write && allow {
            facts.write_allowed = true;
        }
        if has_write && deny {
            facts.write_denied = true;
        }
        if has_write {
            facts.granted_write_groups.extend(write_names);
        }
        if !read_names.is_empty() {
            facts.granted_read_groups.extend(read_names.clone());
        }
        // Scope is relevant to mutation only when the same policy carries the
        // Workers write permission, or is a read-only grant. A read-only policy
        // must not accidentally make a target account appear in-scope for
        // mutation through an account-wide id, but a zone grant still scopes
        // the account for the zone's Workers.
        if has_write || !read_names.is_empty() {
            if let Some(resources) = policy.get("resources") {
                let mut ids = Vec::new();
                collect_account_ids(resources, &mut ids);
                let mut zones = Vec::new();
                collect_zone_ids(resources, &mut zones);
                if !ids.is_empty() {
                    facts.scope_known = true;
                    facts.explicit_accounts.extend(ids.clone());
                }
                if !zones.is_empty() {
                    facts.scope_known = true;
                    facts.explicit_zones.extend(zones.clone());
                }
                if resources
                    .to_string()
                    .contains("com.cloudflare.api.account.zone")
                    && resources.to_string().contains('*')
                {
                    facts.scope_known = true;
                    facts.all_zones = true;
                }
                if ids.is_empty()
                    && zones.is_empty()
                    && !facts.all_zones
                    && resources.to_string().contains('*')
                {
                    facts.scope_known = true;
                    facts.all_accounts = true;
                }
            }
        }
    }
    facts
}

fn collect_account_ids(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(string) if valid_id(string) => output.push(string.clone()),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_account_ids(value, output)),
        Value::Object(map) => {
            for (key, value) in map {
                if valid_id(key) {
                    output.push(key.clone());
                }
                collect_account_ids(value, output);
            }
        }
        _ => {}
    }
}

fn collect_zone_ids(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if let Some(zone_id) = key.strip_prefix("com.cloudflare.api.account.zone.") {
                    if valid_id(zone_id) {
                        output.push(zone_id.to_string());
                    }
                }
                collect_zone_ids(nested, output);
            }
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_zone_ids(value, output)),
        _ => {}
    }
}

fn authority_for(
    facts: &PolicyFacts,
    scope: ScopeState,
    write_group_ids: &HashSet<String>,
) -> (
    RelationshipState,
    AuthorityResolution,
    &'static str,
    Vec<String>,
    bool,
    Vec<String>,
) {
    let zone_scoped = !facts.explicit_zones.is_empty() || facts.all_zones;
    let granted_permissions = if facts.write_allowed {
        facts.granted_write_groups.clone()
    } else if !facts.granted_read_groups.is_empty() {
        facts.granted_read_groups.clone()
    } else {
        Vec::new()
    };
    let mut unknown = Vec::new();
    if facts.write_denied || scope == ScopeState::OutOfScope {
        return (
            RelationshipState::Blocked,
            AuthorityResolution::Exact,
            "DENIED_OR_OUT_OF_SCOPE",
            unknown,
            false,
            granted_permissions,
        );
    }
    if facts.write_allowed && scope == ScopeState::InScope && !write_group_ids.is_empty() {
        return (
            RelationshipState::Derived,
            AuthorityResolution::Exact,
            "WORKERS_SCRIPTS_WRITE",
            unknown,
            zone_scoped,
            granted_permissions,
        );
    }
    if !facts.scope_known {
        unknown.push("ACCOUNT_SCOPE_UNRESOLVED".to_string());
    }
    if !facts.write_allowed {
        unknown.push("WORKERS_SCRIPTS_WRITE_UNRESOLVED".to_string());
    }
    let resolution = if facts.write_allowed && scope != ScopeState::OutOfScope {
        AuthorityResolution::Scoped
    } else if !write_group_ids.is_empty() {
        AuthorityResolution::BehavioralReadOnly
    } else {
        AuthorityResolution::Unknown
    };
    (
        RelationshipState::Unknown,
        resolution,
        "READ_OR_UNKNOWN",
        unknown,
        zone_scoped,
        granted_permissions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureTransport {
        responses: HashMap<String, GetResponse>,
        seen: Vec<String>,
    }

    impl GetTransport for FixtureTransport {
        fn get(&mut self, path: &str, _token: &str) -> Result<GetResponse, String> {
            self.seen.push(path.to_string());
            self.responses
                .get(path)
                .cloned()
                .ok_or_else(|| "fixture response missing".to_string())
        }
    }

    fn response(body: &str) -> GetResponse {
        GetResponse {
            status: 200,
            body: body.to_string(),
            redirected_to: None,
        }
    }

    #[test]
    fn exact_write_authority_is_derived_from_policy_scope_and_worker() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"write-id"}],"resources":{"com.cloudflare.api.account":{"account-1234567890123456":"*"}}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(result.authorities[0].resolution, AuthorityResolution::Exact);
        assert_eq!(result.authorities[0].state, RelationshipState::Derived);
        assert_eq!(
            result.workers[0].canonical_key(),
            "cloudflare:worker:account-1234567890123456:immutable-worker-1"
        );
    }

    #[test]
    fn read_only_listing_never_becomes_write_authority() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("synthetic", "fingerprint");
        assert_eq!(
            result.authorities[0].resolution,
            AuthorityResolution::Unknown
        );
        assert_eq!(result.authorities[0].state, RelationshipState::Unknown);
    }

    #[test]
    fn read_only_listing_survives_policy_read_failure() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        // Token details denied: inspection must NOT bail; account and Worker
        // facts the token can still read must be projected, authority Unknown.
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            GetResponse {
                status: 403,
                body: r#"{"success":false,"errors":[{"code":1000,"message":"not authorized"}]}"#
                    .to_string(),
                redirected_to: None,
            },
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("synthetic", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(result.accounts.len(), 1);
        assert_eq!(result.workers.len(), 1);
        assert_eq!(result.authorities[0].state, RelationshipState::Unknown);
        assert!(!result.problems.is_empty());
    }

    #[test]
    fn repeated_scan_produces_stable_canonical_identities() {
        // Same observed Worker must yield an identical canonical_key across
        // repeated scans (no scan_id, timestamp, or random id participates in
        // the key). This guards against canonical_key churn between runs.
        let first = ObservedWorker {
            account_id: "account-1234567890123456".to_string(),
            script_name: "worker".to_string(),
            worker_tag: Some("immutable-worker-1".to_string()),
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
            sink_impact: None,
        };
        let second = ObservedWorker {
            account_id: "account-1234567890123456".to_string(),
            script_name: "worker".to_string(),
            worker_tag: Some("immutable-worker-1".to_string()),
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
            sink_impact: None,
        };
        assert_eq!(first.canonical_key(), second.canonical_key());
        assert_eq!(
            first.canonical_key(),
            "cloudflare:worker:account-1234567890123456:immutable-worker-1"
        );

        // The tag-less (name-scoped) variant must also be stable across scans.
        let a = ObservedWorker {
            account_id: "account-1234567890123456".to_string(),
            script_name: "daily-job".to_string(),
            worker_tag: None,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
            sink_impact: None,
        };
        let b = ObservedWorker {
            account_id: "account-1234567890123456".to_string(),
            script_name: "daily-job".to_string(),
            worker_tag: None,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
            sink_impact: None,
        };
        assert_eq!(a.canonical_key(), b.canonical_key());
        assert_eq!(
            a.canonical_key(),
            "cloudflare:worker:account-1234567890123456:name:daily-job"
        );
        // Two distinct workers must not collide.
        assert_ne!(first.canonical_key(), a.canonical_key());
    }

    #[test]
    fn client_rejects_unallowlisted_paths() {
        assert!(!is_allowlisted_path("/accounts/a/workers/scripts/worker"));
        assert!(!is_allowlisted_path("/user/tokens/verify?x=1"));
        assert!(is_allowlisted_path("/user/tokens/verify"));
    }

    #[test]
    fn scoped_write_with_unresolved_account_scope() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"write-id","name":"Workers Scripts Write"}],"resources":{}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(
            result.authorities[0].resolution,
            AuthorityResolution::Scoped
        );
        assert_eq!(result.authorities[0].state, RelationshipState::Unknown);
    }

    #[test]
    fn behavioral_read_only_when_policy_readable_no_write() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(
            result.authorities[0].resolution,
            AuthorityResolution::BehavioralReadOnly
        );
        assert_eq!(result.authorities[0].state, RelationshipState::Unknown);
        assert!(result.authorities[0]
            .unknown_reasons
            .contains(&"WORKERS_SCRIPTS_WRITE_UNRESOLVED".to_string()));
    }

    #[test]
    fn blocked_authority_is_exact() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"deny","permission_groups":[{"id":"write-id","name":"Workers Scripts Write"}],"resources":{"com.cloudflare.api.account":{"account-1234567890123456":"*"}}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(result.authorities[0].state, RelationshipState::Blocked);
        assert_eq!(result.authorities[0].resolution, AuthorityResolution::Exact);
        assert_eq!(
            result.authorities[0].permission_state,
            "DENIED_OR_OUT_OF_SCOPE"
        );
    }

    #[test]
    fn r2_zone_scoped_write_resolves_to_exact_with_zone_marker() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"write-id","name":"Workers Scripts Write"}],"resources":{"com.cloudflare.api.account.zone.zone-1234567890123456":"*"}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        let authority = &result.authorities[0];
        assert_eq!(authority.resolution, AuthorityResolution::Exact);
        assert_eq!(authority.state, RelationshipState::Derived);
        assert!(authority.zone_scoped);
        assert_eq!(authority.granted_permissions, vec!["Workers Scripts Write"]);
    }

    #[test]
    fn r3_read_only_permission_group_resolves_to_behavioral_read_only() {
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"read-id","name":"Workers Scripts Read"}],"resources":{}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"},{"id":"read-id","name":"Workers Scripts Read"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        let authority = &result.authorities[0];
        assert_eq!(
            authority.resolution,
            AuthorityResolution::BehavioralReadOnly
        );
        assert_eq!(authority.state, RelationshipState::Unknown);
        assert_eq!(authority.granted_permissions, vec!["Workers Scripts Read"]);
        assert!(!authority.zone_scoped);
    }

    #[test]
    fn r5_authority_tier_table() {
        let mut write_group_ids = HashSet::new();
        write_group_ids.insert("write-id".to_string());

        // write + account scope => Exact/Derived
        let facts = PolicyFacts {
            write_allowed: true,
            granted_write_groups: vec!["Workers Scripts Write".to_string()],
            explicit_accounts: {
                let mut set = HashSet::new();
                set.insert("account-1234567890123456".to_string());
                set
            },
            ..PolicyFacts::default()
        };
        let (state, resolution, _, _, _, granted) =
            authority_for(&facts, ScopeState::InScope, &write_group_ids);
        assert_eq!(resolution, AuthorityResolution::Exact);
        assert_eq!(state, RelationshipState::Derived);
        assert_eq!(granted, vec!["Workers Scripts Write".to_string()]);

        // write + unresolved scope => Scoped
        let facts = PolicyFacts {
            write_allowed: true,
            ..PolicyFacts::default()
        };
        let (state, resolution, _, _, _, _) =
            authority_for(&facts, ScopeState::Unknown, &write_group_ids);
        assert_eq!(resolution, AuthorityResolution::Scoped);
        assert_eq!(state, RelationshipState::Unknown);

        // read-only (write catalog present, policy grants read) => BehavioralReadOnly
        let facts = PolicyFacts {
            granted_read_groups: vec!["Workers Scripts Read".to_string()],
            ..PolicyFacts::default()
        };
        let (state, resolution, _, _, _, granted) =
            authority_for(&facts, ScopeState::Unknown, &write_group_ids);
        assert_eq!(resolution, AuthorityResolution::BehavioralReadOnly);
        assert_eq!(state, RelationshipState::Unknown);
        assert_eq!(granted, vec!["Workers Scripts Read".to_string()]);

        // denied => Blocked/Exact(DENIED)
        let facts = PolicyFacts {
            write_denied: true,
            explicit_accounts: {
                let mut set = HashSet::new();
                set.insert("account-1234567890123456".to_string());
                set
            },
            ..PolicyFacts::default()
        };
        let (state, resolution, permission_state, _, _, _) =
            authority_for(&facts, ScopeState::InScope, &write_group_ids);
        assert_eq!(resolution, AuthorityResolution::Exact);
        assert_eq!(state, RelationshipState::Blocked);
        assert_eq!(permission_state, "DENIED_OR_OUT_OF_SCOPE");

        // none => Unknown
        let facts = PolicyFacts::default();
        let empty = HashSet::new();
        let (state, resolution, _, _, _, granted) =
            authority_for(&facts, ScopeState::Unknown, &empty);
        assert_eq!(resolution, AuthorityResolution::Unknown);
        assert_eq!(state, RelationshipState::Unknown);
        assert!(granted.is_empty());
    }

    #[test]
    fn r8_battery_credential_types_scope_perm_deny_expired_multiaccount_providerfailure() {
        // (a) Provider failure: token-details 403 while the token is active.
        // Accounts and Workers must survive; authorities are Unknown.
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            GetResponse {
                status: 403,
                body: r#"{"success":false,"errors":[{"code":1000,"message":"not authorized"}]}"#
                    .to_string(),
                redirected_to: None,
            },
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"one"},{"id":"account-2234567890123456","name":"two"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker-a","tag":"immutable-worker-1"}]}"#),
        );
        responses.insert(
            "/accounts/account-2234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker-b","tag":"immutable-worker-2"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.credential_status, Some(CredentialStatus::Active));
        assert_eq!(result.accounts.len(), 2);
        assert_eq!(result.workers.len(), 2);
        assert_eq!(result.authorities.len(), 2);
        assert!(result
            .authorities
            .iter()
            .all(|a| a.state == RelationshipState::Unknown));
        assert!(!result.problems.is_empty());

        // (b) Expired/inactive token: inspection must short-circuit after
        // status, leaving no accounts or authorities.
        let mut inactive = HashMap::new();
        inactive.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"expired"}}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses: inactive,
            seen: Vec::new(),
        });
        let expired = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(expired.credential_status, Some(CredentialStatus::Inactive));
        assert!(expired.accounts.is_empty());
        assert!(expired.authorities.is_empty());

        // (c) Deny policy across multiple accounts: the denied account resolves
        // Blocked/Exact while an unscoped account stays Unknown.
        let mut responses = HashMap::new();
        responses.insert(
            "/user/tokens/verify".to_string(),
            response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
        );
        responses.insert(
            "/user/tokens/token-1234567890123456".to_string(),
            response(r#"{"result":{"policies":[{"effect":"deny","permission_groups":[{"id":"write-id","name":"Workers Scripts Write"}],"resources":{"com.cloudflare.api.account":{"account-1234567890123456":"*"}}}]}}"#),
        );
        responses.insert(
            "/user/tokens/permission_groups".to_string(),
            response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
        );
        responses.insert(
            "/accounts".to_string(),
            response(r#"{"result":[{"id":"account-1234567890123456","name":"one"},{"id":"account-2234567890123456","name":"two"}]}"#),
        );
        responses.insert(
            "/accounts/account-1234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker-a","tag":"immutable-worker-1"}]}"#),
        );
        responses.insert(
            "/accounts/account-2234567890123456/workers/scripts".to_string(),
            response(r#"{"result":[{"id":"worker-b","tag":"immutable-worker-2"}]}"#),
        );
        let mut client = Client::new(FixtureTransport {
            responses,
            seen: Vec::new(),
        });
        let result = client.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result.accounts.len(), 2);
        assert_eq!(result.authorities.len(), 2);
        let denied = result
            .authorities
            .iter()
            .find(|a| a.account_id == "account-1234567890123456")
            .unwrap();
        assert_eq!(denied.state, RelationshipState::Blocked);
        assert_eq!(denied.resolution, AuthorityResolution::Exact);
        // A deny policy is a global negation: every enumerated account resolves
        // Blocked/Exact, not merely the explicitly named one.
        let other = result
            .authorities
            .iter()
            .find(|a| a.account_id == "account-2234567890123456")
            .unwrap();
        assert_eq!(other.state, RelationshipState::Blocked);
    }

    #[test]
    fn r9_authority_stable_across_identical_token_info() {
        fn fixture() -> HashMap<String, GetResponse> {
            let mut responses = HashMap::new();
            responses.insert(
                "/user/tokens/verify".to_string(),
                response(r#"{"result":{"id":"token-1234567890123456","status":"active"}}"#),
            );
            responses.insert(
                "/user/tokens/token-1234567890123456".to_string(),
                response(r#"{"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"write-id","name":"Workers Scripts Write"}],"resources":{"com.cloudflare.api.account":{"account-1234567890123456":"*"}}}]}}"#),
            );
            responses.insert(
                "/user/tokens/permission_groups".to_string(),
                response(r#"{"result":[{"id":"write-id","name":"Workers Scripts Write"}]}"#),
            );
            responses.insert(
                "/accounts".to_string(),
                response(r#"{"result":[{"id":"account-1234567890123456","name":"test"}]}"#),
            );
            responses.insert(
                "/accounts/account-1234567890123456/workers/scripts".to_string(),
                response(r#"{"result":[{"id":"worker","tag":"immutable-worker-1"}]}"#),
            );
            responses
        }
        let mut first = Client::new(FixtureTransport {
            responses: fixture(),
            seen: Vec::new(),
        });
        let result_one = first.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        let mut second = Client::new(FixtureTransport {
            responses: fixture(),
            seen: Vec::new(),
        });
        let result_two = second.inspect("TEST_SECRET_SHOULD_NOT_PERSIST", "fingerprint");
        assert_eq!(result_one.authorities, result_two.authorities);
        assert_eq!(result_one.accounts, result_two.accounts);
    }
}
