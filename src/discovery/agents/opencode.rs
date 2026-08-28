//! Bounded OpenCode actor and Bash-policy discovery.
//!
//! OpenCode documents project `opencode.json` / `opencode.jsonc`, the same
//! names under `.opencode/`, and user configuration under
//! `~/.config/opencode/`. We validate only that a candidate is a configuration
//! object and retain only the small permission projection required to resolve
//! the default actor's Bash policy. Raw configuration is discarded.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedWorker, ProviderResult,
    ScopeState,
};
use crate::discovery::{
    CapabilityScope, DiscoveryResult, EffectiveBashPermission, EnvironmentReachability,
    McpTransport, ObservedActor, ObservedBashCapability, ObservedCredential, ObservedMcpServer,
    PermissionAction,
};
use crate::domain::RelationshipState;
use crate::shared::PicoError;

const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];
const CLOUDFLARE_TOKEN_ENV: &str = "CLOUDFLARE_API_TOKEN";

/// Raw credential material is kept behind this non-serializable, redacted
/// handle and zeroized when the adapter releases it.
struct TransientCredential(String);

impl TransientCredential {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn fingerprint(&self) -> String {
        fingerprint(&self.0)
    }
}

impl std::fmt::Debug for TransientCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransientCredential(REDACTED)")
    }
}

impl Drop for TransientCredential {
    fn drop(&mut self) {
        let bytes = unsafe { self.0.as_bytes_mut() };
        for byte in bytes {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Discover a configured OpenCode actor from exact documented locations.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    discover_with_environment(workspace, home, None, EnvironmentReachability::Unknown)
}

pub fn discover_with_environment(
    workspace: &Path,
    home: Option<&Path>,
    explicit_environment: Option<&[(&str, &str)]>,
    environment_reachability: EnvironmentReachability,
) -> Result<DiscoveryResult, PicoError> {
    let mut result = DiscoveryResult::default();
    let mut candidates = Vec::new();
    if let Some(home) = home {
        candidates.extend(user_candidates(home));
    }
    candidates.extend(project_candidates(workspace));

    let mut effective = Value::Object(Default::default());
    let mut locators = Vec::new();

    for (path, locator) in candidates {
        if !path.is_file() {
            continue;
        }
        match parse_config_object(&path) {
            Ok(config) => {
                merge_json(&mut effective, config);
                locators.push(locator.clone());
                result.actors.push(ObservedActor {
                    provider: "opencode",
                    source_type: "opencode_config",
                    source_locator: locator,
                });
            }
            Err(problem) => result.problems.push(format!("{locator}: {problem}")),
        }
    }

    if !result.actors.is_empty() && result.problems.is_empty() {
        match resolve_effective_bash(&effective) {
            Ok((permission, scope, effective_state)) => {
                result.bash_capabilities.push(ObservedBashCapability {
                    provider: "opencode",
                    permission,
                    scope,
                    effective_state,
                    // OpenCode's --auto/TUI session mode is not available from
                    // static configuration. ASK is therefore never described as
                    // automatic execution by this adapter.
                    runtime_mode: "UNKNOWN",
                    source_locator: locators.join(","),
                })
            }
            Err(problem) => result.problems.push(problem),
        }
        match parse_mcp_servers(&effective, &locators) {
            Ok(servers) => {
                result.mcp_servers = servers;
                result.github_surfaces =
                    crate::discovery::mcp::github::classify(&result.mcp_servers);
            }
            Err(problem) => result.problems.push(problem),
        }
        for surface in &mut result.github_surfaces {
            for tool in &mut surface.tools {
                let permission_name = format!("{}_{}", surface.server.name, tool.name);
                let (permission, pattern) = resolve_mcp_permission(&effective, &permission_name);
                tool.permission = permission;
                tool.permission_pattern = pattern;
            }
        }
        let environment_value = explicit_environment
            .and_then(|pairs| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == CLOUDFLARE_TOKEN_ENV)
                    .map(|(_, value)| (*value).to_string())
            })
            .or_else(|| std::env::var(CLOUDFLARE_TOKEN_ENV).ok())
            .map(TransientCredential::new);
        if let Some(value) = environment_value {
            if !value.is_empty()
                && !result
                    .credentials
                    .iter()
                    .any(|credential| credential.fingerprint == value.fingerprint())
            {
                result.credentials.push(ObservedCredential {
                    provider: "cloudflare",
                    credential_type: classify_credential_type(&value.0),
                    source_type: "environment",
                    source_locator: CLOUDFLARE_TOKEN_ENV.to_string(),
                    fingerprint: value.fingerprint(),
                    environment: environment_reachability,
                });
            }
        }
        if let Some(value) = project_dotenv_token(workspace) {
            let value_fingerprint = value.fingerprint();
            if !result
                .credentials
                .iter()
                .any(|credential| credential.fingerprint == value_fingerprint)
            {
                result.credentials.push(ObservedCredential {
                    provider: "cloudflare",
                    credential_type: classify_credential_type(&value.0),
                    source_type: "project_dotenv",
                    source_locator: ".env:CLOUDFLARE_API_TOKEN".to_string(),
                    fingerprint: value_fingerprint.clone(),
                    environment: EnvironmentReachability::Proven,
                });
            }
            // The exact project-root dotenv source is the bounded local
            // contract that proves Bash reachability. Provider access remains
            // transient and emits only safe normalized facts.
            let provider_reachable = environment_reachability == EnvironmentReachability::Proven
                && result.bash_capabilities.first().is_some_and(|capability| {
                    capability.permission == PermissionAction::Allow
                        && capability.scope == CapabilityScope::Unrestricted
                });
            if provider_reachable {
                if classify_credential_type(&value.0) == "api_key" {
                    // A global API key cannot be resolved through the scoped
                    // token endpoints, so synthesize the bounded, unverified
                    // resolution directly. The raw key never leaves this scope.
                    let global_worker = ObservedWorker {
                        account_id: "global".to_string(),
                        script_name: "*".to_string(),
                        worker_tag: None,
                        source_locator: "credential:cloudflare:global_api_key".to_string(),
                        sink_impact: Some("UNKNOWN".to_string()),
                    };
                    let global_key = global_worker.canonical_key();
                    result.cloudflare = Some(ProviderResult {
                        credential_fingerprint: value_fingerprint.clone(),
                        credential_status: Some(CredentialStatus::Active),
                        verified_token_id: None,
                        accounts: Vec::new(),
                        workers: vec![global_worker],
                        authorities: vec![AuthorityObservation {
                            account_id: "global".to_string(),
                            worker_key: global_key,
                            state: RelationshipState::Derived,
                            resolution: AuthorityResolution::Exact,
                            permission_state: "GLOBAL_API_KEY".to_string(),
                            scope_state: ScopeState::InScope,
                            unknown_reasons: vec!["GLOBAL_KEY_UNVERIFIED".to_string()],
                            granted_permissions: Vec::new(),
                            zone_scoped: false,
                            source_locator: "credential:cloudflare:global_api_key".to_string(),
                        }],
                        problems: Vec::new(),
                    });
                } else {
                    result.cloudflare = Some(crate::discovery::cloudflare::inspect_live(
                        &value.0,
                        &value_fingerprint,
                    ));
                }
            }
        }
    }
    Ok(result)
}

/// Read only the exact project-root dotenv file. This is deliberately not a
/// recursive dotenv search or a shell-profile evaluator.
fn project_dotenv_token(workspace: &Path) -> Option<TransientCredential> {
    let root = workspace
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .unwrap_or(workspace);
    let contents = fs::read_to_string(root.join(".env")).ok()?;
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim() != CLOUDFLARE_TOKEN_ENV {
            return None;
        }
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
            })
            .unwrap_or(value)
            .trim();
        (!value.is_empty()).then(|| TransientCredential::new(value.to_string()))
    })
}

/// Classify a Cloudflare credential by its lexical shape. This is a best-effort
/// heuristic used only to choose the correct safe persistence projection; it is
/// never a substitute for live verification.
///
/// * `cfut_` prefixes identify API tokens.
/// * `cwo_` / `fou_` prefixes, or a long (>=40) non-global-key token, identify
///   OAuth tokens.
/// * A long alphanumeric/hex string (>=32, not a token/oauth prefix) identifies
///   a global API key.
/// * Anything unrecognized falls back to `api_token` (the safe default: it is
///   scoped and never assumed to carry global authority).
fn classify_credential_type(value: &str) -> &'static str {
    let candidate = value.trim();
    if candidate.starts_with("cfut_") {
        return "api_token";
    }
    if candidate.starts_with("cwo_") || candidate.starts_with("fou_") {
        return "oauth";
    }
    let alnum = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count();
    let global_key_shape = (32..=64).contains(&candidate.len())
        && candidate.chars().all(|c| c.is_ascii_alphanumeric());
    if alnum >= 40 && !global_key_shape {
        return "oauth";
    }
    if global_key_shape {
        return "api_key";
    }
    "api_token"
}

fn fingerprint(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"pico:credential:cloudflare:api_token:v1:");
    digest.update(value.as_bytes());
    let bytes = digest.finalize();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_mcp_servers(
    config: &Value,
    locators: &[String],
) -> Result<Vec<ObservedMcpServer>, String> {
    let Some(mcp) = config.get("mcp") else {
        return Ok(Vec::new());
    };
    let servers = mcp
        .get("servers")
        .and_then(Value::as_object)
        .or_else(|| mcp.as_object());
    let Some(servers) = servers else {
        return Err("mcp must be an object".to_string());
    };
    let mut output = Vec::new();
    for (name, value) in servers {
        let Some(server) = value.as_object() else {
            // V2 requires server objects. Legacy scalar values are ignored so
            // an unrelated `mcp` setting cannot create an actor.
            continue;
        };
        if !server.contains_key("type")
            && !server.contains_key("command")
            && !server.contains_key("url")
        {
            continue;
        }
        let transport = match server.get("type").and_then(Value::as_str) {
            Some("local") | Some("stdio") => McpTransport::Stdio,
            Some("remote") | Some("http") => McpTransport::Http,
            _ if server.contains_key("command") => McpTransport::Stdio,
            _ if server.contains_key("url") => McpTransport::Http,
            _ => McpTransport::Unknown,
        };
        let enabled = server.get("disabled").and_then(Value::as_bool) != Some(true)
            && server.get("enabled").and_then(Value::as_bool) != Some(false);
        let (safe_command, safe_identity) = normalize_command(server.get("command"));
        let safe_endpoint = server
            .get("url")
            .and_then(Value::as_str)
            .map(normalize_endpoint);
        let environment_keys = server
            .get("environment")
            .or_else(|| server.get("env"))
            .and_then(Value::as_object)
            .map(|env| env.keys().cloned().collect())
            .unwrap_or_default();
        let tool_declaration = extract_declaration(server, "tools");
        let toolset_declaration = extract_declaration(server, "toolsets");
        output.push(ObservedMcpServer {
            provider: "opencode",
            name: name.clone(),
            transport,
            enabled,
            source_locator: locators.join(","),
            safe_identity,
            safe_endpoint,
            safe_command,
            environment_keys,
            tool_declaration,
            toolset_declaration,
        });
    }
    Ok(output)
}

fn normalize_command(value: Option<&Value>) -> (Option<String>, Option<String>) {
    let parts = match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Some(Value::String(command)) => vec![command.clone()],
        _ => Vec::new(),
    };
    if parts.is_empty() {
        return (None, None);
    }
    let identity = parts.iter().find_map(|part| {
        let normalized = part.trim_end_matches('/');
        let image = normalized.split(':').next().unwrap_or(normalized);
        if image == "ghcr.io/github/github-mcp-server" || image == "github-mcp-server" {
            Some(image.to_string())
        } else {
            None
        }
    });
    let safe = parts
        .iter()
        .filter(|part| !looks_secret(part))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    (Some(safe), identity)
}

fn normalize_endpoint(url: &str) -> String {
    url.split('?')
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .to_string()
}

fn extract_declaration(server: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    server.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    })
}

fn looks_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "token",
        "secret",
        "password",
        "apikey",
        "authorization",
        "bearer",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn project_candidates(workspace: &Path) -> Vec<(PathBuf, String)> {
    let root = workspace
        .ancestors()
        .find(|candidate| candidate.join(".git").exists());
    let mut directories = match root {
        Some(root) => workspace
            .ancestors()
            .take_while(|candidate| *candidate != root)
            .chain(std::iter::once(root))
            .map(Path::to_path_buf)
            .collect::<Vec<_>>(),
        None => vec![workspace.to_path_buf()],
    };
    directories.reverse();

    let mut candidates = Vec::new();
    for directory in &directories {
        for name in CONFIG_NAMES {
            candidates.push((directory.join(name), format!("project:{name}")));
        }
    }
    for directory in &directories {
        for name in CONFIG_NAMES {
            candidates.push((
                directory.join(".opencode").join(name),
                format!("project:.opencode/{name}"),
            ));
        }
    }
    candidates
}

fn user_candidates(home: &Path) -> Vec<(PathBuf, String)> {
    CONFIG_NAMES
        .into_iter()
        .map(|name| {
            (
                home.join(".config").join("opencode").join(name),
                format!("user:{name}"),
            )
        })
        .collect()
}

fn parse_config_object(path: &Path) -> Result<Value, String> {
    let contents =
        fs::read_to_string(path).map_err(|err| format!("cannot read configuration: {err}"))?;
    let normalized = if path.extension().is_some_and(|ext| ext == "jsonc") {
        strip_jsonc(&contents)?
    } else {
        contents
    };
    match serde_json::from_str::<Value>(&normalized) {
        Ok(value @ Value::Object(_)) => Ok(value),
        Ok(_) => Err("configuration must be a JSON object".to_string()),
        Err(err) => Err(format!("invalid configuration: {err}")),
    }
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                if key == "mcp" {
                    merge_mcp_config(
                        base.entry(key)
                            .or_insert_with(|| Value::Object(Default::default())),
                        value,
                    );
                    continue;
                }
                match base.get_mut(&key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// OpenCode V2 replaces a matching project MCP server entry rather than
/// recursively retaining fields from a lower-precedence user entry.
fn merge_mcp_config(base: &mut Value, overlay: Value) {
    let overlay = match overlay {
        Value::Object(overlay) => overlay,
        other => {
            *base = other;
            return;
        }
    };
    let Some(base) = base.as_object_mut() else {
        *base = Value::Object(overlay);
        return;
    };
    for (key, value) in overlay {
        if key == "servers" {
            match value {
                Value::Object(overlay_servers) => {
                    if let Some(base_servers) =
                        base.get_mut("servers").and_then(Value::as_object_mut)
                    {
                        for (name, server) in overlay_servers {
                            base_servers.insert(name, server);
                        }
                    } else {
                        base.insert(key, Value::Object(overlay_servers));
                    }
                }
                other => {
                    base.insert(key, other);
                }
            }
        } else {
            base.insert(key, value);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PermissionRule {
    action: PermissionAction,
    command_catch_all: bool,
}

#[cfg(test)]
fn resolve_bash(config: &Value) -> Result<(PermissionAction, CapabilityScope), String> {
    let (permission, scope, _) = resolve_effective_bash(config)?;
    Ok((permission, scope))
}

/// Resolve the OpenCode Bash policy into the raw permission action, its scope,
/// and the single `EffectiveBashPermission` the analysis boundary layer
/// consumes. Sandbox posture is detected here from configuration before the
/// raw action is flattened.
pub fn resolve_effective_bash(
    config: &Value,
) -> Result<(PermissionAction, CapabilityScope, EffectiveBashPermission), String> {
    let sandboxed = is_sandbox_enabled(config);
    // OpenCode's current built-in build-agent default is `* = allow`.
    let mut rules = vec![PermissionRule {
        action: PermissionAction::Allow,
        command_catch_all: true,
    }];

    if let Some(tools) = config.get("tools").and_then(Value::as_object) {
        if let Some(enabled) = tools.get("bash").and_then(Value::as_bool) {
            rules.push(PermissionRule {
                action: if enabled {
                    PermissionAction::Allow
                } else {
                    PermissionAction::Deny
                },
                command_catch_all: true,
            });
        }
    }
    if let Some(permission) = config.get("permission") {
        append_bash_rules(permission, &mut rules)?;
    }

    let agent_name = config
        .get("default_agent")
        .and_then(Value::as_str)
        .unwrap_or("build");
    if let Some(agent) = config
        .get("agent")
        .and_then(Value::as_object)
        .and_then(|agents| agents.get(agent_name))
    {
        let agent = agent
            .as_object()
            .ok_or_else(|| format!("agent.{agent_name} must be an object"))?;
        if agent.get("disable").and_then(Value::as_bool) == Some(true) {
            return Ok((
                PermissionAction::Unknown,
                CapabilityScope::Bounded,
                EffectiveBashPermission::Unknown,
            ));
        }
        if let Some(permission) = agent.get("permission") {
            append_bash_rules(permission, &mut rules)?;
        }
    } else if agent_name != "build" {
        return Ok((
            PermissionAction::Unknown,
            CapabilityScope::Bounded,
            EffectiveBashPermission::Unknown,
        ));
    }

    let baseline = rules
        .iter()
        .rposition(|rule| rule.command_catch_all)
        .expect("built-in default supplies a catch-all");
    // A command-independent edge cannot truthfully flatten a mixed pattern
    // policy: if any rule after the last catch-all is pattern-scoped, the
    // policy is bounded and reported as UNKNOWN.
    let tail_has_pattern = rules[baseline..].iter().any(|rule| !rule.command_catch_all);
    let (action, scope) = if tail_has_pattern {
        (PermissionAction::Unknown, CapabilityScope::Bounded)
    } else {
        // Among the explicitly configured catch-all rules apply the precedence
        // Deny > Allow > Ask. The built-in `* = allow` default is excluded so
        // an explicit `ask`/`deny` is honored rather than masked by the
        // fallback. An explicit Allow therefore overrides an explicit Ask.
        let explicit = rules.iter().skip(1).filter(|rule| rule.command_catch_all);
        let action = if explicit
            .clone()
            .any(|rule| rule.action == PermissionAction::Deny)
        {
            PermissionAction::Deny
        } else if explicit
            .clone()
            .any(|rule| rule.action == PermissionAction::Allow)
        {
            PermissionAction::Allow
        } else if explicit
            .clone()
            .any(|rule| rule.action == PermissionAction::Ask)
        {
            PermissionAction::Ask
        } else {
            PermissionAction::Allow
        };
        (action, CapabilityScope::Unrestricted)
    };
    let effective_state = effective_state_for(action, sandboxed);
    Ok((action, scope, effective_state))
}

/// Detect the OpenCode sandbox posture. We honor two documented config keys:
///   1. Top-level `"sandbox": true` (the documented V2 project sandbox toggle).
///   2. `"permission": { "bash": { "action": "allow", "sandbox": true } }`
///      (a per-bash sandbox grant inside the permission object).
///
/// The second form is normalized by ignoring the non-pattern `sandbox` key in
/// `append_bash_rules` so policy resolution does not reject it.
fn is_sandbox_enabled(config: &Value) -> bool {
    if config.get("sandbox").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if let Some(bash) = config
        .get("permission")
        .and_then(Value::as_object)
        .and_then(|permission| permission.get("bash"))
        .and_then(Value::as_object)
    {
        if bash.get("sandbox").and_then(Value::as_bool) == Some(true) {
            return true;
        }
    }
    false
}

/// Map a resolved `PermissionAction` plus sandbox posture to the single
/// effective Bash permission the boundary layer consumes.
fn effective_state_for(action: PermissionAction, sandboxed: bool) -> EffectiveBashPermission {
    if sandboxed {
        return EffectiveBashPermission::Sandboxed;
    }
    match action {
        PermissionAction::Allow => EffectiveBashPermission::AutoAllow,
        PermissionAction::Ask => EffectiveBashPermission::ApprovalGated,
        PermissionAction::Deny => EffectiveBashPermission::Denied,
        // A mixed/bounded policy yields no concrete effective state.
        PermissionAction::Unknown => EffectiveBashPermission::Unknown,
    }
}

fn append_bash_rules(permission: &Value, rules: &mut Vec<PermissionRule>) -> Result<(), String> {
    if let Some(action) = permission.as_str() {
        rules.push(PermissionRule {
            action: parse_action(action)?,
            command_catch_all: true,
        });
        return Ok(());
    }
    let permission = permission
        .as_object()
        .ok_or_else(|| "permission must be a string or object".to_string())?;
    for (tool, value) in permission {
        if tool != "*" && tool != "bash" {
            continue;
        }
        if let Some(action) = value.as_str() {
            rules.push(PermissionRule {
                action: parse_action(action)?,
                command_catch_all: true,
            });
            continue;
        }
        if tool == "*" {
            return Err("permission.* must be allow, ask, or deny".to_string());
        }
        let patterns = value
            .as_object()
            .ok_or_else(|| "permission.bash must be a string or object".to_string())?;
        for (pattern, action) in patterns {
            // Non-pattern control keys: `sandbox` is the sandbox toggle (already
            // detected by `is_sandbox_enabled`) and `action` is an alias for a
            // catch-all grant. Neither is a command pattern.
            if pattern == "sandbox" {
                continue;
            }
            if pattern == "action" {
                let action = action
                    .as_str()
                    .ok_or_else(|| "permission.bash.action must be a string".to_string())?;
                rules.push(PermissionRule {
                    action: parse_action(action)?,
                    command_catch_all: true,
                });
                continue;
            }
            let action = action
                .as_str()
                .ok_or_else(|| format!("permission.bash.{pattern} must be a string"))?;
            rules.push(PermissionRule {
                action: parse_action(action)?,
                command_catch_all: pattern == "*",
            });
        }
    }
    Ok(())
}

fn parse_action(action: &str) -> Result<PermissionAction, String> {
    match action {
        "allow" => Ok(PermissionAction::Allow),
        "ask" => Ok(PermissionAction::Ask),
        "deny" => Ok(PermissionAction::Deny),
        _ => Err(format!("unsupported permission action: {action}")),
    }
}

/// Resolve the current OpenCode V2 ordered MCP permission rules. A small
/// legacy object form is accepted only for compatibility with documented V1
/// configurations; the default remains V2's approval-gated ASK.
pub fn resolve_mcp_permission(config: &Value, permission_name: &str) -> (PermissionAction, String) {
    let mut result = (PermissionAction::Ask, "<default>".to_string());
    if let Some(rules) = config.get("permissions").and_then(Value::as_array) {
        for rule in rules {
            if let Some((pattern, action)) = permission_rule(rule) {
                if wildcard_match(&pattern, permission_name) {
                    result = (action, pattern);
                }
            }
        }
    }
    if let Some(permission) = config.get("permission") {
        if let Some(object) = permission.as_object() {
            for (pattern, value) in object {
                if let Some(action) = value.as_str().and_then(parse_action_lossy) {
                    if wildcard_match(pattern, permission_name) {
                        result = (action, pattern.clone());
                    }
                }
            }
        }
    }
    let agent_name = config
        .get("default_agent")
        .and_then(Value::as_str)
        .unwrap_or("build");
    if let Some(agent) = config
        .get("agents")
        .and_then(Value::as_object)
        .and_then(|agents| agents.get(agent_name))
    {
        if let Some(rules) = agent.get("permissions").and_then(Value::as_array) {
            for rule in rules {
                if let Some((pattern, action)) = permission_rule(rule) {
                    if wildcard_match(&pattern, permission_name) {
                        result = (action, pattern);
                    }
                }
            }
        }
    }
    result
}

fn permission_rule(rule: &Value) -> Option<(String, PermissionAction)> {
    let object = rule.as_object()?;
    let pattern = object
        .get("resource")
        .or_else(|| object.get("permission"))
        .or_else(|| object.get("action"))
        .and_then(Value::as_str)?;
    let action = object
        .get("effect")
        .or_else(|| object.get("value"))
        .or_else(|| object.get("action"))
        .and_then(Value::as_str)
        .and_then(parse_action_lossy)?;
    Some((pattern.to_string(), action))
}

fn parse_action_lossy(value: &str) -> Option<PermissionAction> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Some(PermissionAction::Allow),
        "ask" => Some(PermissionAction::Ask),
        "deny" => Some(PermissionAction::Deny),
        _ => None,
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let (mut p, mut v, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'?') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Remove JSONC comments and trailing commas without inspecting values.
fn strip_jsonc(input: &str) -> Result<String, String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push(next);
                    break;
                }
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut closed = false;
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err("unterminated JSONC block comment".to_string());
            }
        } else {
            output.push(ch);
        }
    }
    if in_string {
        return Err("unterminated JSON string".to_string());
    }

    let chars: Vec<char> = output.chars().collect();
    let mut without_trailing = String::with_capacity(output.len());
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in chars.iter().copied().enumerate() {
        if in_string {
            without_trailing.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '"' {
            in_string = true;
            without_trailing.push(ch);
            continue;
        }
        if ch == ',' {
            let next = chars[index + 1..]
                .iter()
                .copied()
                .find(|candidate| !candidate.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        without_trailing.push(ch);
    }
    Ok(without_trailing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::model::{
        AuthorityPath, AuthorityResolution, BoundaryKind, CapabilityClass, InfluencePath,
        InfluenceStrength, PathEdgeRef, PathPhase, SegmentDisposition, SinkImpact, SourceTrust,
        TraversalDirection,
    };
    use crate::discovery::EffectiveBashPermission;
    use crate::domain::RelationshipState;
    use crate::graph::model::{EdgeUsability, GraphEdge};
    use crate::graph::SecurityGraph;
    use tempfile::tempdir;

    #[test]
    fn finds_supported_project_jsonc_and_ignores_irrelevant_files() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("opencode.jsonc"),
            "// comment\n{\"provider\": \"x\",}",
        )
        .unwrap();
        fs::write(dir.path().join("opencode-notes.txt"), "opencode").unwrap();
        let result = discover(dir.path(), None).unwrap();
        assert_eq!(result.actors.len(), 1);
        assert!(result.problems.is_empty());
        assert_eq!(result.actors[0].source_locator, "project:opencode.jsonc");
        assert_eq!(result.bash_capabilities.len(), 1);
        assert_eq!(
            result.bash_capabilities[0].permission,
            PermissionAction::Allow
        );
    }

    #[test]
    fn absence_is_not_a_problem() {
        let dir = tempdir().unwrap();
        let result = discover(dir.path(), None).unwrap();
        assert!(result.actors.is_empty());
        assert!(result.problems.is_empty());
    }

    #[test]
    fn malformed_supported_config_is_reported_without_detection() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("opencode.json"), "not json").unwrap();
        let result = discover(dir.path(), None).unwrap();
        assert!(result.actors.is_empty());
        assert_eq!(result.problems.len(), 1);
    }

    #[test]
    fn resolves_allow_ask_and_deny_shorthand() {
        for (configured, expected) in [
            ("allow", PermissionAction::Allow),
            ("ask", PermissionAction::Ask),
            ("deny", PermissionAction::Deny),
        ] {
            let config = serde_json::json!({"permission": {"bash": configured}});
            assert_eq!(
                resolve_bash(&config).unwrap(),
                (expected, CapabilityScope::Unrestricted)
            );
        }
    }

    #[test]
    fn default_agent_override_wins() {
        let config = serde_json::json!({
            "permission": {"bash": "allow"},
            "agent": {"build": {"permission": {"bash": "deny"}}}
        });
        assert_eq!(
            resolve_bash(&config).unwrap(),
            (PermissionAction::Deny, CapabilityScope::Unrestricted)
        );
    }

    #[test]
    fn mixed_patterns_are_bounded_unknown() {
        let config = serde_json::json!({
            "permission": {"bash": {"*": "ask", "git status": "allow"}}
        });
        assert_eq!(
            resolve_bash(&config).unwrap(),
            (PermissionAction::Unknown, CapabilityScope::Bounded)
        );
    }

    #[test]
    fn last_catch_all_rule_wins_in_authored_order() {
        let config: Value =
            serde_json::from_str(r#"{"permission":{"bash":{"git *":"allow","*":"deny"}}}"#)
                .unwrap();
        assert_eq!(
            resolve_bash(&config).unwrap(),
            (PermissionAction::Deny, CapabilityScope::Unrestricted)
        );
    }

    #[test]
    fn project_permission_overrides_global_permission() {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        let global = home.path().join(".config/opencode");
        fs::create_dir_all(&global).unwrap();
        fs::write(
            global.join("opencode.json"),
            r#"{"permission":{"bash":"deny"}}"#,
        )
        .unwrap();
        fs::write(
            workspace.path().join("opencode.json"),
            r#"{"permission":{"bash":"allow"}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(result.actors.len(), 2);
        assert!(result.problems.is_empty());
        assert_eq!(
            result.bash_capabilities[0].permission,
            PermissionAction::Allow
        );
    }

    #[test]
    fn invalid_bash_policy_preserves_actor_but_not_capability() {
        let workspace = tempdir().unwrap();
        fs::write(
            workspace.path().join("opencode.json"),
            r#"{"permission":{"bash":"sometimes"}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), None).unwrap();
        assert_eq!(result.actors.len(), 1);
        assert!(result.bash_capabilities.is_empty());
        assert_eq!(result.problems.len(), 1);
    }

    #[test]
    fn transient_credential_debug_is_redacted() {
        let credential = TransientCredential::new("TEST_SECRET_SHOULD_NOT_PERSIST".to_string());
        let debug = format!("{credential:?}");
        assert_eq!(debug, "TransientCredential(REDACTED)");
        assert!(!debug.contains("TEST_SECRET_SHOULD_NOT_PERSIST"));
    }

    // ---- Effective Bash permission mapping (STEP 1-3) -----------------------

    #[test]
    fn r1_deny_overrides_allow_becomes_denied() {
        let config = serde_json::json!({
            "permission": {"bash": "allow"},
            "agent": {"build": {"permission": {"bash": "deny"}}}
        });
        let (permission, scope, effective) = resolve_effective_bash(&config).unwrap();
        assert_eq!(permission, PermissionAction::Deny);
        assert_eq!(scope, CapabilityScope::Unrestricted);
        assert_eq!(effective, EffectiveBashPermission::Denied);
    }

    #[test]
    fn r2_ask_becomes_approval_gated_and_mandatory_approval_boundary() {
        let config = serde_json::json!({"permission": {"bash": "ask"}});
        let (permission, _, effective) = resolve_effective_bash(&config).unwrap();
        assert_eq!(permission, PermissionAction::Ask);
        assert_eq!(effective, EffectiveBashPermission::ApprovalGated);

        // The scan mapping emits an Unknown-state edge with effective_permission
        // ASK, which the boundary layer converts to a MandatoryApproval boundary.
        let edge = GraphEdge {
            relationship_id: "agent:opencode|can_execute|shell:bash".to_string(),
            canonical_key: "agent:opencode|can_execute|shell:bash".to_string(),
            from_resource_id: "agent:opencode".to_string(),
            to_resource_id: "shell:bash".to_string(),
            kind: "can_execute".to_string(),
            state: RelationshipState::Unknown,
            usability: EdgeUsability::from_state(RelationshipState::Unknown),
            safe_metadata: Some(serde_json::json!({"effective_permission": "ASK"})),
            evidence_ids: Vec::new(),
        };
        let graph = SecurityGraph {
            scan_id: "scan".into(),
            snapshot_version: 1,
            nodes: Vec::new(),
            edges: vec![edge],
            outgoing_index: Default::default(),
            incoming_index: Default::default(),
            evidence_index: Default::default(),
        };
        let path = InfluencePath {
            source_resource_id: "source".into(),
            actor_resource_id: "agent:opencode".into(),
            edges: vec![PathEdgeRef {
                relationship_id: "agent:opencode|can_execute|shell:bash".into(),
                phase: PathPhase::Influence,
                traversal: TraversalDirection::Forward,
                position: 0,
            }],
            source_trust: SourceTrust::Unknown,
            influence_strength: InfluenceStrength::Unknown,
            evidence_ids: Vec::new(),
            disposition: SegmentDisposition::Active,
        };
        let authority = AuthorityPath {
            actor_resource_id: "agent:opencode".into(),
            sink_resource_id: "sink".into(),
            edges: Vec::new(),
            capability: CapabilityClass::Execute,
            authority_resolution: AuthorityResolution::Unknown,
            sink_impact: SinkImpact::Unknown,
            evidence_ids: Vec::new(),
            disposition: SegmentDisposition::Active,
        };
        let evaluations = crate::analysis::boundary::evaluate(&graph, &path, &authority);
        assert!(
            evaluations
                .iter()
                .any(|e| e.kind == BoundaryKind::MandatoryApproval),
            "expected a MandatoryApproval boundary, got {evaluations:?}"
        );
    }

    #[test]
    fn r3_sandbox_becomes_sandboxed_and_sandbox_boundary() {
        for config in [
            serde_json::json!({"sandbox": true, "permission": {"bash": "allow"}}),
            serde_json::json!({"permission": {"bash": {"action": "allow", "sandbox": true}}}),
        ] {
            let (permission, _, effective) = resolve_effective_bash(&config).unwrap();
            assert_eq!(permission, PermissionAction::Allow);
            assert_eq!(effective, EffectiveBashPermission::Sandboxed);

            let edge = GraphEdge {
                relationship_id: "agent:opencode|can_execute|shell:bash".to_string(),
                canonical_key: "agent:opencode|can_execute|shell:bash".to_string(),
                from_resource_id: "agent:opencode".to_string(),
                to_resource_id: "shell:bash".to_string(),
                kind: "can_execute".to_string(),
                state: RelationshipState::Derived,
                usability: EdgeUsability::from_state(RelationshipState::Derived),
                safe_metadata: Some(serde_json::json!({
                    "effective_permission": "ALLOW",
                    "effective_state": "SANDBOXED",
                    "boundary_kind": "SANDBOX"
                })),
                evidence_ids: Vec::new(),
            };
            let graph = SecurityGraph {
                scan_id: "scan".into(),
                snapshot_version: 1,
                nodes: Vec::new(),
                edges: vec![edge],
                outgoing_index: Default::default(),
                incoming_index: Default::default(),
                evidence_index: Default::default(),
            };
            let path = InfluencePath {
                source_resource_id: "source".into(),
                actor_resource_id: "agent:opencode".into(),
                edges: vec![PathEdgeRef {
                    relationship_id: "agent:opencode|can_execute|shell:bash".into(),
                    phase: PathPhase::Influence,
                    traversal: TraversalDirection::Forward,
                    position: 0,
                }],
                source_trust: SourceTrust::Unknown,
                influence_strength: InfluenceStrength::Unknown,
                evidence_ids: Vec::new(),
                disposition: SegmentDisposition::Active,
            };
            let authority = AuthorityPath {
                actor_resource_id: "agent:opencode".into(),
                sink_resource_id: "sink".into(),
                edges: Vec::new(),
                capability: CapabilityClass::Execute,
                authority_resolution: AuthorityResolution::Unknown,
                sink_impact: SinkImpact::Unknown,
                evidence_ids: Vec::new(),
                disposition: SegmentDisposition::Active,
            };
            let evaluations = crate::analysis::boundary::evaluate(&graph, &path, &authority);
            assert!(
                evaluations.iter().any(|e| e.kind == BoundaryKind::Sandbox),
                "expected a Sandbox boundary for {config}, got {evaluations:?}"
            );
        }
    }

    #[test]
    fn r4_agent_ask_overridden_by_bash_allow_is_auto_allow_without_interrupt() {
        // Bash-level allow overrides an agent-level ask (higher precedence).
        let config = serde_json::json!({
            "permission": {"bash": "allow"},
            "agent": {"build": {"permission": {"bash": "ask"}}}
        });
        let (permission, _, effective) = resolve_effective_bash(&config).unwrap();
        assert_eq!(permission, PermissionAction::Allow);
        assert_eq!(effective, EffectiveBashPermission::AutoAllow);

        let edge = GraphEdge {
            relationship_id: "agent:opencode|can_execute|shell:bash".to_string(),
            canonical_key: "agent:opencode|can_execute|shell:bash".to_string(),
            from_resource_id: "agent:opencode".to_string(),
            to_resource_id: "shell:bash".to_string(),
            kind: "can_execute".to_string(),
            state: RelationshipState::Derived,
            usability: EdgeUsability::from_state(RelationshipState::Derived),
            safe_metadata: Some(serde_json::json!({"effective_permission": "ALLOW"})),
            evidence_ids: Vec::new(),
        };
        let graph = SecurityGraph {
            scan_id: "scan".into(),
            snapshot_version: 1,
            nodes: Vec::new(),
            edges: vec![edge],
            outgoing_index: Default::default(),
            incoming_index: Default::default(),
            evidence_index: Default::default(),
        };
        let path = InfluencePath {
            source_resource_id: "source".into(),
            actor_resource_id: "agent:opencode".into(),
            edges: vec![PathEdgeRef {
                relationship_id: "agent:opencode|can_execute|shell:bash".into(),
                phase: PathPhase::Influence,
                traversal: TraversalDirection::Forward,
                position: 0,
            }],
            source_trust: SourceTrust::Unknown,
            influence_strength: InfluenceStrength::Unknown,
            evidence_ids: Vec::new(),
            disposition: SegmentDisposition::Active,
        };
        let authority = AuthorityPath {
            actor_resource_id: "agent:opencode".into(),
            sink_resource_id: "sink".into(),
            edges: Vec::new(),
            capability: CapabilityClass::Execute,
            authority_resolution: AuthorityResolution::Unknown,
            sink_impact: SinkImpact::Unknown,
            evidence_ids: Vec::new(),
            disposition: SegmentDisposition::Active,
        };
        let evaluations = crate::analysis::boundary::evaluate(&graph, &path, &authority);
        assert!(
            evaluations.is_empty(),
            "AutoAllow must not yield an interrupting boundary, got {evaluations:?}"
        );
    }

    #[test]
    fn r5_state_to_boundary_table() {
        // (effective_state, edge state, metadata) => expected boundary kind.
        let cases: Vec<(
            EffectiveBashPermission,
            RelationshipState,
            Option<serde_json::Value>,
            Option<BoundaryKind>,
        )> = vec![
            (
                EffectiveBashPermission::AutoAllow,
                RelationshipState::Derived,
                Some(serde_json::json!({"effective_permission": "ALLOW"})),
                None,
            ),
            (
                EffectiveBashPermission::ApprovalGated,
                RelationshipState::Unknown,
                Some(serde_json::json!({"effective_permission": "ASK"})),
                Some(BoundaryKind::MandatoryApproval),
            ),
            (
                EffectiveBashPermission::Denied,
                RelationshipState::Blocked,
                None,
                Some(BoundaryKind::HardDeny),
            ),
            (
                EffectiveBashPermission::Sandboxed,
                RelationshipState::Derived,
                Some(serde_json::json!({
                    "effective_permission": "ALLOW",
                    "boundary_kind": "SANDBOX"
                })),
                Some(BoundaryKind::Sandbox),
            ),
            (
                EffectiveBashPermission::Unknown,
                RelationshipState::Unknown,
                None,
                Some(BoundaryKind::HardDeny),
            ),
        ];
        for (effective, state, metadata, expected) in cases {
            let edge = GraphEdge {
                relationship_id: "agent:opencode|can_execute|shell:bash".to_string(),
                canonical_key: "agent:opencode|can_execute|shell:bash".to_string(),
                from_resource_id: "agent:opencode".to_string(),
                to_resource_id: "shell:bash".to_string(),
                kind: "can_execute".to_string(),
                state,
                usability: EdgeUsability::from_state(state),
                safe_metadata: metadata,
                evidence_ids: Vec::new(),
            };
            let graph = SecurityGraph {
                scan_id: "scan".into(),
                snapshot_version: 1,
                nodes: Vec::new(),
                edges: vec![edge],
                outgoing_index: Default::default(),
                incoming_index: Default::default(),
                evidence_index: Default::default(),
            };
            let path = InfluencePath {
                source_resource_id: "source".into(),
                actor_resource_id: "agent:opencode".into(),
                edges: vec![PathEdgeRef {
                    relationship_id: "agent:opencode|can_execute|shell:bash".into(),
                    phase: PathPhase::Influence,
                    traversal: TraversalDirection::Forward,
                    position: 0,
                }],
                source_trust: SourceTrust::Unknown,
                influence_strength: InfluenceStrength::Unknown,
                evidence_ids: Vec::new(),
                disposition: SegmentDisposition::Active,
            };
            let authority = AuthorityPath {
                actor_resource_id: "agent:opencode".into(),
                sink_resource_id: "sink".into(),
                edges: Vec::new(),
                capability: CapabilityClass::Execute,
                authority_resolution: AuthorityResolution::Unknown,
                sink_impact: SinkImpact::Unknown,
                evidence_ids: Vec::new(),
                disposition: SegmentDisposition::Active,
            };
            let evaluations = crate::analysis::boundary::evaluate(&graph, &path, &authority);
            let found = evaluations.iter().map(|e| e.kind).next();
            assert_eq!(
                found, expected,
                "effective_state {effective:?} (state {state:?}) boundary mismatch"
            );
        }
    }

    #[test]
    fn r8_battery_precedence_and_surface_effective_state() {
        // Precedence: deny must beat ask and allow at the same level.
        fn effective_of(config: serde_json::Value) -> EffectiveBashPermission {
            resolve_effective_bash(&config).unwrap().2
        }
        assert_eq!(
            effective_of(serde_json::json!({"permission": {"bash": "deny"}})),
            EffectiveBashPermission::Denied
        );
        assert_eq!(
            effective_of(serde_json::json!({"permission": {"bash": "ask"}})),
            EffectiveBashPermission::ApprovalGated
        );
        assert_eq!(
            effective_of(serde_json::json!({"permission": {"bash": "allow"}})),
            EffectiveBashPermission::AutoAllow
        );
        // Agent deny overrides global allow.
        assert_eq!(
            effective_of(serde_json::json!({
                "permission": {"bash": "allow"},
                "agent": {"build": {"permission": {"bash": "deny"}}}
            })),
            EffectiveBashPermission::Denied
        );
        // Sandbox wins even when the action would otherwise be allow/ask/deny.
        assert_eq!(
            effective_of(serde_json::json!({"sandbox": true, "permission": {"bash": "deny"}})),
            EffectiveBashPermission::Sandboxed
        );

        // MCP transport + credential surfaces are observed independently; the
        // effective Bash state still resolves from the same config.
        let dir = tempdir().unwrap();
        let cfg = serde_json::json!({
            "permission": {"bash": "allow"},
            "mcp": {
                "servers": {
                    "local": {"type": "stdio", "command": "ghcr.io/github/github-mcp-server"},
                    "remote": {"type": "http", "url": "https://mcp.example.com"}
                }
            }
        });
        fs::write(
            dir.path().join("opencode.json"),
            serde_json::to_string(&cfg).unwrap(),
        )
        .unwrap();
        let result = discover(dir.path(), None).unwrap();
        assert_eq!(result.bash_capabilities.len(), 1);
        assert_eq!(
            result.bash_capabilities[0].effective_state,
            EffectiveBashPermission::AutoAllow
        );
        let transports: Vec<_> = result
            .mcp_servers
            .iter()
            .map(|s| (s.name.as_str(), s.transport))
            .collect();
        assert!(transports
            .iter()
            .any(|(n, t)| *n == "local" && *t == McpTransport::Stdio));
        assert!(transports
            .iter()
            .any(|(n, t)| *n == "remote" && *t == McpTransport::Http));

        // Credential from .env beats environment variant in reachability, but
        // the effective Bash state is unchanged.
        let ws = tempdir().unwrap();
        fs::write(
            ws.path().join(".env"),
            "CLOUDFLARE_API_TOKEN=dotenv-token-value\n",
        )
        .unwrap();
        fs::write(
            ws.path().join("opencode.json"),
            serde_json::to_string(&serde_json::json!({"permission": {"bash": "ask"}})).unwrap(),
        )
        .unwrap();
        let cred_result = discover_with_environment(
            ws.path(),
            None,
            Some(&[("CLOUDFLARE_API_TOKEN", "env-token-value")]),
            EnvironmentReachability::Proven,
        )
        .unwrap();
        assert_eq!(
            cred_result.bash_capabilities[0].effective_state,
            EffectiveBashPermission::ApprovalGated
        );
        assert!(
            cred_result
                .credentials
                .iter()
                .any(|c| c.source_type == "project_dotenv"),
            "expected a .env credential surface"
        );
    }

    #[test]
    fn r9_identical_config_yields_identical_effective_state() {
        let config = serde_json::json!({
            "permission": {"bash": {"*": "allow"}},
            "agent": {"build": {"permission": {"bash": "ask"}}}
        });
        let first = resolve_effective_bash(&config).unwrap();
        let second = resolve_effective_bash(&config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.2, EffectiveBashPermission::AutoAllow);
    }

    #[test]
    fn r1_classifies_credential_type_by_format() {
        // API token prefixes.
        assert_eq!(
            classify_credential_type("cfut_TESTFAKE0000000000000000000000000000"),
            "api_token"
        );
        // Global API key shape: long hexadecimal, no token/oauth prefix.
        assert_eq!(
            classify_credential_type("0123456789abcdef0123456789abcdef0123456789abcdef"),
            "api_key"
        );
        // Explicit OAuth prefixes.
        assert_eq!(
            classify_credential_type("cwo_TESTFAKE0000000000000000000000000000"),
            "oauth"
        );
        assert_eq!(
            classify_credential_type("fou_TESTFAKE0000000000000000000000000000"),
            "oauth"
        );
        // Long non-global-key token with structure (not pure alphanumeric): oauth.
        assert_eq!(
            classify_credential_type("ya29.oauth_token_with_dots_and_underscores_0123456789"),
            "oauth"
        );
        // Unrecognized short value falls back to the safe api_token default.
        assert_eq!(classify_credential_type("short"), "api_token");
    }
}
