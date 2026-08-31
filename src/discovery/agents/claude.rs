//! Bounded Claude Code actor and Bash-policy discovery.
//!
//! Claude Code is observed from documented static configuration only:
//!
//! * project `.claude/settings.json` and `.claude/settings.local.json` (scoped
//!   to the workspace or its nearest `.git` ancestor, mirroring the OpenCode
//!   adapter's project candidate traversal),
//! * user `~/.claude/settings.json`,
//! * project `.mcp.json` for Claude-declared MCP servers.
//!
//! This adapter is intentionally CONFIG-ONLY. It never reads environment
//! variables or dotenv files; the Cloudflare environment/.env credential
//! reader remains the OpenCode adapter's responsibility. Absence of a
//! documented location is not a problem.
//!
//! Bash policy is resolved from the `permissions.allow` / `permissions.ask` /
//! `permissions.deny` arrays (a rule is a Bash rule when it is exactly `"Bash"`
//! or starts with `"Bash("`), `permissions.disableBash`, `permissions.defaultMode`
//! (which informs but never fabricates AUTO_ALLOW), and a sandbox indicator.
//! Unresolvable or mixed pattern policies resolve to `(Unknown, Bounded)` and are
//! never invented.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::discovery::{
    CapabilityScope, DiscoveryResult, EffectiveBashPermission, McpTransport, ObservedActor,
    ObservedBashCapability, ObservedMcpServer, PermissionAction,
};
use crate::shared::PicoError;

const SETTINGS_NAMES: [&str; 2] = ["settings.json", "settings.local.json"];
const MCP_CONFIG_NAME: &str = ".mcp.json";

/// Discover a configured Claude Code actor from exact documented locations.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    let mut result = DiscoveryResult::default();

    let mut candidates = Vec::new();
    if let Some(home) = home {
        candidates.extend(user_candidates(home));
    }
    candidates.extend(project_candidates(workspace));

    let mut settings = Value::Object(Default::default());
    let mut settings_locators = Vec::new();
    for (path, locator) in candidates {
        if !path.is_file() {
            continue;
        }
        match parse_config_object(&path) {
            Ok(config) => {
                merge_json(&mut settings, config);
                settings_locators.push(locator.clone());
                result.actors.push(ObservedActor {
                    provider: "claude",
                    source_type: "claude_settings",
                    source_locator: locator,
                });
            }
            Err(problem) => result.problems.push(format!("{locator}: {problem}")),
        }
    }

    let mut mcp_config = Value::Object(Default::default());
    let mut mcp_locator = None;
    for (path, locator) in mcp_candidates(workspace) {
        if !path.is_file() {
            continue;
        }
        match parse_config_object(&path) {
            Ok(config) => {
                merge_json(&mut mcp_config, config);
                mcp_locator = Some(locator);
            }
            Err(problem) => result.problems.push(format!("{locator}: {problem}")),
        }
    }

    // A project `.mcp.json` is itself a documented Claude Code presence, so a
    // workspace with only an MCP declaration still emits the actor surface.
    if result.actors.is_empty() {
        if let Some(locator) = mcp_locator.as_deref() {
            result.actors.push(ObservedActor {
                provider: "claude",
                source_type: "claude_settings",
                source_locator: locator.to_string(),
            });
        }
    }

    if !result.actors.is_empty() && result.problems.is_empty() {
        if !settings_locators.is_empty() {
            match resolve_effective_bash(&settings) {
                Ok((permission, scope, effective_state)) => {
                    result.bash_capabilities.push(ObservedBashCapability {
                        provider: "claude",
                        permission,
                        scope,
                        effective_state,
                        // Static configuration cannot observe an auto-approval
                        // session mode, so the runtime mode is never asserted.
                        runtime_mode: "UNKNOWN",
                        source_locator: settings_locators.join(","),
                    })
                }
                Err(problem) => result.problems.push(problem),
            }
        }
        match parse_mcp_servers(
            &settings,
            &mcp_config,
            &settings_locators,
            mcp_locator.as_deref(),
        ) {
            Ok(servers) => {
                result.mcp_servers = servers;
                result.github_surfaces =
                    crate::discovery::mcp::github::classify(&result.mcp_servers);
            }
            Err(problem) => result.problems.push(problem),
        }
        for surface in &mut result.github_surfaces {
            for tool in &mut surface.tools {
                // Claude's MCP permissions are not resolved per tool from
                // static config; the classifier's conservative Unknown default
                // is preserved (no invented certainty).
                tool.permission = PermissionAction::Unknown;
                tool.permission_pattern = "<default>".to_string();
            }
        }
    }
    Ok(result)
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
        for name in SETTINGS_NAMES {
            candidates.push((
                directory.join(".claude").join(name),
                format!("project:.claude/{name}"),
            ));
        }
    }
    candidates
}

fn mcp_candidates(workspace: &Path) -> Vec<(PathBuf, String)> {
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

    directories
        .into_iter()
        .map(|directory| {
            (
                directory.join(MCP_CONFIG_NAME),
                format!("project:{MCP_CONFIG_NAME}"),
            )
        })
        .collect()
}

fn user_candidates(home: &Path) -> Vec<(PathBuf, String)> {
    vec![(
        home.join(".claude").join("settings.json"),
        "user:.claude/settings.json".to_string(),
    )]
}

fn parse_config_object(path: &Path) -> Result<Value, String> {
    let contents =
        crate::shared::read_regular_file_bounded(path, crate::shared::MAX_LOCAL_FILE_BYTES)
            .map_err(|err| format!("cannot read configuration: {err}"))?;
    match serde_json::from_str::<Value>(&contents) {
        Ok(value @ Value::Object(_)) => Ok(value),
        Ok(_) => Err("configuration must be a JSON object".to_string()),
        Err(err) => Err(format!("invalid configuration: {err}")),
    }
}

fn merge_json(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
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

/// Parse the merged Claude MCP servers. `mcpServers` from any parsed settings
/// file is the lower-precedence source; `mcpServers` from the project
/// `.mcp.json` overrides it by server name (project over user).
fn parse_mcp_servers(
    settings: &Value,
    mcp_config: &Value,
    settings_locators: &[String],
    mcp_locator: Option<&str>,
) -> Result<Vec<ObservedMcpServer>, String> {
    let settings_locator = settings_locators.join(",");
    let mut sources: std::collections::BTreeMap<String, (Value, String)> =
        std::collections::BTreeMap::new();
    if let Some(servers) = settings.get("mcpServers").and_then(Value::as_object) {
        for (name, value) in servers {
            sources.insert(name.clone(), (value.clone(), settings_locator.clone()));
        }
    }
    if let Some(servers) = mcp_config.get("mcpServers").and_then(Value::as_object) {
        let locator = mcp_locator.unwrap_or("").to_string();
        for (name, value) in servers {
            sources.insert(name.clone(), (value.clone(), locator.clone()));
        }
    }
    if sources.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::new();
    for (name, (value, locator)) in sources {
        let Some(server) = value.as_object() else {
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
        let mut parts = Vec::new();
        if let Some(command) = server.get("command").and_then(Value::as_str) {
            parts.push(command.to_string());
        }
        if let Some(args) = server.get("args").and_then(Value::as_array) {
            parts.extend(args.iter().filter_map(Value::as_str).map(str::to_string));
        }
        let (safe_command, safe_identity) = normalize_command(&parts);
        let safe_endpoint = server
            .get("url")
            .and_then(Value::as_str)
            .map(crate::discovery::mcp::normalize_endpoint);
        let environment_keys = server
            .get("environment")
            .or_else(|| server.get("env"))
            .and_then(Value::as_object)
            .map(|env| env.keys().cloned().collect())
            .unwrap_or_default();
        let tool_declaration = extract_declaration(server, "tools");
        let toolset_declaration = extract_declaration(server, "toolsets");
        output.push(ObservedMcpServer {
            provider: "claude",
            name: name.clone(),
            transport,
            enabled,
            source_locator: locator,
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

/// Normalize a Claude command (command + args) into a secret-free safe string
/// and an official GitHub MCP identity when present.
fn normalize_command(parts: &[String]) -> (Option<String>, Option<String>) {
    if parts.is_empty() {
        return (None, None);
    }
    let identity = crate::discovery::mcp::official_identity_from_command_parts(parts);
    let safe = parts
        .iter()
        .filter(|part| !crate::discovery::mcp::looks_secret(part))
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    (Some(safe), identity)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PermissionRule {
    action: PermissionAction,
    command_catch_all: bool,
}

/// Resolve the Claude Code Bash policy into the raw permission action, its
/// scope, and the single `EffectiveBashPermission` the analysis boundary layer
/// consumes. Precedence across arrays is deny > ask > allow; within an array
/// the last-listed Bash rule governs. A non-catch-all Bash pattern that cannot
/// be flattened resolves to `(Unknown, Bounded)` — never an invented state.
pub fn resolve_effective_bash(
    config: &Value,
) -> Result<(PermissionAction, CapabilityScope, EffectiveBashPermission), String> {
    let sandboxed = is_sandbox_enabled(config);
    let mut rules = Vec::new();

    if let Some(permissions) = config.get("permissions").and_then(Value::as_object) {
        for (key, action) in [
            ("allow", PermissionAction::Allow),
            ("ask", PermissionAction::Ask),
            ("deny", PermissionAction::Deny),
        ] {
            if let Some(array) = permissions.get(key) {
                append_bash_rules(array, action, &mut rules)?;
            }
        }
        if permissions.get("disableBash").and_then(Value::as_bool) == Some(true) {
            rules.push(PermissionRule {
                action: PermissionAction::Deny,
                command_catch_all: true,
            });
        }
        // `permissions.defaultMode` informs the resolution but is never allowed
        // to fabricate AUTO_ALLOW by itself: Claude Code's documented Bash
        // posture remains approval-gated unless an explicit rule says otherwise.
    }

    let winning = rules
        .iter()
        .find(|rule| rule.action == PermissionAction::Deny)
        .or_else(|| {
            rules
                .iter()
                .find(|rule| rule.action == PermissionAction::Ask)
        })
        .or_else(|| {
            rules
                .iter()
                .find(|rule| rule.action == PermissionAction::Allow)
        });
    let (action, scope) = match winning {
        Some(rule) if rule.command_catch_all => (rule.action, CapabilityScope::Unrestricted),
        // A pattern-scoped Bash rule (e.g. `Bash(git rm *)`) that cannot be
        // flattened to a single posture is bounded and reported as UNKNOWN.
        Some(_) => (PermissionAction::Unknown, CapabilityScope::Bounded),
        // No explicit Bash rule: Claude Code's product default requires
        // approval before Bash executes.
        None => (PermissionAction::Ask, CapabilityScope::Unrestricted),
    };
    let effective_state = effective_state_for(action, sandboxed);
    Ok((action, scope, effective_state))
}

/// Detect the Claude sandbox posture. Honored indicators:
///   1. top-level `"sandbox": true`,
///   2. `"permissions": { "sandbox": true }`,
///   3. `"bash": { "sandbox": true }`.
fn is_sandbox_enabled(config: &Value) -> bool {
    if config.get("sandbox").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if let Some(permissions) = config.get("permissions").and_then(Value::as_object) {
        if permissions.get("sandbox").and_then(Value::as_bool) == Some(true) {
            return true;
        }
    }
    if let Some(bash) = config.get("bash").and_then(Value::as_object) {
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

/// Collect the Bash rules contributed by one `permissions` array. Only rules
/// that are exactly `"Bash"` or start with `"Bash("` are Bash rules; the
/// last-listed Bash rule in the array governs (all rules in one array share
/// the array's action). Non-Bash rules (e.g. `"Edit"`, `"Read"`) are ignored.
fn append_bash_rules(
    array: &Value,
    action: PermissionAction,
    rules: &mut Vec<PermissionRule>,
) -> Result<(), String> {
    let items = array
        .as_array()
        .ok_or_else(|| "permissions allow/ask/deny must be arrays of rules".to_string())?;
    for rule in items.iter().rev() {
        let Some(rule) = rule.as_str() else {
            continue;
        };
        if rule != "Bash" && !rule.starts_with("Bash(") {
            continue;
        }
        let command_catch_all = if rule == "Bash" {
            true
        } else {
            let pattern = rule.trim_start_matches("Bash(").trim_end_matches(')');
            pattern == "*"
        };
        rules.push(PermissionRule {
            action,
            command_catch_all,
        });
        return Ok(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{EffectiveBashPermission, McpTransport};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn claude_actor_discovered_from_documented_config() {
        // Project `.claude/settings.json`.
        let workspace = tempdir().unwrap();
        fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.json"),
            r#"{"permissions":{"allow":["Bash"]}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), None).unwrap();
        assert_eq!(result.actors.len(), 1);
        assert_eq!(result.actors[0].provider, "claude");
        assert_eq!(result.actors[0].source_type, "claude_settings");
        assert_eq!(
            result.actors[0].source_locator,
            "project:.claude/settings.json"
        );
        assert!(result.problems.is_empty());

        // User `~/.claude/settings.json` alongside the project location yields
        // a second actor and a merged Bash capability.
        let home = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".claude")).unwrap();
        fs::write(
            home.path().join(".claude").join("settings.json"),
            r#"{"permissions":{"ask":["Bash"]}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(result.actors.len(), 2);
        assert!(result
            .actors
            .iter()
            .any(|actor| actor.source_locator == "user:.claude/settings.json"));
        assert_eq!(result.bash_capabilities.len(), 1);
        assert_eq!(result.bash_capabilities[0].provider, "claude");
    }

    #[test]
    fn claude_settings_local_overrides_settings() {
        let workspace = tempdir().unwrap();
        fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.json"),
            r#"{"permissions":{"allow":["Bash(git status)"]}}"#,
        )
        .unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.local.json"),
            r#"{"permissions":{"allow":["Bash"]}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), None).unwrap();
        assert_eq!(result.actors.len(), 2);
        // The local allow array replaces the shared pattern array at the key
        // level: the result flips from an unresolvable pattern to a catch-all.
        assert_eq!(
            result.bash_capabilities[0].effective_state,
            EffectiveBashPermission::AutoAllow
        );
    }

    #[test]
    fn claude_absence_is_not_a_problem() {
        let workspace = tempdir().unwrap();
        let result = discover(workspace.path(), None).unwrap();
        assert!(result.actors.is_empty());
        assert!(result.bash_capabilities.is_empty());
        assert!(result.problems.is_empty());
    }

    #[test]
    fn claude_malformed_config_is_reported_without_detection() {
        let workspace = tempdir().unwrap();
        fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.json"),
            "not json",
        )
        .unwrap();
        let result = discover(workspace.path(), None).unwrap();
        assert!(result.actors.is_empty());
        assert_eq!(result.problems.len(), 1);
        assert!(result.problems[0].starts_with("project:.claude/settings.json:"));
    }

    #[test]
    fn claude_bash_effective_state_resolution() {
        // allow => AUTO_ALLOW, unrestricted.
        let (permission, scope, effective) =
            resolve_effective_bash(&serde_json::json!({"permissions": {"allow": ["Bash"]}}))
                .unwrap();
        assert_eq!(permission, PermissionAction::Allow);
        assert_eq!(scope, CapabilityScope::Unrestricted);
        assert_eq!(effective, EffectiveBashPermission::AutoAllow);

        // ask => APPROVAL_GATED.
        let (permission, _, effective) =
            resolve_effective_bash(&serde_json::json!({"permissions": {"ask": ["Bash"]}})).unwrap();
        assert_eq!(permission, PermissionAction::Ask);
        assert_eq!(effective, EffectiveBashPermission::ApprovalGated);

        // deny => DENIED.
        let (permission, _, effective) =
            resolve_effective_bash(&serde_json::json!({"permissions": {"deny": ["Bash"]}}))
                .unwrap();
        assert_eq!(permission, PermissionAction::Deny);
        assert_eq!(effective, EffectiveBashPermission::Denied);

        // disableBash => DENIED.
        let (permission, _, effective) =
            resolve_effective_bash(&serde_json::json!({"permissions": {"disableBash": true}}))
                .unwrap();
        assert_eq!(permission, PermissionAction::Deny);
        assert_eq!(effective, EffectiveBashPermission::Denied);

        // defaultMode alone must never fabricate AUTO_ALLOW.
        let (permission, _, effective) = resolve_effective_bash(&serde_json::json!({
            "permissions": {"defaultMode": "acceptEdits"}
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Ask);
        assert_eq!(effective, EffectiveBashPermission::ApprovalGated);

        // Precedence: deny > ask > allow across arrays. A catch-all deny wins.
        let (permission, _, effective) = resolve_effective_bash(&serde_json::json!({
            "permissions": {
                "allow": ["Bash"],
                "ask": ["Bash"],
                "deny": ["Bash"]
            }
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Deny);
        assert_eq!(effective, EffectiveBashPermission::Denied);

        // A pattern-scoped higher-precedence rule that cannot be flattened
        // resolves to (Unknown, Bounded) rather than a false certainty.
        let (permission, scope, _) = resolve_effective_bash(&serde_json::json!({
            "permissions": {
                "allow": ["Bash"],
                "ask": ["Bash"],
                "deny": ["Bash(git rm *)"]
            }
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Unknown);
        assert_eq!(scope, CapabilityScope::Bounded);

        // ask beats allow.
        let (permission, _, effective) = resolve_effective_bash(&serde_json::json!({
            "permissions": {"allow": ["Bash"], "ask": ["Bash"]}
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Ask);
        assert_eq!(effective, EffectiveBashPermission::ApprovalGated);

        // Within an array the last-listed Bash rule governs.
        let (permission, scope, effective) = resolve_effective_bash(&serde_json::json!({
            "permissions": {"allow": ["Bash(git status)", "Bash"]}
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Allow);
        assert_eq!(scope, CapabilityScope::Unrestricted);
        assert_eq!(effective, EffectiveBashPermission::AutoAllow);

        // Sandbox indicators (top-level, permissions, bash) => SANDBOXED.
        for config in [
            serde_json::json!({"sandbox": true, "permissions": {"allow": ["Bash"]}}),
            serde_json::json!({"permissions": {"sandbox": true, "allow": ["Bash"]}}),
            serde_json::json!({"permissions": {"allow": ["Bash"]}, "bash": {"sandbox": true}}),
        ] {
            let (permission, _, effective) = resolve_effective_bash(&config).unwrap();
            assert_eq!(permission, PermissionAction::Allow);
            assert_eq!(effective, EffectiveBashPermission::Sandboxed);
        }

        // A non-catch-all Bash pattern that cannot be flattened is
        // (Unknown, Bounded) — never invented.
        let (permission, scope, effective) = resolve_effective_bash(&serde_json::json!({
            "permissions": {"allow": ["Bash(npm run build)"]}
        }))
        .unwrap();
        assert_eq!(permission, PermissionAction::Unknown);
        assert_eq!(scope, CapabilityScope::Bounded);
        assert_eq!(effective, EffectiveBashPermission::Unknown);

        // No Bash rules: Claude Code's documented default is approval-gated.
        let (permission, scope, effective) =
            resolve_effective_bash(&serde_json::json!({"permissions": {"allow": ["Edit"]}}))
                .unwrap();
        assert_eq!(permission, PermissionAction::Ask);
        assert_eq!(scope, CapabilityScope::Unrestricted);
        assert_eq!(effective, EffectiveBashPermission::ApprovalGated);
    }

    #[test]
    fn claude_mcp_servers_normalized() {
        // A project `.mcp.json` with a local GitHub server and a remote server,
        // plus `mcpServers` declared inside settings.
        let workspace = tempdir().unwrap();
        fs::write(
            workspace.path().join(".mcp.json"),
            serde_json::to_string(&serde_json::json!({
                "mcpServers": {
                    "github": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["-y", "github-mcp-server"],
                        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST"}
                    },
                    "remote": {"type": "http", "url": "https://api.githubcopilot.com/mcp"}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.json"),
            serde_json::to_string(&serde_json::json!({
                "mcpServers": {
                    "from-settings": {"type": "stdio", "command": "some-tool"}
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let result = discover(workspace.path(), None).unwrap();
        let names: Vec<&str> = result.mcp_servers.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"github"));
        assert!(names.contains(&"remote"));
        assert!(names.contains(&"from-settings"));
        assert_eq!(result.mcp_servers.len(), 3);

        let github = result
            .mcp_servers
            .iter()
            .find(|s| s.name == "github")
            .unwrap();
        assert_eq!(github.transport, McpTransport::Stdio);
        assert_eq!(github.provider, "claude");
        assert_eq!(github.safe_identity.as_deref(), Some("github-mcp-server"));
        assert!(
            github
                .safe_command
                .as_deref()
                .is_some_and(|c| !c.contains("TEST_SECRET_SHOULD_NOT_PERSIST")),
            "secret must be filtered from the safe command"
        );
        assert_eq!(
            github.environment_keys,
            vec!["GITHUB_PERSONAL_ACCESS_TOKEN".to_string()]
        );
        assert_eq!(github.source_locator, "project:.mcp.json");

        let remote = result
            .mcp_servers
            .iter()
            .find(|s| s.name == "remote")
            .unwrap();
        assert_eq!(remote.transport, McpTransport::Http);
        assert_eq!(
            remote.safe_endpoint.as_deref(),
            Some("https://api.githubcopilot.com/mcp")
        );

        // The GitHub classifier applies to Claude-declared official servers:
        // the stdio identity server and the official remote endpoint both
        // classify; the unrelated settings-only server does not.
        assert_eq!(result.github_surfaces.len(), 2);
        let github_surface = result
            .github_surfaces
            .iter()
            .find(|surface| surface.server.name == "github")
            .unwrap();
        assert!(github_surface
            .tools
            .iter()
            .any(|tool| tool.name == "issue_read"));
        assert!(result
            .github_surfaces
            .iter()
            .any(|surface| surface.server.name == "remote"));
    }

    #[test]
    fn claude_project_mcp_overrides_settings_mcp() {
        let workspace = tempdir().unwrap();
        fs::write(
            workspace.path().join(".mcp.json"),
            r#"{"mcpServers":{"shared":{"type":"stdio","command":"project-version"}}}"#,
        )
        .unwrap();
        fs::create_dir_all(workspace.path().join(".claude")).unwrap();
        fs::write(
            workspace.path().join(".claude").join("settings.json"),
            r#"{"mcpServers":{"shared":{"type":"stdio","command":"user-version"}}}"#,
        )
        .unwrap();
        let result = discover(workspace.path(), None).unwrap();
        let shared = result
            .mcp_servers
            .iter()
            .find(|s| s.name == "shared")
            .unwrap();
        assert_eq!(shared.safe_command.as_deref(), Some("project-version"));
        assert_eq!(shared.source_locator, "project:.mcp.json");
    }

    #[test]
    fn claude_discovery_stable_across_identical_configs() {
        let build = || {
            let workspace = tempdir().unwrap();
            fs::create_dir_all(workspace.path().join(".claude")).unwrap();
            fs::write(
                workspace.path().join(".claude").join("settings.json"),
                r#"{"permissions":{"allow":["Bash"],"deny":["Bash(git push *)"]}}"#,
            )
            .unwrap();
            fs::write(
                workspace.path().join(".mcp.json"),
                r#"{"mcpServers":{"github":{"type":"stdio","command":"npx","args":["-y","github-mcp-server"]}}}"#,
            )
            .unwrap();
            discover(workspace.path(), None).unwrap()
        };
        let first = build();
        let second = build();
        assert_eq!(first.actors, second.actors);
        assert_eq!(first.bash_capabilities, second.bash_capabilities);
        assert_eq!(first.mcp_servers, second.mcp_servers);
        assert_eq!(first.github_surfaces, second.github_surfaces);
        assert_eq!(first.problems, second.problems);
    }
}
