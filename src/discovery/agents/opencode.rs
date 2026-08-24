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

use crate::discovery::{
    CapabilityScope, DiscoveryResult, ObservedActor, ObservedBashCapability, PermissionAction,
};
use crate::shared::PicoError;

const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];

/// Discover a configured OpenCode actor from exact documented locations.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
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
        match resolve_bash(&effective) {
            Ok((permission, scope)) => result.bash_capabilities.push(ObservedBashCapability {
                permission,
                scope,
                // OpenCode's --auto/TUI session mode is not available from
                // static configuration. ASK is therefore never described as
                // automatic execution by this adapter.
                runtime_mode: "UNKNOWN",
                source_locator: locators.join(","),
            }),
            Err(problem) => result.problems.push(problem),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PermissionRule {
    action: PermissionAction,
    command_catch_all: bool,
}

fn resolve_bash(config: &Value) -> Result<(PermissionAction, CapabilityScope), String> {
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
            return Ok((PermissionAction::Unknown, CapabilityScope::Bounded));
        }
        if let Some(permission) = agent.get("permission") {
            append_bash_rules(permission, &mut rules)?;
        }
    } else if agent_name != "build" {
        return Ok((PermissionAction::Unknown, CapabilityScope::Bounded));
    }

    let baseline = rules
        .iter()
        .rposition(|rule| rule.command_catch_all)
        .expect("built-in default supplies a catch-all");
    let baseline_action = rules[baseline].action;
    if rules[baseline..]
        .iter()
        .all(|rule| rule.action == baseline_action)
    {
        Ok((baseline_action, CapabilityScope::Unrestricted))
    } else {
        // A command-independent edge cannot truthfully flatten a mixed
        // pattern policy. Preserve that it is bounded and report UNKNOWN.
        Ok((PermissionAction::Unknown, CapabilityScope::Bounded))
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
}
