//! Bounded OpenCode presence discovery.
//!
//! OpenCode documents project `opencode.json` / `opencode.jsonc`, the same
//! names under `.opencode/`, and user configuration under
//! `~/.config/opencode/`. We validate only that a candidate is a configuration
//! object, then discard its contents. Permissions and other configuration
//! fields are deliberately outside this adapter's Sprint 002 responsibility.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::discovery::{DiscoveryResult, ObservedActor};
use crate::shared::PicoError;

const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];

/// Discover a configured OpenCode actor from exact documented locations.
pub fn discover(workspace: &Path, home: Option<&Path>) -> Result<DiscoveryResult, PicoError> {
    let mut result = DiscoveryResult::default();
    let mut candidates = project_candidates(workspace);
    if let Some(home) = home {
        candidates.extend(user_candidates(home));
    }

    for (path, locator) in candidates {
        if !path.is_file() {
            continue;
        }
        match valid_config_object(&path) {
            Ok(()) => result.actors.push(ObservedActor {
                provider: "opencode",
                source_type: "opencode_config",
                source_locator: locator,
            }),
            Err(problem) => result.problems.push(format!("{locator}: {problem}")),
        }
    }
    Ok(result)
}

fn project_candidates(workspace: &Path) -> Vec<(PathBuf, String)> {
    let mut directories = vec![workspace.to_path_buf()];
    let mut current = workspace;
    while !current.join(".git").exists() {
        let Some(parent) = current.parent() else {
            break;
        };
        directories.push(parent.to_path_buf());
        current = parent;
    }

    directories
        .into_iter()
        .flat_map(|directory| {
            CONFIG_NAMES.into_iter().flat_map(move |name| {
                [
                    (directory.join(name), format!("project:{name}")),
                    (
                        directory.join(".opencode").join(name),
                        format!("project:.opencode/{name}"),
                    ),
                ]
            })
        })
        .collect()
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

fn valid_config_object(path: &Path) -> Result<(), String> {
    let contents =
        fs::read_to_string(path).map_err(|err| format!("cannot read configuration: {err}"))?;
    let normalized = if path.extension().is_some_and(|ext| ext == "jsonc") {
        strip_jsonc(&contents)?
    } else {
        contents
    };
    match serde_json::from_str::<Value>(&normalized) {
        Ok(Value::Object(_)) => Ok(()),
        Ok(_) => Err("configuration must be a JSON object".to_string()),
        Err(err) => Err(format!("invalid configuration: {err}")),
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
}
