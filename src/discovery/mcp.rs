//! Bounded MCP adapter boundaries. Protocol facts are normalized here, while
//! OpenCode configuration parsing remains in the OpenCode adapter.

use std::path::Path;

use super::{
    McpTransport, ObservedGithubSurface, ObservedGithubTool, ObservedMcpServer, PermissionAction,
};

const OFFICIAL_GITHUB_MCP_IDENTITIES: [&str; 2] =
    ["ghcr.io/github/github-mcp-server", "github-mcp-server"];
const OFFICIAL_COMMAND_RUNNERS: [&str; 12] = [
    "docker", "podman", "nerdctl", "npx", "npx.cmd", "npm", "pnpm", "yarn", "bunx", "bun", "uvx",
    "deno",
];
const SECRET_KEYWORDS: [&str; 6] = [
    "token",
    "secret",
    "password",
    "apikey",
    "authorization",
    "bearer",
];
const TOKEN_PREFIXES: [&str; 5] = ["ghp_", "gho_", "ghs_", "ghr_", "github_pat_"];

/// Official GitHub MCP identity, only when the executable is the official
/// image/binary or a known runner that launches that image. Arbitrary argv
/// containing `github-mcp-server` is not an identity signal.
pub(crate) fn official_identity_from_command_parts(parts: &[String]) -> Option<String> {
    let identity = parts.iter().find_map(|part| official_image_name(part))?;
    let executable = parts.first()?;
    let exec_name = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable);
    let exec_stem = exec_name
        .strip_suffix(".exe")
        .or_else(|| exec_name.strip_suffix(".cmd"))
        .unwrap_or(exec_name);
    if official_image_name(exec_stem).is_some()
        || OFFICIAL_COMMAND_RUNNERS
            .iter()
            .any(|runner| exec_stem.eq_ignore_ascii_case(runner))
    {
        Some(identity)
    } else {
        None
    }
}

fn official_image_name(part: &str) -> Option<String> {
    let normalized = part.trim_end_matches('/');
    let image = normalized.split(':').next().unwrap_or(normalized);
    let basename = Path::new(image)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(image);
    OFFICIAL_GITHUB_MCP_IDENTITIES
        .iter()
        .copied()
        .find(|identity| *identity == image || *identity == basename)
        .map(str::to_string)
}

pub(crate) fn looks_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if TOKEN_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    SECRET_KEYWORDS.iter().any(|needle| lower.contains(needle))
}

/// Strip query, fragment, and URL userinfo so credentials in `user:pass@host`
/// never become a persisted endpoint.
pub(crate) fn normalize_endpoint(url: &str) -> String {
    let mut endpoint = url.split(['?', '#']).next().unwrap_or(url).to_string();
    if let Some(scheme_end) = endpoint.find("://") {
        let after_scheme = scheme_end + 3;
        if let Some(at) = endpoint[after_scheme..].find('@') {
            let at_abs = after_scheme + at;
            if !endpoint[after_scheme..at_abs].contains('/') {
                endpoint.replace_range(after_scheme..at_abs + 1, "");
            }
        }
    }
    while endpoint.ends_with('/') {
        endpoint.pop();
    }
    endpoint
}

pub mod github {
    use super::*;

    const OFFICIAL_REMOTE: &str = "https://api.githubcopilot.com/mcp";
    const DEFAULT_RETRIEVAL_TOOL: &str = "issue_read";

    /// Classify only exact official GitHub MCP identity signals. No command is
    /// executed and no remote endpoint is contacted.
    pub fn classify(servers: &[ObservedMcpServer]) -> Vec<ObservedGithubSurface> {
        servers
            .iter()
            .filter_map(|server| {
                if !is_official(server) {
                    return None;
                }
                let (names, tier) = declared_tools(server);
                let tools = names
                    .into_iter()
                    .map(|name| {
                        // Repo visibility is NOT observable from static config, so
                        // read surfaces that reach repository content are reported
                        // with UNKNOWN trust rather than a fabricated PRIVATE_EXTERNAL.
                        let (content_class, trust, influence_strength) = classify_tool(&name);
                        ObservedGithubTool {
                            name,
                            discovery_tier: tier,
                            permission: PermissionAction::Unknown,
                            permission_pattern: String::new(),
                            content_class,
                            trust,
                            influence_strength,
                        }
                    })
                    .collect::<Vec<_>>();
                Some(ObservedGithubSurface {
                    server: server.clone(),
                    tools,
                })
            })
            .collect()
    }

    /// Deterministic per-tool mapping. User-generated issue/PR content is
    /// `AGENT_INJECTABLE` (it can carry attacker-controlled instructions into the
    /// agent); repository/code content is `AGENT_RETRIEVABLE`; documented write
    /// tools are `AGENT_MUTABLE`. Unrecognized tools fall back to an honest
    /// `AGENT_RETRIEVABLE` default with `github:unknown` rather than a false
    /// certainty.
    fn classify_tool(name: &str) -> (&'static str, &'static str, &'static str) {
        match name {
            "issue_read" | "list_issues" => (
                "github:public:issue-content",
                "PUBLIC_EXTERNAL",
                "AGENT_INJECTABLE",
            ),
            "pull_request_read" | "list_pull_requests" => (
                "github:public:pull-request-content",
                "PUBLIC_EXTERNAL",
                "AGENT_INJECTABLE",
            ),
            "get_file_contents" | "get_file" | "get_repository_contents" => {
                ("github:repository-content", "UNKNOWN", "AGENT_RETRIEVABLE")
            }
            "code_search" | "search_code" | "search_repositories" => {
                ("github:code-search-content", "UNKNOWN", "AGENT_RETRIEVABLE")
            }
            "create_issue" | "update_issue" | "delete_issue" => {
                ("github:write:issue", "UNKNOWN", "AGENT_MUTABLE")
            }
            "create_pull_request"
            | "update_pull_request"
            | "delete_pull_request"
            | "merge_pull_request" => ("github:write:pull-request", "UNKNOWN", "AGENT_MUTABLE"),
            "create_comment" => ("github:write:comment", "UNKNOWN", "AGENT_MUTABLE"),
            _ => ("github:unknown", "UNKNOWN", "AGENT_RETRIEVABLE"),
        }
    }

    fn is_official_identity(identity: Option<&str>) -> bool {
        identity.is_some_and(|identity| OFFICIAL_GITHUB_MCP_IDENTITIES.contains(&identity))
    }

    fn is_official_endpoint(endpoint: Option<&str>) -> bool {
        endpoint == Some(OFFICIAL_REMOTE)
    }

    /// HTTP is official only by exact remote origin. Stdio is official only by
    /// command identity. Identity OR an unrelated URL is not enough: a spoofed
    /// argv must not admit an attacker endpoint as `mcp:github:official`.
    fn is_official(server: &ObservedMcpServer) -> bool {
        match server.transport {
            McpTransport::Http => is_official_endpoint(server.safe_endpoint.as_deref()),
            McpTransport::Stdio => {
                is_official_identity(server.safe_identity.as_deref())
                    && (server.safe_endpoint.is_none()
                        || is_official_endpoint(server.safe_endpoint.as_deref()))
            }
            McpTransport::Unknown => {
                is_official_endpoint(server.safe_endpoint.as_deref())
                    || (is_official_identity(server.safe_identity.as_deref())
                        && server.safe_endpoint.is_none())
            }
        }
    }

    fn declared_tools(server: &ObservedMcpServer) -> (Vec<String>, &'static str) {
        if let Some(value) = &server.tool_declaration {
            let tools = value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !tools.is_empty() {
                return (tools, "DECLARED");
            }
        }
        if let Some(value) = &server.toolset_declaration {
            let mut tools = Vec::new();
            for set in value.split(',').map(str::trim) {
                match set {
                    "issues" => tools.push(DEFAULT_RETRIEVAL_TOOL.to_string()),
                    "pull_requests" => tools.push("pull_request_read".to_string()),
                    "repos" => tools.push("get_file_contents".to_string()),
                    _ => {}
                }
            }
            if !tools.is_empty() {
                return (tools, "DECLARED");
            }
        }
        // The official server's documented default toolsets include issues,
        // whose read tool is the narrowest external-content surface.
        (vec![DEFAULT_RETRIEVAL_TOOL.to_string()], "DERIVED")
    }
}

#[cfg(test)]
mod tests {
    use super::github;
    use crate::discovery::{McpTransport, ObservedMcpServer};

    fn official_image_server(tool_declaration: Option<&str>) -> ObservedMcpServer {
        ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Stdio,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: Some("ghcr.io/github/github-mcp-server".to_string()),
            safe_endpoint: None,
            safe_command: Some("docker run ghcr.io/github/github-mcp-server".to_string()),
            environment_keys: vec![],
            tool_declaration: tool_declaration.map(str::to_string),
            toolset_declaration: None,
        }
    }

    fn official_remote_server() -> ObservedMcpServer {
        ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Http,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: None,
            safe_endpoint: Some("https://api.githubcopilot.com/mcp".to_string()),
            safe_command: None,
            environment_keys: vec![],
            tool_declaration: None,
            toolset_declaration: None,
        }
    }

    fn tool_map(
        surfaces: &[crate::discovery::ObservedGithubSurface],
    ) -> Vec<&crate::discovery::ObservedGithubTool> {
        surfaces.iter().flat_map(|s| s.tools.iter()).collect()
    }

    fn tool_by_name<'a>(
        surfaces: &'a [crate::discovery::ObservedGithubSurface],
        name: &str,
    ) -> &'a crate::discovery::ObservedGithubTool {
        tool_map(surfaces)
            .into_iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| panic!("tool {name} not classified"))
    }

    #[test]
    fn r1_github_content_variant_taxonomy() {
        let server = official_image_server(Some(
            "issue_read,pull_request_read,get_file_contents,get_file,get_repository_contents,\
code_search,search_code,search_repositories,list_issues,list_pull_requests,\
create_issue,create_pull_request,update_issue,update_pull_request,delete_issue,\
delete_pull_request,create_comment,merge_pull_request,unknown_tool",
        ));
        let surfaces = github::classify(&[server]);
        assert_eq!(surfaces.len(), 1);
        let expectations = [
            (
                "issue_read",
                "github:public:issue-content",
                "AGENT_INJECTABLE",
            ),
            (
                "pull_request_read",
                "github:public:pull-request-content",
                "AGENT_INJECTABLE",
            ),
            (
                "list_issues",
                "github:public:issue-content",
                "AGENT_INJECTABLE",
            ),
            (
                "list_pull_requests",
                "github:public:pull-request-content",
                "AGENT_INJECTABLE",
            ),
            (
                "get_file_contents",
                "github:repository-content",
                "AGENT_RETRIEVABLE",
            ),
            ("get_file", "github:repository-content", "AGENT_RETRIEVABLE"),
            (
                "get_repository_contents",
                "github:repository-content",
                "AGENT_RETRIEVABLE",
            ),
            (
                "code_search",
                "github:code-search-content",
                "AGENT_RETRIEVABLE",
            ),
            (
                "search_code",
                "github:code-search-content",
                "AGENT_RETRIEVABLE",
            ),
            (
                "search_repositories",
                "github:code-search-content",
                "AGENT_RETRIEVABLE",
            ),
            ("create_issue", "github:write:issue", "AGENT_MUTABLE"),
            ("update_issue", "github:write:issue", "AGENT_MUTABLE"),
            ("delete_issue", "github:write:issue", "AGENT_MUTABLE"),
            (
                "create_pull_request",
                "github:write:pull-request",
                "AGENT_MUTABLE",
            ),
            (
                "update_pull_request",
                "github:write:pull-request",
                "AGENT_MUTABLE",
            ),
            (
                "delete_pull_request",
                "github:write:pull-request",
                "AGENT_MUTABLE",
            ),
            (
                "merge_pull_request",
                "github:write:pull-request",
                "AGENT_MUTABLE",
            ),
            ("create_comment", "github:write:comment", "AGENT_MUTABLE"),
            ("unknown_tool", "github:unknown", "AGENT_RETRIEVABLE"),
        ];
        for (name, content_class, influence) in expectations {
            let tool = tool_by_name(&surfaces, name);
            assert_eq!(
                tool.content_class, content_class,
                "content_class mismatch for {name}"
            );
            assert_eq!(
                tool.influence_strength, influence,
                "influence_strength mismatch for {name}"
            );
        }
    }

    #[test]
    fn r2_github_trust_tiers_public_vs_unknown() {
        let server = official_image_server(Some(
            "issue_read,pull_request_read,get_file_contents,code_search,create_issue",
        ));
        let surfaces = github::classify(&[server]);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").trust,
            "PUBLIC_EXTERNAL"
        );
        assert_eq!(
            tool_by_name(&surfaces, "pull_request_read").trust,
            "PUBLIC_EXTERNAL"
        );
        assert_eq!(
            tool_by_name(&surfaces, "get_file_contents").trust,
            "UNKNOWN"
        );
        assert_eq!(tool_by_name(&surfaces, "code_search").trust, "UNKNOWN");
        // No static evidence supports PRIVATE_EXTERNAL; writes are UNKNOWN.
        assert_eq!(tool_by_name(&surfaces, "create_issue").trust, "UNKNOWN");
    }

    #[test]
    fn r3_github_influence_strength_tiers() {
        let server = official_image_server(Some("issue_read,get_file_contents,create_issue"));
        let surfaces = github::classify(&[server]);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").influence_strength,
            "AGENT_INJECTABLE"
        );
        assert_eq!(
            tool_by_name(&surfaces, "get_file_contents").influence_strength,
            "AGENT_RETRIEVABLE"
        );
        assert_eq!(
            tool_by_name(&surfaces, "create_issue").influence_strength,
            "AGENT_MUTABLE"
        );
    }

    #[test]
    fn r8_github_battery_toolset_declared_derived_transport_identity_failure() {
        // Official image + explicit tool declaration => DECLARED tier.
        let declared = official_image_server(Some("issue_read"));
        let surfaces = github::classify(&[declared]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").discovery_tier,
            "DECLARED"
        );

        // Official image with no declaration => DERIVED default (issue_read).
        let derived = official_image_server(None);
        let surfaces = github::classify(&[derived]);
        assert_eq!(surfaces.len(), 1);
        let derived_tool = tool_by_name(&surfaces, "issue_read");
        assert_eq!(derived_tool.discovery_tier, "DERIVED");
        assert_eq!(derived_tool.content_class, "github:public:issue-content");

        // Official remote endpoint (HTTP transport) is admitted the same way.
        let remote = official_remote_server();
        let surfaces = github::classify(&[remote]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").trust,
            "PUBLIC_EXTERNAL"
        );

        // Local stdio transport with official image is admitted by identity.
        let local = official_image_server(Some("issue_read"));
        assert_eq!(github::classify(&[local]).len(), 1);

        // Non-official identity is ignored entirely (spoof / provider illusion).
        let spoof = ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Http,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: None,
            safe_endpoint: Some("https://example.invalid/github-mcp-server".to_string()),
            safe_command: None,
            environment_keys: vec![],
            tool_declaration: Some("issue_read".to_string()),
            toolset_declaration: None,
        };
        assert!(github::classify(&[spoof]).is_empty());

        // Identity from a command must not admit an attacker HTTP endpoint.
        let identity_or_url = ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Http,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: Some("github-mcp-server".to_string()),
            safe_endpoint: Some("https://attacker.example/mcp".to_string()),
            safe_command: Some("evil-proxy github-mcp-server".to_string()),
            environment_keys: vec![],
            tool_declaration: Some("issue_read".to_string()),
            toolset_declaration: None,
        };
        assert!(github::classify(&[identity_or_url]).is_empty());

        // Disabled official server is still classified (admission is by
        // identity, not enabled state); the scan layer suppresses its edges.
        let mut disabled = official_image_server(Some("issue_read"));
        disabled.enabled = false;
        let surfaces = github::classify(&[disabled]);
        assert_eq!(surfaces.len(), 1);
        assert!(!surfaces[0].server.enabled);

        // Toolset declaration maps to its read tool (PARTIAL: a toolset that
        // yields no recognized tools still resolves to the DERIVED default).
        let toolset = ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Stdio,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: Some("github-mcp-server".to_string()),
            safe_endpoint: None,
            safe_command: None,
            environment_keys: vec![],
            tool_declaration: None,
            toolset_declaration: Some("issues".to_string()),
        };
        let surfaces = github::classify(&[toolset]);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").discovery_tier,
            "DECLARED"
        );

        // Provider-failure (PARTIAL) variant: a toolset that resolves to nothing
        // falls back to the DERIVED default rather than dropping the surface.
        let partial = ObservedMcpServer {
            provider: "opencode",
            name: "github".to_string(),
            transport: McpTransport::Stdio,
            enabled: true,
            source_locator: "project:opencode.json".to_string(),
            safe_identity: Some("ghcr.io/github/github-mcp-server".to_string()),
            safe_endpoint: None,
            safe_command: None,
            environment_keys: vec![],
            tool_declaration: None,
            toolset_declaration: Some("unknown_toolset".to_string()),
        };
        let surfaces = github::classify(&[partial]);
        assert_eq!(surfaces.len(), 1);
        assert_eq!(
            tool_by_name(&surfaces, "issue_read").discovery_tier,
            "DERIVED"
        );
    }

    #[test]
    fn r9_github_influence_stable_across_identical_configs() {
        let build = || {
            let server = official_image_server(Some(
                "issue_read,pull_request_read,get_file_contents,create_issue,create_comment",
            ));
            github::classify(&[server])
        };
        assert_eq!(build(), build());
    }
}

#[cfg(test)]
mod command_identity_tests {
    use super::*;

    fn parts(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn official_docker_image_is_an_identity() {
        assert_eq!(
            official_identity_from_command_parts(&parts(&[
                "docker",
                "run",
                "--rm",
                "ghcr.io/github/github-mcp-server:0.1.0",
            ])),
            Some("ghcr.io/github/github-mcp-server".to_string())
        );
        assert_eq!(
            official_identity_from_command_parts(&parts(&["github-mcp-server"])),
            Some("github-mcp-server".to_string())
        );
    }

    #[test]
    fn arbitrary_argv_containing_the_image_is_not_an_identity() {
        assert_eq!(
            official_identity_from_command_parts(&parts(&["evil-proxy", "github-mcp-server"])),
            None
        );
    }

    #[test]
    fn normalize_endpoint_strips_userinfo_and_query() {
        assert_eq!(
            normalize_endpoint("https://user:ghp_live@api.githubcopilot.com/mcp/?x=1"),
            "https://api.githubcopilot.com/mcp"
        );
        assert_eq!(
            normalize_endpoint("https://api.githubcopilot.com/mcp/"),
            "https://api.githubcopilot.com/mcp"
        );
    }

    #[test]
    fn looks_secret_matches_token_prefixes() {
        assert!(looks_secret("ghp_liveTokenShouldBeRedacted0000000000"));
        assert!(looks_secret("--token"));
        assert!(!looks_secret("issue_read"));
    }
}
