//! Bounded MCP adapter boundaries. Protocol facts are normalized here, while
//! OpenCode configuration parsing remains in the OpenCode adapter.

use super::{ObservedGithubSurface, ObservedGithubTool, ObservedMcpServer, PermissionAction};

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

    fn is_official(server: &ObservedMcpServer) -> bool {
        server.safe_identity.as_deref().is_some_and(|identity| {
            identity == "ghcr.io/github/github-mcp-server" || identity == "github-mcp-server"
        }) || server
            .safe_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint == OFFICIAL_REMOTE)
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

        // Local stdio transport with official image is admitted (transport is
        // not the admission gate).
        let local = official_image_server(Some("issue_read"));
        assert_eq!(github::classify(&[local]).len(), 1);

        // Non-official identity is ignored entirely (spoof / provider illusion).
        let spoof = ObservedMcpServer {
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
