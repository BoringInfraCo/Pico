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
                    .filter(|name| {
                        matches!(
                            name.as_str(),
                            "issue_read" | "pull_request_read" | "get_file_contents"
                        )
                    })
                    .map(|name| {
                        let (content_class, trust) = match name.as_str() {
                            "issue_read" => ("github:public:issue-content", "PUBLIC_EXTERNAL"),
                            "pull_request_read" => {
                                ("github:public:pull-request-content", "PUBLIC_EXTERNAL")
                            }
                            _ => ("github:repository-content", "UNKNOWN"),
                        };
                        ObservedGithubTool {
                            name,
                            discovery_tier: tier,
                            permission: PermissionAction::Unknown,
                            permission_pattern: String::new(),
                            content_class,
                            trust,
                            influence_strength: "AGENT_RETRIEVABLE",
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
