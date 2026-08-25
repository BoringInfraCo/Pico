//! Command-line entrypoint (SPRINT-001.md §4).
//!
//! Parses subcommands with clap, resolves the workspace to the current
//! directory, and delegates to the application layer. Contains no domain
//! or persistence logic.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::application::{InitService, ScanService};
use crate::shared::{PicoError, PICO_VERSION};

/// Pico discovers the dangerous paths your AI agents create.
#[derive(Parser)]
#[command(
    name = "pico",
    version = PICO_VERSION,
    about = "Pico discovers the dangerous paths your AI agents create.",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize Pico state in the current workspace.
    Init,
    /// Run a scan of the current workspace.
    Scan,
}

/// Runs the parsed CLI command.
pub fn run() -> Result<(), PicoError> {
    match Cli::parse().command {
        Command::Init => run_init(),
        Command::Scan => run_scan(),
    }
}

/// Resolves the workspace to the current directory.
fn workspace() -> Result<PathBuf, PicoError> {
    std::env::current_dir()
        .map_err(|e| PicoError::io(format!("cannot resolve current directory: {e}")))
}

/// Renders `pico init`.
fn run_init() -> Result<(), PicoError> {
    InitService::run(&workspace()?)?;
    println!("Pico initialized.");
    println!();
    println!(".pico/");
    println!("  pico.db");
    Ok(())
}

/// Renders `pico scan`.
fn run_scan() -> Result<(), PicoError> {
    let result = ScanService::run(&workspace()?)?;
    println!("Pico scan complete");
    println!();
    println!("Scan: {}", result.scan_id);
    println!("Status: {}", result.status);
    println!();
    println!("Agents:        {}", result.agent_count);
    println!("Resources:     {}", result.resource_count);
    println!("Relationships: {}", result.relationship_count);
    println!("Evidence:      {}", result.evidence_count);
    println!("Security Graph: {}", result.graph_projection_status);
    println!("Graph Nodes:    {}", result.graph_node_count);
    println!("Graph Edges:    {}", result.graph_edge_count);
    println!("State-Eligible Edges: {}", result.state_eligible_edge_count);
    println!("Non-Eligible Edges:   {}", result.non_eligible_edge_count);
    println!("Analysis:       {}", result.analysis_status);
    println!("Analysis Disposition: {}", result.analysis_disposition);
    println!("Influence Paths: {}", result.influence_path_count);
    println!("Authority Paths: {}", result.authority_path_count);
    println!(
        "Potentially Active AttackPaths: {}",
        result.active_attack_path_count
    );
    println!("Blocked AttackPaths: {}", result.blocked_attack_path_count);
    println!(
        "Unresolved Candidates: {}",
        result.unresolved_candidate_count
    );
    println!("Findings:        {}", result.finding_count);
    if let Some(class) = result.finding_class {
        println!("Finding:         {class}");
    }
    if let Some(severity) = result.finding_severity {
        println!("Severity:        {severity}");
    }
    if let Some(confidence) = result.finding_confidence {
        println!("Confidence:      {confidence}");
    }
    if let Some(permission) = result.bash_permission {
        println!("Effective Bash: {permission}");
    }
    println!(
        "GitHub MCP:    {}",
        if result.github_mcp_observed {
            "OBSERVED"
        } else {
            "NOT OBSERVED"
        }
    );
    if let Some(strength) = result.influence_strength {
        println!("Influence:     {strength}");
    }
    println!(
        "Cloudflare Credential: {}",
        if result.cloudflare_credential_observed {
            "OBSERVED"
        } else {
            "NOT OBSERVED"
        }
    );
    if let Some(reachability) = result.credential_reachability {
        println!("Credential Reachability: {reachability}");
    }
    if let Some(status) = result.cloudflare_credential_status {
        println!("Cloudflare Credential Status: {status}");
    }
    println!("Cloudflare Accounts: {}", result.cloudflare_account_count);
    println!("Cloudflare Workers: {}", result.cloudflare_worker_count);
    if let Some(authority) = result.worker_mutation_authority {
        println!("Worker Mutation Authority: {authority}");
    }
    if let Some(resolution) = result.authority_resolution {
        println!("Authority Resolution: {resolution}");
    }
    println!("Credential Value Stored: NO");
    Ok(())
}
