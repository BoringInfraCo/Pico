//! Command-line entrypoint (SPRINT-001.md §4).
//!
//! Parses subcommands with clap, resolves the workspace to the current
//! directory, and delegates to the application layer. Contains no domain
//! or persistence logic.

pub mod render;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::application::{finding_navigation_ids, FindingQueryService, InitService, ScanService};
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
    /// List Findings from the newest COMPLETE scan.
    Findings,
    /// Show one Finding by its exact ID.
    Finding { id: String },
}

/// Runs the parsed CLI command.
pub fn run() -> Result<(), PicoError> {
    match Cli::parse().command {
        Command::Init => run_init(),
        Command::Scan => run_scan(),
        Command::Findings => run_findings(),
        Command::Finding { id } => run_finding(&id),
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
    print!("{}", navigation_hint(result.findings.as_ref()));
    Ok(())
}

/// Renders `pico findings`.
fn run_findings() -> Result<(), PicoError> {
    let list = FindingQueryService::list_latest(&workspace()?)?;
    print!("{}", render::render_findings_list(&list));
    Ok(())
}

/// Renders `pico finding <id>`.
fn run_finding(id: &str) -> Result<(), PicoError> {
    if id.is_empty() {
        return Err(PicoError::usage("a non-empty Finding ID is required"));
    }
    let detail = FindingQueryService::get(&workspace()?, id)?;
    print!("{}", render::render_finding_detail(&detail));
    Ok(())
}

/// Builds the `pico scan` Finding-ID navigation hint in deterministic order.
fn navigation_hint(findings: Option<&crate::findings::FindingResult>) -> String {
    let Some(findings) = findings else {
        return String::new();
    };
    let ids = finding_navigation_ids(findings);
    if ids.is_empty() {
        return String::new();
    }
    let mut out = String::from("Findings:\n");
    for id in ids {
        out.push_str("  ");
        out.push_str(&crate::shared::terminal_safe(&id));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::navigation_hint;
    use crate::findings::{
        Confidence, Finding, FindingClass, FindingGenerationStatus, FindingResult, FindingStatus,
        Remediation, Severity,
    };

    fn result_with(ids: &[(&str, Severity, Confidence)]) -> FindingResult {
        let findings: Vec<Finding> = ids
            .iter()
            .enumerate()
            .map(|(index, (id, severity, confidence))| Finding {
                id: (*id).to_string(),
                scan_id: "scan_nav".to_string(),
                fingerprint: format!("sha256:fp{index}"),
                finding_version: 1,
                finding_class: FindingClass::UntrustedToProduction,
                status: FindingStatus::Open,
                title: format!("title {index}"),
                summary: "summary".to_string(),
                severity: *severity,
                confidence: *confidence,
                source_resource_ids: Vec::new(),
                actor_resource_ids: Vec::new(),
                sink_resource_ids: Vec::new(),
                attack_path_ids: Vec::new(),
                attack_path_fingerprints: Vec::new(),
                evidence_ids: Vec::new(),
                reasons: Vec::new(),
                remediations: vec![Remediation {
                    rule_id: "ENFORCE_BASH_APPROVAL_OR_DENY".to_string(),
                    title: "t".to_string(),
                    description: "d".to_string(),
                    security_effect: "e".to_string(),
                    cut_phase: "AUTHORITY".to_string(),
                    target_resource_ids: Vec::new(),
                    target_relationship_ids: Vec::new(),
                }],
                created_at: chrono::Utc::now(),
            })
            .collect();
        FindingResult {
            scan_id: "scan_nav".to_string(),
            finding_version: 1,
            status: FindingGenerationStatus::Complete,
            findings,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn navigation_hint_prints_every_id_in_deterministic_order() {
        let result = result_with(&[
            ("id-high", Severity::High, Confidence::High),
            ("id-crit", Severity::Critical, Confidence::High),
            ("id-low", Severity::Medium, Confidence::Low),
        ]);
        let hint = navigation_hint(Some(&result));
        assert_eq!(hint, "Findings:\n  id-crit\n  id-high\n  id-low\n");
    }

    #[test]
    fn navigation_hint_is_empty_without_findings() {
        assert_eq!(navigation_hint(None), "");
        assert_eq!(navigation_hint(Some(&result_with(&[]))), "");
    }

    #[test]
    fn navigation_hint_sanitizes_ids() {
        let result = result_with(&[("id\x1b[31mX", Severity::Critical, Confidence::High)]);
        let hint = navigation_hint(Some(&result));
        assert!(!hint.contains('\u{1b}'));
        assert!(hint.contains("id\\x1B[31mX"));
    }

    #[test]
    fn empty_finding_id_is_a_usage_error() {
        let error = super::run_finding("").unwrap_err();
        assert!(matches!(error, crate::shared::PicoError::Usage(_)));
    }
}
