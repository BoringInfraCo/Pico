//! Command-line entrypoint (SPRINT-001.md §4).
//!
//! Parses subcommands with clap, resolves the workspace to the current
//! directory, and delegates to the application layer. Contains no domain
//! or persistence logic.

pub mod render;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::application::{
    finding_navigation_ids, DiffService, DoctorService, FindingQueryService, HistoryService,
    InitService, PruneService, ScanService,
};
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
    /// List all scans with status and finding counts.
    History {
        /// Emit the versioned public JSON contract.
        #[arg(long)]
        json: bool,
    },
    /// List Findings from the newest COMPLETE scan.
    Findings,
    /// Show one Finding by its exact ID.
    Finding { id: String },
    /// Compare Findings across scans. No args: last two COMPLETE. Two args: explicit pair.
    Diff {
        /// Older scan id (COMPLETE).
        from: Option<String>,
        /// Newer scan id (COMPLETE).
        to: Option<String>,
        /// Emit the versioned public JSON contract.
        #[arg(long)]
        json: bool,
    },
    /// Prune local scan history beyond the retention window.
    Prune {
        /// Number of COMPLETE scans to retain (>= 2, default 10).
        #[arg(long)]
        keep: Option<usize>,
    },
    /// Report local database health (read-only).
    Doctor,
    /// Serve Pico findings to coding agents over MCP (stdio).
    Mcp,
}

/// Runs the parsed CLI command.
pub fn run() -> Result<(), PicoError> {
    match Cli::parse().command {
        Command::Init => run_init(),
        Command::Scan => run_scan(),
        Command::History { json } => run_history(json),
        Command::Findings => run_findings(),
        Command::Finding { id } => run_finding(&id),
        Command::Diff { from, to, json } => run_diff(from.as_deref(), to.as_deref(), json),
        Command::Prune { keep } => run_prune(keep),
        Command::Doctor => run_doctor(),
        Command::Mcp => crate::mcp::run(),
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
    if let Some(class) = &result.finding_class {
        println!("Finding:         {class}");
    }
    if let Some(severity) = &result.finding_severity {
        println!("Severity:        {severity}");
    }
    if let Some(confidence) = &result.finding_confidence {
        println!("Confidence:      {confidence}");
    }
    print!("{}", render::render_scan_effective_bash(&result));
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
    let github_authority = render::render_github_credential_authority(&result.github_credentials);
    if !github_authority.is_empty() {
        println!();
        print!("{}", github_authority);
    }
    let diagnostics = render::render_scan_diagnostics(
        result
            .diagnostics_detail
            .as_ref()
            .expect("diagnostics_detail is always populated by the scan service"),
    );
    if !diagnostics.is_empty() {
        println!();
        print!("{}", diagnostics);
    }
    print!("{}", navigation_hint(result.findings.as_ref()));
    Ok(())
}

/// Renders `pico findings`.
fn run_findings() -> Result<(), PicoError> {
    let list = FindingQueryService::list_latest(&workspace()?)?;
    print!("{}", render::render_findings_list(&list));
    Ok(())
}

/// Renders `pico history`.
fn run_history(json: bool) -> Result<(), PicoError> {
    let result = workspace().and_then(|workspace| HistoryService::list(&workspace));
    if json {
        return match result {
            Ok(history) => print_json(&crate::output::history(&history)),
            Err(error) => print_json_error("history", error),
        };
    }
    let history = result?;
    print!("{}", render::render_scan_history(&history));
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

/// Renders `pico diff` or `pico diff <from> <to>`.
fn run_diff(from: Option<&str>, to: Option<&str>, json: bool) -> Result<(), PicoError> {
    let result = query_diff(from, to);
    if json {
        return match result {
            Ok(result) => print_json(&crate::output::diff(&result)),
            Err(error) => print_json_error("diff", error),
        };
    }
    print!("{}", render::render_finding_diff(&result?));
    Ok(())
}

fn query_diff(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<crate::application::FindingDiffResult, PicoError> {
    let result = match (from, to) {
        (Some(from_id), Some(to_id)) => DiffService::compare(&workspace()?, from_id, to_id)?,
        (None, None) => DiffService::latest(&workspace()?)?,
        _ => {
            return Err(PicoError::usage(
                "diff requires either zero or two scan ids: pico diff  OR  pico diff <from> <to>",
            ));
        }
    };
    Ok(result)
}

fn print_json(payload: &impl serde::Serialize) -> Result<(), PicoError> {
    use std::io::Write;
    let encoded =
        serde_json::to_string(payload).map_err(|_| PicoError::io("cannot encode JSON output"))?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{encoded}").map_err(|_| PicoError::io("cannot write JSON output"))
}

fn print_json_error(command: &str, error: PicoError) -> Result<(), PicoError> {
    print_json(&crate::output::error(command, &error))?;
    // main.rs preserves failure exit behavior, without echoing raw DB or ID data.
    Err(PicoError::usage("query failed; see JSON error on stdout"))
}

/// Renders `pico prune` (SPRINT-030.md §5.4). Service-level failures (keep
/// validation, RUNNING refusal, health-gate aborts) propagate as errors so
/// the process exits with FAILURE; a below-window no-op is a success with an
/// explicit report.
fn run_prune(keep: Option<usize>) -> Result<(), PicoError> {
    let report = PruneService::run(&workspace()?, keep)?;
    print!("{}", render::render_prune_report(&report));
    Ok(())
}

/// Renders `pico doctor` (SPRINT-030.md §5.3/§5.4). The full health report is
/// printed to stdout even when a check fails; the fail-closed database error
/// is then returned so the process still exits with FAILURE for scripts.
fn run_doctor() -> Result<(), PicoError> {
    let report = DoctorService::run(&workspace()?)?;
    print!("{}", render::render_doctor_report(&report));
    if !report.ok {
        return Err(PicoError::database(
            "pico doctor: database health check failed",
        ));
    }
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
                family_fingerprint: format!("sha256:family{index}"),
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
