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
    println!("Resources:     {}", result.resource_count);
    println!("Relationships: {}", result.relationship_count);
    println!("Evidence:      {}", result.evidence_count);
    println!("Findings:      {}", result.finding_count);
    Ok(())
}
