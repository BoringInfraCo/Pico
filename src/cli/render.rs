//! Deterministic terminal rendering of Finding DTOs (SPRINT-010.md §7/§10).
//!
//! These functions format the application DTOs only; they contain no SQL, no
//! security logic, and no provider interpretation. Every persisted string is
//! passed through `terminal_safe` so untrusted text cannot spoof the layout.

use crate::application::diff::{FindingLifecycleChange, FindingRatingDelta};
use crate::application::{
    findings_list_guidance, findings_list_state, DiffFinding, FindingDetail, FindingDiff,
    FindingDiffResult, FindingList, FindingSummary, FindingsListState, GraphSubject,
    GraphSubjectDiff, ScanHistory, ScanResult,
};
use crate::application::{
    ComparedVia, ComparisonContractVersions, DiffNotComparable, DiffNotComparableReason, Freshness,
    HealthReport, PruneReport, RetentionCounts, UnitCounts,
};
use crate::findings::diagnostics::ScanDiagnostics;
use crate::shared::terminal_safe;

/// Renders `pico findings` for the selected scan snapshot.
pub fn render_findings_list(list: &FindingList) -> String {
    let mut out = String::new();
    out.push_str("Pico Findings\n\n");
    let state = findings_list_state(list);
    if state != FindingsListState::ResultsAvailable {
        let guidance = findings_list_guidance(state, list);
        if state == FindingsListState::NoScans {
            for line in &guidance {
                out.push_str(line);
                out.push('\n');
            }
            return out;
        }
        out.push_str(&guidance[0]);
        out.push('\n');
        if let Some(attempt) = &list.newest_scan_attempt {
            out.push_str(&format!(
                "Newest scan attempt: {} ({})\n",
                terminal_safe(&attempt.id),
                terminal_safe(&attempt.status)
            ));
        }
        out.push_str("Run `pico scan` and let it complete to produce results.\n");
        out.push_str(&guidance[1]);
        out.push('\n');
        return out;
    }
    let selected = match &list.selected_scan {
        Some(scan) => scan,
        None => return out,
    };
    {
        out.push_str(&format!("Scan: {}\n", terminal_safe(&selected.id)));
        out.push_str(&format!("Status: {}\n", terminal_safe(&selected.status)));
        out.push_str(&format!(
            "Completed: {}\n",
            selected
                .completed_at
                .as_deref()
                .map(terminal_safe)
                .unwrap_or_else(|| "n/a".to_string())
        ));
        out.push_str(match list.freshness {
            crate::application::Freshness::LatestComplete => "Freshness: LATEST COMPLETE\n",
            crate::application::Freshness::NewerIncomplete => {
                "Freshness: NEWER INCOMPLETE ATTEMPT\n"
            }
        });
        if let Some(warning) = &list.freshness_warning {
            out.push('\n');
            for line in warning.split('\n') {
                out.push_str(&terminal_safe(line));
                out.push('\n');
            }
        }
        out.push_str(&format!("Findings: {}\n", list.findings.len()));
    }

    for summary in &list.findings {
        out.push('\n');
        push_summary(&mut out, summary);
        out.push_str("\nRun:\n  pico finding ");
        out.push_str(&terminal_safe(&summary.id));
        out.push('\n');
    }

    if list.findings.is_empty() {
        out.push('\n');
        for line in findings_list_guidance(FindingsListState::ResultsAvailable, list) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Renders one Finding summary block inside the list.
fn push_summary(out: &mut String, summary: &FindingSummary) {
    out.push_str(&format!(
        "{} · {} confidence\n",
        terminal_safe(&summary.severity),
        terminal_safe(&summary.confidence)
    ));
    out.push_str(&terminal_safe(&summary.title));
    out.push('\n');
    out.push_str(&format!(
        "Class: {}\n",
        terminal_safe(&summary.finding_class)
    ));
    out.push_str(&format!("Status: {}\n", terminal_safe(&summary.status)));
    out.push_str(&format!("Paths: {}\n", summary.attack_path_count));
    out.push_str(&format!(
        "Affected production resources: {}\n",
        summary.affected_sink_count
    ));
    out.push_str(&format!("ID: {}\n", terminal_safe(&summary.id)));
    out.push_str(&format!(
        "Fingerprint: {}\n",
        terminal_safe(&summary.fingerprint)
    ));
}

/// Renders `pico finding <id>` for one persisted Finding.
pub fn render_finding_detail(detail: &FindingDetail) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} · {} confidence\n",
        terminal_safe(&detail.severity),
        terminal_safe(&detail.confidence)
    ));
    out.push_str(&terminal_safe(&detail.title));
    out.push_str("\n\n");

    out.push_str("Finding\n");
    out.push_str(&format!("ID: {}\n", terminal_safe(&detail.id)));
    out.push_str(&format!(
        "Fingerprint: {}\n",
        terminal_safe(&detail.fingerprint)
    ));
    out.push_str(&format!(
        "Grouped paths: {}\n",
        detail.attack_path_fingerprints.len()
    ));
    out.push_str(&format!("Version: {}\n", detail.finding_version));
    out.push_str(&format!(
        "Class: {}\n",
        terminal_safe(&detail.finding_class)
    ));
    out.push_str(&format!("Status: {}\n", terminal_safe(&detail.status)));
    out.push_str(&format!("Scan: {}\n", terminal_safe(&detail.scan.id)));
    out.push_str(&format!(
        "Scan status: {}\n",
        terminal_safe(&detail.scan.status)
    ));
    out.push_str(&format!("Created: {}\n", terminal_safe(&detail.created_at)));
    match &detail.currentness {
        crate::application::Currentness::LatestComplete => {
            out.push_str("Currentness: LATEST_COMPLETE\n");
        }
        crate::application::Currentness::Historical {
            newer_complete_scan_id,
        } => {
            out.push_str("Currentness: HISTORICAL\n");
            out.push_str(&format!(
                "Newer COMPLETE scan: {}\n",
                terminal_safe(newer_complete_scan_id)
            ));
        }
    }
    if let Some(warning) = &detail.freshness_warning {
        out.push_str("Freshness: NEWER INCOMPLETE ATTEMPT\n");
        for line in warning.split('\n') {
            out.push_str(&terminal_safe(line));
            out.push('\n');
        }
    }
    out.push('\n');

    out.push_str("What Pico found\n");
    out.push_str(&terminal_safe(&detail.summary));
    out.push_str("\n\n");

    out.push_str("Why it matters\n");
    out.push_str(&terminal_safe(&detail.title));
    out.push('\n');
    out.push_str(&terminal_safe(&detail.summary));
    out.push_str("\n\n");

    out.push_str("Reasons\n");
    if detail.reasons.is_empty() {
        out.push_str("No recorded reasons.\n");
    } else {
        for reason in &detail.reasons {
            out.push_str(&format!(
                "{}. {} — {}\n",
                reason.position + 1,
                terminal_safe(&reason.code),
                terminal_safe(&reason.explanation)
            ));
        }
    }
    out.push('\n');

    out.push_str("Path or Paths\n");
    if detail.paths.is_empty() {
        out.push_str("No linked attack paths.\n");
    } else {
        for (index, path) in detail.paths.iter().enumerate() {
            out.push_str(&format!("Path {}\n", index + 1));
            out.push_str(&path_chain(path));
            out.push('\n');
            out.push_str(&format!(
                "Disposition: {}\n",
                terminal_safe(&path.disposition)
            ));
            out.push_str(&format!(
                "Source trust: {}\n",
                terminal_safe(&path.source_trust)
            ));
            out.push_str(&format!(
                "Influence strength: {}\n",
                terminal_safe(&path.influence_strength)
            ));
            out.push_str(&format!(
                "Capability: {}\n",
                terminal_safe(&path.capability)
            ));
            out.push_str(&format!(
                "Authority resolution: {}\n",
                terminal_safe(&path.authority_resolution)
            ));
            out.push_str(&format!(
                "Sink impact: {}\n",
                terminal_safe(&path.sink_impact)
            ));
            out.push_str(&format!(
                "Source: {}\n",
                terminal_safe(&path.source_resource_id)
            ));
            out.push_str(&format!(
                "Actor: {}\n",
                terminal_safe(&path.actor_resource_id)
            ));
            out.push_str(&format!(
                "Sink: {}\n",
                terminal_safe(&path.sink_resource_id)
            ));
            if path.agents.len() > 1 {
                for agent in &path.agents {
                    let boundary = agent.bash_boundary.as_deref().unwrap_or("none");
                    out.push_str(&format!(
                        "Agent {} effective Bash: {}; boundary: {}\n",
                        terminal_safe(&agent.provider),
                        terminal_safe(&agent.effective_bash_capability),
                        terminal_safe(boundary),
                    ));
                }
            } else if let Some(capability) = &path.effective_bash_capability {
                out.push_str(&format!(
                    "Effective Bash capability: {}\n",
                    terminal_safe(capability)
                ));
                match &path.bash_boundary {
                    Some(boundary) => {
                        out.push_str(&format!(
                            "Bash interrupting boundary: {}\n",
                            terminal_safe(boundary)
                        ));
                    }
                    None => {
                        out.push_str("Bash interrupting boundary: none\n");
                    }
                }
            }
            for step in &path.steps {
                out.push_str(&format!(
                    "  {} {} {} → {} {} ({})\n",
                    step.position,
                    terminal_safe(&step.phase),
                    terminal_safe(&step.traversal),
                    terminal_safe(&step.from_resource.name),
                    terminal_safe(&step.to_resource.name),
                    terminal_safe(&step.relationship_kind)
                ));
                out.push_str("  Supporting evidence:");
                if step.evidence_ids.is_empty() {
                    out.push_str(" none\n");
                } else {
                    out.push(' ');
                    out.push_str(
                        &step
                            .evidence_ids
                            .iter()
                            .map(|id| terminal_safe(id))
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    out.push('\n');
                }
                for provenance in &step.supporting_evidence {
                    out.push_str(&format!(
                        "    - {} locator={} captured={} freshness={}\n",
                        terminal_safe(&provenance.evidence_id),
                        provenance
                            .safe_source_locator
                            .as_deref()
                            .map(terminal_safe)
                            .unwrap_or_else(|| "<redacted source locator>".to_string()),
                        terminal_safe(&provenance.captured_at),
                        terminal_safe(&provenance.freshness),
                    ));
                }
            }
            if path.boundaries.is_empty() {
                out.push_str("  Recorded boundaries: none\n");
            } else {
                for boundary in &path.boundaries {
                    out.push_str(&format!(
                        "  Boundary {}: {}\n",
                        terminal_safe(&boundary.kind),
                        terminal_safe(&boundary.decision)
                    ));
                }
            }
            if !path.github_influence.is_empty() {
                out.push_str("GitHub MCP influence:\n");
                for entry in &path.github_influence {
                    out.push_str(&format!(
                        "  GitHub MCP {}: {} | trust={} | influence={}\n",
                        terminal_safe(&entry.tool_name),
                        terminal_safe(&entry.content_class),
                        terminal_safe(&entry.trust),
                        terminal_safe(&entry.influence_strength),
                    ));
                }
            }
            if !path.cloudflare_authority.is_empty() {
                out.push_str("Cloudflare authority:\n");
                for authority in &path.cloudflare_authority {
                    let mut line = format!(
                        "  Cloudflare {} authority: resolution={} granted=[{}] scope={}",
                        terminal_safe(&authority.credential_type),
                        terminal_safe(&authority.authority_resolution),
                        authority
                            .granted_permissions
                            .iter()
                            .map(|permission| terminal_safe(permission))
                            .collect::<Vec<_>>()
                            .join(", "),
                        terminal_safe(&authority.account_scope_state),
                    );
                    if authority.zone_scoped {
                        line.push_str(" zone-scoped");
                    }
                    if authority.permission_state == "GLOBAL_API_KEY" {
                        line.push_str(" global-key-unverified");
                    }
                    line.push('\n');
                    out.push_str(&line);
                }
            }
            out.push('\n');
        }
    }

    out.push_str("Severity and Confidence\n");
    out.push_str(&format!("Severity: {}\n", terminal_safe(&detail.severity)));
    out.push_str(&format!(
        "Confidence: {}\n",
        terminal_safe(&detail.confidence)
    ));
    out.push_str("Severity — what could happen if the established path is usable.\n");
    out.push_str("Confidence — how strongly Pico established that this Finding exists.\n");
    out.push_str(&terminal_safe(&detail.severity_basis));
    out.push('\n');
    out.push_str(&terminal_safe(&detail.confidence_basis));
    out.push_str("\n\n");

    out.push_str("Weakest evidence\n");
    out.push_str(&terminal_safe(&detail.weakest_evidence));
    out.push('\n');

    out.push_str("Evidence\n");
    if detail.evidence.is_empty() {
        out.push_str("No same-scan Evidence recorded.\n");
    } else {
        for evidence in &detail.evidence {
            out.push_str(&format!("Evidence: {}\n", terminal_safe(&evidence.id)));
            out.push_str(&format!("  Class: {}\n", terminal_safe(&evidence.class)));
            out.push_str(&format!(
                "  Source type: {}\n",
                terminal_safe(&evidence.source_type)
            ));
            out.push_str(&format!(
                "  Source: {}\n",
                evidence
                    .safe_source_locator
                    .as_deref()
                    .map(terminal_safe)
                    .unwrap_or_else(|| "<redacted source locator>".to_string())
            ));
            out.push_str(&format!(
                "  Subject: {}\n",
                terminal_safe(&evidence.subject)
            ));
            out.push_str(&format!(
                "  Observation: {}\n",
                terminal_safe(&evidence.observation)
            ));
            out.push_str(&format!(
                "  Captured: {}\n",
                terminal_safe(&evidence.captured_at)
            ));
            out.push_str(&format!(
                "  Freshness: {}\n",
                terminal_safe(&evidence.freshness)
            ));
            out.push_str(&format!(
                "  Sensitivity: {}\n",
                terminal_safe(&evidence.sensitivity)
            ));
            out.push_str(&format!(
                "  Support roles: {}\n",
                evidence
                    .support_roles
                    .iter()
                    .map(|role| terminal_safe(role))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    out.push('\n');

    out.push_str("Boundaries and Uncertainty\n");
    out.push_str(&terminal_safe(&detail.boundary_summary));
    out.push('\n');
    for uncertainty in &detail.uncertainties {
        out.push_str("- ");
        out.push_str(&terminal_safe(uncertainty));
        out.push('\n');
    }
    out.push('\n');

    out.push_str("Recommended cuts\n");
    for remediation in &detail.remediations {
        out.push_str(&format!(
            "{}. {} ({})\n",
            remediation.position + 1,
            terminal_safe(&remediation.title),
            terminal_safe(&remediation.rule_id)
        ));
        out.push_str(&format!(
            "   Description: {}\n",
            terminal_safe(&remediation.description)
        ));
        out.push_str(&format!(
            "   Security effect: {}\n",
            terminal_safe(&remediation.security_effect)
        ));
        out.push_str(&format!(
            "   Cut phase: {}\n",
            terminal_safe(&remediation.cut_phase)
        ));
        out.push_str("   Target resources:");
        if remediation.target_resources.is_empty() {
            out.push_str(" none\n");
        } else {
            out.push(' ');
            out.push_str(
                &remediation
                    .target_resources
                    .iter()
                    .map(|resource| {
                        format!(
                            "{} ({})",
                            terminal_safe(&resource.name),
                            terminal_safe(&resource.id)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            out.push('\n');
        }
        out.push_str("   Target relationships:");
        if remediation.target_relationship_ids.is_empty() {
            out.push_str(" none\n");
        } else {
            out.push(' ');
            out.push_str(
                &remediation
                    .target_relationship_ids
                    .iter()
                    .map(|id| terminal_safe(id))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            out.push('\n');
        }
        out.push_str("   Target relationship (human-readable):");
        if remediation.target_relationship_descriptions.is_empty() {
            out.push_str(" none\n");
        } else {
            out.push('\n');
            for description in &remediation.target_relationship_descriptions {
                out.push_str(&format!("     - {}\n", terminal_safe(description)));
            }
        }
    }
    out.push_str(&terminal_safe(&detail.remediation_note));
    out.push_str("\n\n");

    out.push_str("Scope note\n");
    out.push_str("Potential exposure, not exploitation\n");
    out.push_str(&terminal_safe(&detail.scope_note));
    out.push('\n');
    out
}

/// Renders the structured scan diagnostics block for the `pico scan` summary.
///
/// Prints an honest, human-readable explanation of incomplete evidence:
/// per-provider reachability (with sanitized problems), the scan lifecycle
/// status, suppressed candidate Findings, and confidence-reducing edges. When
/// the diagnostics are clean (the golden Complete + Fresh path), this returns an
/// empty string so the golden path is never given spurious noise.
pub fn render_scan_diagnostics(diagnostics: &ScanDiagnostics) -> String {
    if diagnostics.is_clean() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("Incomplete evidence\n");

    for provider in &diagnostics.provider_statuses {
        out.push_str(&format!(
            "Provider {}: {}\n",
            terminal_safe(&provider.name),
            if provider.reachable {
                "reachable"
            } else {
                "FAILED"
            }
        ));
        for problem in &provider.problems {
            out.push_str(&format!("  - {}\n", terminal_safe(problem)));
        }
    }

    match &diagnostics.partial_reason {
        Some(reason) => out.push_str(&format!(
            "Scan status: PARTIAL ({})\n",
            terminal_safe(reason)
        )),
        None => out.push_str(&format!(
            "Scan status: {}\n",
            terminal_safe(&diagnostics.scan_status)
        )),
    }

    for suppressed in &diagnostics.suppressed {
        out.push_str(&format!(
            "Suppressed {}: {}\n",
            terminal_safe(&suppressed.fingerprint),
            terminal_safe(&suppressed.reason)
        ));
    }

    for note in &diagnostics.reduced_confidence {
        out.push_str(&format!(
            "Confidence reduced {}:",
            terminal_safe(&note.fingerprint)
        ));
        for (edge_key, freshness, penalty) in &note.edges {
            out.push_str(&format!(
                " {} ({}, -{})",
                terminal_safe(edge_key),
                terminal_safe(freshness),
                penalty
            ));
        }
        out.push('\n');
    }

    out
}

/// Renders `pico diff` (SPRINT-024; comparison-contract provenance and
/// non-comparable states per SPRINT-029 §5.5).
pub fn render_finding_diff(result: &FindingDiffResult) -> String {
    match result {
        FindingDiffResult::NoCompleteScan => {
            "Pico diff\n\nNo COMPLETE scan exists in this workspace.\nRun `pico scan` and let it complete to produce results.\nThis is not an all-clear.\n".to_string()
        }
        FindingDiffResult::NeedPrevious { newest_complete, .. } => {
            format!(
                "Pico diff\n\nA previous COMPLETE scan is required to compare.\nNewest COMPLETE scan: {} ({})\nRun `pico scan` again after a completed scan to produce a diff.\nThis is not an all-clear.\n",
                terminal_safe(&newest_complete.id),
                terminal_safe(&newest_complete.status)
            )
        }
        FindingDiffResult::NotComparable(nc) => render_not_comparable_diff(nc),
        FindingDiffResult::Ready(diff) => render_ready_diff(diff),
    }
}

/// `c{ccv}-g{gsv}-a{av}-f{fv}` for one side's persisted comparison contract
/// (SPRINT-029.md §5.5). Integer components are validated u32/u64 values, so
/// they render as plain integers without sanitization.
fn comparison_contract_label(contract: Option<&ComparisonContractVersions>) -> String {
    match contract {
        Some(contract) => format!(
            "c{}-g{}-a{}-f{}",
            contract.comparison_contract_version,
            contract.graph_snapshot_version,
            contract.analysis_version,
            contract.finding_version
        ),
        // The guard only decides ContractChanged/ContractUnsupported when
        // both side tuples are present; this keeps the renderer total for an
        // invariant violation instead of fabricating a tuple.
        None => "(unavailable)".to_string(),
    }
}

/// Renders a comparison pair the contract guard refused to compare
/// (SPRINT-029.md §5.5, frozen). Comparison is skipped: the render names both
/// sides and the guard decision, then states that no Finding, graph,
/// lifecycle, or Cause claim was computed. It never renders Findings,
/// Resources, Relationships, change counts, the S024 no-change sentence, or a
/// Cause line, and never reads as an all-clear.
fn render_not_comparable_diff(nc: &DiffNotComparable) -> String {
    let mut out = String::from("Pico diff\n\n");
    out.push_str(&format!(
        "From: {} ({})\n",
        terminal_safe(&nc.from.id),
        terminal_safe(&nc.from.status)
    ));
    out.push_str(&format!(
        "To:   {} ({})\n",
        terminal_safe(&nc.to.id),
        terminal_safe(&nc.to.status)
    ));
    match nc.compared_via {
        ComparedVia::LatestTwo => {
            out.push_str("Compared: LAST TWO COMPLETE SCANS\n");
            out.push_str(match nc.freshness {
                Freshness::LatestComplete => "Freshness: LATEST COMPLETE\n",
                Freshness::NewerIncomplete => "Freshness: NEWER INCOMPLETE ATTEMPT\n",
            });
            if let Some(warning) = &nc.freshness_warning {
                for line in warning.split('\n') {
                    out.push_str(&terminal_safe(line));
                    out.push('\n');
                }
            }
        }
        ComparedVia::ExplicitPair => {
            out.push_str("Compared: EXPLICIT PAIR\n");
        }
    }
    out.push('\n');
    match nc.reason {
        DiffNotComparableReason::ContractChanged => {
            debug_assert!(
                nc.provenance.from.contract.is_some() && nc.provenance.to.contract.is_some(),
                "ContractChanged requires both side tuples"
            );
            out.push_str(&format!(
                "Comparison contracts: {} → {} (MISMATCH)\n",
                comparison_contract_label(nc.provenance.from.contract.as_ref()),
                comparison_contract_label(nc.provenance.to.contract.as_ref()),
            ));
        }
        DiffNotComparableReason::ContractUnsupported => {
            debug_assert!(
                nc.provenance.from.contract.is_some() && nc.provenance.to.contract.is_some(),
                "ContractUnsupported requires both side tuples"
            );
            out.push_str(&format!(
                "Comparison contracts: {} → {} (UNSUPPORTED)\n",
                comparison_contract_label(nc.provenance.from.contract.as_ref()),
                comparison_contract_label(nc.provenance.to.contract.as_ref()),
            ));
        }
        DiffNotComparableReason::ProvenanceUnavailable => {
            out.push_str("Comparison contracts: (PROVENANCE UNAVAILABLE)\n");
            // Render the gaps as the guard produced them: all FROM-side gaps
            // first, then TO-side, each side's fields in tuple-field
            // declaration order. Reordering here would hide guard ordering.
            for gap in &nc.gaps {
                out.push_str(&format!(
                    "Missing: {} {}\n",
                    terminal_safe(gap.side.as_str()),
                    terminal_safe(gap.field.as_str())
                ));
            }
        }
    }
    out.push_str(&format!(
        "Pico versions: {} → {}\n",
        terminal_safe(&nc.provenance.from.pico_version),
        terminal_safe(&nc.provenance.to.pico_version)
    ));
    out.push('\n');
    out.push_str(match nc.reason {
        DiffNotComparableReason::ContractChanged => {
            "Security change comparison was skipped because the persisted comparison contracts differ."
        }
        DiffNotComparableReason::ContractUnsupported => {
            "Security change comparison was skipped because this Pico build does not support the persisted comparison contract."
        }
        DiffNotComparableReason::ProvenanceUnavailable => {
            "Security change comparison was skipped because required historical provenance is unavailable."
        }
    });
    out.push('\n');
    out.push_str("No Finding, graph, lifecycle, or Cause claim was computed for this pair.\n");
    out.push_str("This is not an all-clear.\n");
    out
}

/// Renders `pico history`.
pub fn render_scan_history(history: &ScanHistory) -> String {
    let mut out = String::from("Pico Scan History\n\n");
    if history.scans.is_empty() {
        out.push_str(
            "No scans exist in this workspace.\nRun `pico scan` to create the first scan.\n",
        );
        return out;
    }
    out.push_str(&format!(
        "{:<42} {:<10} {:<10} {}\n",
        "ID", "STATUS", "FINDINGS", "COMPLETED"
    ));
    for scan in &history.scans {
        let completed = scan.completed_at.as_deref().unwrap_or("—");
        out.push_str(&format!(
            "{:<42} {:<10} {:<10} {}\n",
            terminal_safe(&scan.id),
            terminal_safe(&scan.status),
            scan.finding_count,
            terminal_safe(completed)
        ));
    }
    out.push('\n');
    let newest_complete = history.scans.iter().rev().find(|s| s.status == "COMPLETE");
    if let Some(scan) = newest_complete {
        out.push_str(&format!("Newest COMPLETE: {}\n", terminal_safe(&scan.id)));
    } else {
        out.push_str("No COMPLETE scan exists.\n");
    }
    out
}

/// Renders `pico prune` (SPRINT-030.md §5.4).
///
/// Deterministic and terminal-safe: every persisted scan id and status passes
/// through `terminal_safe`; counts are plain integers; plural nouns are always
/// used (no singular/plural shaping). The pruned-scan lines follow the
/// service's deletion order (COMPLETE units oldest-first, then incomplete
/// attempts oldest-first). A below-window no-op is an explicit success with
/// its own retained-state block, and the health line distinguishes the two
/// paths (`Health after prune:` vs `Health:`). A failing post-prune health
/// check still renders the full report (the CLI returns the corresponding
/// database error separately; that path is unreachable through the current
/// service but remains specified). No claim of space reclaimed, no claim that
/// pruning improved security, and no environment-change attribution.
pub fn render_prune_report(report: &PruneReport) -> String {
    let mut out = String::new();
    out.push_str("Pico prune\n\n");
    out.push_str(&format!("Policy: keep {} COMPLETE scans\n", report.keep));
    if report.nothing_pruned {
        out.push_str("Nothing pruned: history is within the window.\n");
        out.push_str(&retained_state_line(&report.retained));
        out.push_str(&health_line("Health", report.post_health_ok));
        return out;
    }
    out.push_str(&format!("Pruned: {} scans\n", report.pruned.len()));
    for unit in &report.pruned {
        out.push_str(&format!(
            "  {} ({}): {}\n",
            terminal_safe(&unit.scan_id),
            terminal_safe(&unit.status),
            unit_counts_line(&unit.counts)
        ));
    }
    out.push_str(&format!("Totals: {}\n", unit_counts_line(&report.totals.0)));
    out.push_str(&retained_state_line(&report.retained));
    out.push_str(&health_line("Health after prune", report.post_health_ok));
    out
}

/// The seven-count deletion summary shared by the per-scan lines and totals.
fn unit_counts_line(counts: &UnitCounts) -> String {
    format!(
        "{} observations, {} evidence, {} findings, {} attack paths, \
         {} analyses, {} diagnostics, {} relationship evidence links",
        counts.observations,
        counts.evidence,
        counts.findings,
        counts.attack_paths,
        counts.scan_analyses,
        counts.scan_diagnostics,
        counts.relationship_evidence,
    )
}

/// The retained-state summary line after a prune.
fn retained_state_line(counts: &RetentionCounts) -> String {
    format!(
        "Retained: {} COMPLETE, {} PARTIAL, {} FAILED, {} RUNNING\n",
        counts.complete, counts.partial, counts.failed, counts.running
    )
}

/// The trailing health line: `ok` or the fail-closed `FAILED` marker.
fn health_line(label: &str, ok: bool) -> String {
    format!("{label}: {}\n", if ok { "ok" } else { "FAILED" })
}

/// Renders `pico doctor` (SPRINT-030.md §5.3/§5.4, corrected by
/// SPRINT-031.md §5.2/§5.3).
///
/// Deterministic and terminal-safe: the only persisted value rendered (the
/// dangling-reference structural `finding_id`, retained scan ids) passes
/// through `terminal_safe`; integers and booleans render as plain words.
/// Dangling diagnostics carry stable reason codes and bounded structural
/// locations only — no field of the report holds raw JSON text or unresolved
/// id contents, so the output can never echo them. The renderer is total:
/// every field of the health report is renderable, including an unsupported
/// schema version, failing integrity/foreign-key checks (frozen as `FAILED`),
/// a capped dangling-location list with a summary remainder line, and a
/// retention window with no COMPLETE scans (`none` placeholders). The window
/// line separates the policy window from the scans actually present. The
/// PRAGMA detail strings (`integrity_check` rows, `foreign_key_check` rows)
/// are deliberately not echoed — the boolean outcome is enough to stay
/// deterministic and secret-free. The report states observed facts only: it
/// never claims repair, cleanup, space reclamation, or any environment
/// change. `Result: ok` vs `Result: FAIL` is the single success marker; the
/// CLI returns the fail-closed error separately so a failing doctor still
/// renders the full report before the process exits FAILURE.
pub fn render_doctor_report(report: &HealthReport) -> String {
    let mut out = String::from("Pico doctor\n\n");
    out.push_str(&format!(
        "Schema version: {} ({})\n",
        report.schema_version,
        if report.schema_ok {
            "supported"
        } else {
            "unsupported"
        }
    ));
    out.push_str(&format!(
        "Integrity: {}\n",
        if report.integrity_ok { "ok" } else { "FAILED" }
    ));
    out.push_str(&format!(
        "Foreign keys: {}\n",
        if report.foreign_keys_ok {
            "ok"
        } else {
            "FAILED"
        }
    ));
    if report.dangling_total == 0 {
        out.push_str("Dangling references: none\n");
    } else {
        out.push_str(&format!("Dangling references: {}\n", report.dangling_total));
        for dangling in &report.dangling_json_refs {
            // Only the structural `finding_id` is a persisted value; table,
            // column, and referenced table are frozen constants, and the
            // count and position are integers — no id contents anywhere.
            let location = format!(
                "at finding_id={} position={}",
                terminal_safe(&dangling.finding_id),
                dangling.position
            );
            match dangling.category.as_str() {
                "unparseable" => out.push_str(&format!(
                    "  {}/{}: unparseable JSON {}\n",
                    dangling.table, dangling.column, location
                )),
                _ => out.push_str(&format!(
                    "  {}/{}: {} unresolved {} id(s) {}\n",
                    dangling.table,
                    dangling.column,
                    dangling.unresolved_count,
                    dangling.referenced_table,
                    location
                )),
            }
        }
        if report.dangling_more > 0 {
            out.push_str(&format!("  ... and {} more\n", report.dangling_more));
        }
    }
    out.push_str(&format!("Orphan scan rows: {}\n", report.orphan_scan_rows));
    out.push_str(&format!("Summary rows: {}\n", report.summary_rows));
    out.push_str(&format!(
        "Scans: {} COMPLETE, {} PARTIAL, {} FAILED, {} RUNNING\n",
        report.counts.complete, report.counts.partial, report.counts.failed, report.counts.running
    ));
    out.push_str(&format!(
        "Retention window: policy keep {} COMPLETE scans; workspace has {} \
         COMPLETE scans; oldest retained {}; newest {}\n",
        report.window_keep,
        report.counts.complete,
        report
            .oldest_retained_complete
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "none".to_string()),
        report
            .newest_complete
            .as_deref()
            .map(terminal_safe)
            .unwrap_or_else(|| "none".to_string()),
    ));
    out.push_str(if report.ok {
        "Result: ok\n"
    } else {
        "Result: FAIL\n"
    });
    out
}

fn render_ready_diff(diff: &FindingDiff) -> String {
    let mut out = String::from("Pico diff\n\n");
    out.push_str(&format!(
        "From: {} ({})\n",
        terminal_safe(&diff.from.id),
        terminal_safe(&diff.from.status)
    ));
    out.push_str(&format!(
        "To:   {} ({})\n",
        terminal_safe(&diff.to.id),
        terminal_safe(&diff.to.status)
    ));
    match diff.compared_via {
        crate::application::ComparedVia::LatestTwo => {
            out.push_str("Compared: LAST TWO COMPLETE SCANS\n");
            out.push_str(match diff.freshness {
                Freshness::LatestComplete => "Freshness: LATEST COMPLETE\n",
                Freshness::NewerIncomplete => "Freshness: NEWER INCOMPLETE ATTEMPT\n",
            });
            if let Some(warning) = &diff.freshness_warning {
                out.push('\n');
                for line in warning.split('\n') {
                    out.push_str(&terminal_safe(line));
                    out.push('\n');
                }
            }
        }
        crate::application::ComparedVia::ExplicitPair => {
            out.push_str("Compared: EXPLICIT PAIR\n");
        }
    }
    // Persisted comparison-contract provenance (SPRINT-029.md §5.5): both
    // tuples are guaranteed Some, equal, and current on a Ready result.
    if let (Some(from_contract), Some(to_contract)) = (
        diff.provenance.from.contract.as_ref(),
        diff.provenance.to.contract.as_ref(),
    ) {
        debug_assert_eq!(from_contract, to_contract);
        out.push_str(&format!(
            "Comparison contracts: {} → {} (SUPPORTED MATCH)\n",
            comparison_contract_label(Some(from_contract)),
            comparison_contract_label(Some(to_contract)),
        ));
        out.push_str(&format!(
            "Pico versions: {} → {}\n",
            terminal_safe(&diff.provenance.from.pico_version),
            terminal_safe(&diff.provenance.to.pico_version)
        ));
    }
    out.push_str("\nFindings\n");
    out.push_str(&format!("  Unchanged: {}\n", diff.unchanged.len()));
    out.push_str(&format!("  Appeared:  {}\n", diff.appeared.len()));
    out.push_str(&format!("  Not observed: {}\n", diff.disappeared.len()));
    out.push_str(&format!("  Weakened: {}\n", diff.weakened.len()));
    out.push_str(&format!("  Strengthened: {}\n", diff.strengthened.len()));
    out.push_str(&format!("  Uncertain: {}\n", diff.uncertain.len()));

    if !diff.appeared.is_empty() {
        out.push_str("\nAppeared\n");
        for finding in &diff.appeared {
            push_diff_finding(&mut out, finding);
        }
    }
    if !diff.disappeared.is_empty() {
        out.push_str("\nNot observed\n");
        for finding in &diff.disappeared {
            push_diff_finding(&mut out, finding);
        }
    }
    if !diff.weakened.is_empty() {
        out.push_str("\nWeakened\n");
        for change in &diff.weakened {
            push_lifecycle_change(&mut out, change);
        }
    }
    if !diff.strengthened.is_empty() {
        out.push_str("\nStrengthened\n");
        for change in &diff.strengthened {
            push_lifecycle_change(&mut out, change);
        }
    }
    if !diff.uncertain.is_empty() {
        out.push_str("\nUncertain\n");
        for change in &diff.uncertain {
            push_lifecycle_change(&mut out, change);
        }
    }

    if diff.appeared.is_empty()
        && diff.disappeared.is_empty()
        && diff.weakened.is_empty()
        && diff.strengthened.is_empty()
        && diff.uncertain.is_empty()
    {
        out.push('\n');
        out.push_str("No security-significant finding change.\n");
        if diff.unchanged.is_empty() {
            out.push_str("This is not an all-clear.\n");
        }
    }
    out.push('\n');
    out.push_str(&render_graph_subject_diff(
        "Resources",
        &diff.graph.resources,
    ));
    out.push('\n');
    out.push_str(&render_graph_subject_diff(
        "Relationships",
        &diff.graph.relationships,
    ));
    if !diff.disappeared.is_empty()
        || !diff.graph.resources.disappeared.is_empty()
        || !diff.graph.relationships.disappeared.is_empty()
    {
        out.push_str("\nNot observed means not observed in the newer scan; remediation is not established.\n");
    }
    if !diff.attribution.graph_changes.is_empty() || !diff.attribution.finding_changes.is_empty() {
        out.push_str("\nObserved-change attribution\n");
        for change in diff
            .attribution
            .graph_changes
            .iter()
            .chain(&diff.attribution.finding_changes)
        {
            let class = match change.classification {
                crate::application::AttributionClass::ObservedEnvironmentChange => {
                    "observed environment change"
                }
                crate::application::AttributionClass::EvidenceChange => "evidence change",
                crate::application::AttributionClass::Mixed => "mixed",
                crate::application::AttributionClass::Unattributed => "unattributed",
            };
            out.push_str(&format!(
                "  {}: {} ({})\n",
                terminal_safe(&change.key),
                class,
                terminal_safe(&change.reasons.join(", "))
            ));
            for (label, side) in [("Before", &change.before), ("After", &change.after)] {
                out.push_str(&format!("    {label}: coverage {:?}; sources [{}]; supported fields [{}]; evidence [{}]\n",
                    side.coverage, terminal_safe(&side.source_types.join(", ")),
                    terminal_safe(&side.supported_fields.join(", ")), terminal_safe(&side.evidence_ids.join(", "))));
            }
        }
    }
    out
}

fn render_graph_subject_diff(title: &str, diff: &GraphSubjectDiff) -> String {
    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push_str(&format!("  Unchanged: {}\n", diff.unchanged.len()));
    out.push_str(&format!("  First seen: {}\n", diff.first_seen.len()));
    out.push_str(&format!("  Reappeared: {}\n", diff.reappeared.len()));
    out.push_str(&format!("  Changed: {}\n", diff.changed.len()));
    out.push_str(&format!("  Not observed: {}\n", diff.disappeared.len()));
    push_graph_bucket(&mut out, "First seen", &diff.first_seen);
    push_graph_bucket(&mut out, "Reappeared", &diff.reappeared);
    push_graph_bucket(&mut out, "Changed", &diff.changed);
    push_graph_bucket(&mut out, "Not observed", &diff.disappeared);
    out
}

fn push_graph_bucket(out: &mut String, title: &str, entries: &[GraphSubject]) {
    if entries.is_empty() {
        return;
    }
    out.push('\n');
    out.push_str(title);
    out.push('\n');
    for entry in entries {
        if let Some(provider) = &entry.provider {
            out.push_str(&format!(
                "  {} · {} · {}\n",
                terminal_safe(&entry.kind),
                terminal_safe(provider),
                terminal_safe(&entry.canonical_key)
            ));
        } else {
            out.push_str(&format!(
                "  {} · {}\n",
                terminal_safe(&entry.kind),
                terminal_safe(&entry.canonical_key)
            ));
        }
        out.push_str(&format!(
            "  First seen: {}\n",
            terminal_safe(&entry.first_seen_scan_id)
        ));
        out.push_str(&format!(
            "  Last seen: {}\n",
            terminal_safe(&entry.last_seen_scan_id)
        ));
        for delta in &entry.deltas {
            out.push_str(&format!(
                "  {}: {} → {}\n",
                terminal_safe(&delta.field),
                terminal_safe(&delta.from),
                terminal_safe(&delta.to)
            ));
        }
    }
}

fn push_diff_finding(out: &mut String, finding: &DiffFinding) {
    out.push_str(&format!(
        "  {} · {} confidence\n",
        terminal_safe(&finding.severity),
        terminal_safe(&finding.confidence)
    ));
    out.push_str("  ");
    out.push_str(&terminal_safe(&finding.title));
    out.push('\n');
    out.push_str(&format!(
        "  Fingerprint: {}\n",
        terminal_safe(&finding.fingerprint)
    ));
    out.push_str(&format!("  ID: {}\n", terminal_safe(&finding.id)));
    if let Some(cause) = &finding.cause {
        out.push_str(&format!("  Cause: {}\n", terminal_safe(&cause.summary)));
    }
}

fn push_lifecycle_change(out: &mut String, change: &FindingLifecycleChange) {
    out.push_str(&format!(
        "  {} · {} confidence\n",
        terminal_safe(&change.to.severity),
        terminal_safe(&change.to.confidence)
    ));
    out.push_str("  ");
    out.push_str(&terminal_safe(&change.to.title));
    out.push('\n');
    out.push_str(&format!(
        "  Fingerprint: {}\n",
        terminal_safe(&change.to.fingerprint)
    ));
    out.push_str(&format!("  ID: {}\n", terminal_safe(&change.to.id)));
    out.push_str(&format!(
        "  From fingerprint: {}\n",
        terminal_safe(&change.from.fingerprint)
    ));
    out.push_str(&format!(
        "  From: {} · {} confidence\n",
        terminal_safe(&change.from.severity),
        terminal_safe(&change.from.confidence)
    ));
    out.push_str(&format!(
        "  Cause: {}\n",
        lifecycle_cause_summary(&change.deltas)
    ));
}

/// Render-time label for a delta field: the machine values "severity" and
/// "confidence" map to their title-cased display forms; any unknown value is
/// still rendered safely (title-cased, then passed through `terminal_safe`).
fn delta_field_label(field: &str) -> String {
    let title = match field {
        "severity" => "Severity".to_string(),
        "confidence" => "Confidence".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        }
    };
    terminal_safe(&title)
}

fn lifecycle_cause_summary(deltas: &[FindingRatingDelta]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for delta in deltas {
        if delta.field == "severity"
            && delta.from_value != delta.to_value
            && !parts.iter().any(|part| part.starts_with("Severity "))
        {
            parts.push(format!(
                "Severity {} → {}",
                terminal_safe(&delta.from_value),
                terminal_safe(&delta.to_value)
            ));
        }
    }
    for delta in deltas {
        if delta.field == "confidence"
            && delta.from_value != delta.to_value
            && !parts.iter().any(|part| part.starts_with("Confidence "))
        {
            parts.push(format!(
                "Confidence {} → {}",
                terminal_safe(&delta.from_value),
                terminal_safe(&delta.to_value)
            ));
        }
    }
    for delta in deltas {
        if delta.field != "severity"
            && delta.field != "confidence"
            && delta.from_value != delta.to_value
        {
            parts.push(format!(
                "{} {} → {}",
                delta_field_label(&delta.field),
                terminal_safe(&delta.from_value),
                terminal_safe(&delta.to_value)
            ));
        }
    }
    if parts.is_empty() {
        "Ratings unchanged; fingerprint changed".to_string()
    } else {
        parts.join("; ")
    }
}

/// Renders the scan-summary Effective Bash block (S023 / F-U1).
///
/// When more than one agent is detected, list every observed agent's
/// `effective_state` so a mixed workspace never collapses to the primary
/// permission line. When exactly one agent is detected, keep the legacy
/// single-agent `Effective Bash: ALLOW` contract byte-for-byte (permission
/// string, not effective_state).
pub fn render_scan_effective_bash(result: &ScanResult) -> String {
    if result.agent_count > 1 && !result.agent_bash_postures.is_empty() {
        let mut out = String::from("Effective Bash:\n");
        for posture in &result.agent_bash_postures {
            out.push_str(&format!(
                "  {}: {}\n",
                terminal_safe(&posture.provider),
                terminal_safe(&posture.effective_state),
            ));
        }
        out
    } else if let Some(permission) = &result.bash_permission {
        format!("Effective Bash: {permission}\n")
    } else {
        String::new()
    }
}

/// Renders the per-GitHub-credential authority block for the `pico scan`
/// summary (SPRINT-021 R6).
///
/// Each observed GitHub credential produces one line carrying only safe
/// classification facts — the credential type, the authority resolution tier,
/// the permission state, and the reasons a write claim could not be
/// established. When no GitHub credential was observed this returns an empty
/// string so the golden path is given no noise.
pub fn render_github_credential_authority(
    credentials: &[crate::application::GitHubCredentialView],
) -> String {
    if credentials.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("GitHub credential authority:\n");
    for credential in credentials {
        let mut line = format!(
            "  GitHub {} authority: resolution={} permission={}",
            terminal_safe(&credential.credential_type),
            terminal_safe(&credential.authority_resolution),
            terminal_safe(&credential.permission_state),
        );
        if !credential.unknown_reasons.is_empty() {
            line.push_str(" reasons=[");
            line.push_str(
                &credential
                    .unknown_reasons
                    .iter()
                    .map(|reason| terminal_safe(reason))
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            line.push(']');
        }
        line.push('\n');
        out.push_str(&line);
    }
    out
}

/// Renders a connected source-to-Sink chain from traversal-applied steps.
fn path_chain(path: &crate::application::ExplainedPath) -> String {
    if path.steps.is_empty() {
        return terminal_safe(&path.source_resource_id);
    }
    let mut chain: Vec<String> = Vec::with_capacity(path.steps.len() + 1);
    let first = &path.steps[0];
    chain.push(display_name(&first.from_resource));
    for step in &path.steps {
        chain.push(display_name(&step.to_resource));
    }
    chain
        .iter()
        .map(|name| terminal_safe(name))
        .collect::<Vec<_>>()
        .join(" → ")
}

/// Prefers the persisted resource name, falling back to its canonical key.
fn display_name(resource: &crate::application::ResourceView) -> String {
    if resource.name.is_empty() {
        resource.canonical_key.clone()
    } else {
        resource.name.clone()
    }
}
