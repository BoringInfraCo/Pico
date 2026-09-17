//! `pico runtime` application service (SPRINT-039 §2).
//!
//! Answers "what runtime evidence exists on this machine about my agents, and
//! what can Pico safely read?" by resolving each supported agent's known
//! runtime artifact surfaces and reporting **filesystem metadata only**:
//! existence, kind (file/dir), byte size, readability, and `-wal`/`-shm`
//! sidecar presence.
//!
//! Honesty contract (SPRINT-039 §2.1–§2.2):
//!
//! - Detection is `DECLARED` evidence about *observability capability*, never
//!   evidence of agent activity, execution, or approval.
//! - `ApprovedUse` is always `NotAvailable`: OpenCode records allow/deny only
//!   as live plugin events and Claude Code only through live hooks or OTel
//!   export, so there is no dependable local decision record. Live
//!   interception would require a daemon or hook installation, both outside
//!   Pico V0's non-goals.
//! - No level is inferred from another: every distinction is computed from its
//!   own disjoint set of surfaces.
//!
//! Read-only by construction: this module uses `std::fs::symlink_metadata`
//! only. It never opens or queries a database, never reads file contents,
//! never reads credential/account stores, and never creates or modifies a file
//! (including SQLite `-wal`/`-shm` sidecars). Testing a surface therefore
//! cannot mutate it.
//!
//! S043 extends the survey to Claude Code transcript surfaces without parsing
//! them: the `~/.claude/projects/` directory is listed to count `*.jsonl`
//! entries (names only — no entry is opened, no per-file metadata is read),
//! present-but-empty is reported distinctly from absent, and the Claude CLI
//! version is declared from the `~/.local/share/claude/versions/<v>` install
//! layout (directory listing only; the binary is never read). The per-line
//! transcript format is internal and version-varying, so parsing is explicitly
//! deferred and that reason is a [`RuntimeReport::notes`] entry.
//!
//! Surface whitelist (conservative; recorded in [`RuntimeReport::notes`]):
//!
//! - OpenCode: `~/.local/share/opencode/opencode.db` and its `-wal`/`-shm`
//!   sidecars, `storage/`, `snapshot/`, `tool-output/`.
//! - Claude Code: `~/.claude/projects/`, `~/.claude/sessions/`, and the
//!   `~/.local/share/claude/versions/` install-layout directory (listed, never
//!   opened, only to declare the installed CLI version).
//!
//! Excluded by policy (not listed as surfaces): `prompt-history.jsonl` (prompt
//! content), `log/` directories (may contain content), credential/account
//! stores (`auth.json`, `account.json`, `mcp-auth.json`), and `.claude.json`
//! (mixed history/config). These are named in the report notes so the refusal
//! is explicit rather than implied.

use std::path::{Path, PathBuf};

use crate::shared::PicoError;

/// What Pico can honestly observe about a security distinction (SPRINT-039
/// §2.2). `Unknown` preserves honest uncertainty; it is never upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityLevel {
    /// Existing v0.1–v0.4 discovery already resolves this capability.
    Observable,
    /// A backing surface is present but its contents are not read this slice.
    AvailableUnread,
    /// No dependable local record exists (or the surface is absent).
    NotAvailable,
    /// The surface could not be resolved (missing home, unreadable, unknown).
    Unknown,
}

impl ObservabilityLevel {
    /// Stable machine-readable code for interfaces that render the report.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObservabilityLevel::Observable => "OBSERVABLE",
            ObservabilityLevel::AvailableUnread => "AVAILABLE_UNREAD",
            ObservabilityLevel::NotAvailable => "NOT_AVAILABLE",
            ObservabilityLevel::Unknown => "UNKNOWN",
        }
    }
}

/// The security distinctions S039 reports on (SPRINT-039 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distinction {
    /// What the agent was configured to be able to do.
    ConfiguredCapability,
    /// That the agent attempted to use a capability.
    AttemptedUse,
    /// Whether a use was approved or denied.
    ApprovedUse,
    /// That a consequential action completed.
    CompletedAction,
}

impl Distinction {
    /// Stable machine-readable code for interfaces that render the report.
    pub fn as_str(&self) -> &'static str {
        match self {
            Distinction::ConfiguredCapability => "configured_capability",
            Distinction::AttemptedUse => "attempted_use",
            Distinction::ApprovedUse => "approved_use",
            Distinction::CompletedAction => "completed_action",
        }
    }
}

/// Metadata-only description of one resolved runtime surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceReport {
    pub agent: String,
    pub label: String,
    /// `~/`-relative (or workspace-relative) display form; never absolute HOME.
    pub path: String,
    pub present: bool,
    /// Byte size of a present regular file; `None` when absent or a directory.
    pub bytes: Option<u64>,
    /// For directory surfaces that support it (currently only the Claude
    /// transcript directory), the number of `*.jsonl` child entries found by a
    /// directory read. `None` when the surface is not countable, is absent, or
    /// could not be listed. `Some(0)` with `present == true` is the honest
    /// present-but-empty state. Only directory entry names are used: no entry
    /// is opened and no per-file metadata is read.
    pub jsonl_count: Option<u64>,
    pub level: ObservabilityLevel,
}

/// Read-only observability survey. Deterministic: surfaces are sorted by agent
/// then label and no timestamps are included (a point-in-time capability read,
/// not an event log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReport {
    pub surfaces: Vec<SurfaceReport>,
    pub distinctions: Vec<(Distinction, ObservabilityLevel)>,
    /// Human-readable honesty notes. Dynamic entries report resolved facts
    /// (transcript count, declared CLI version) and static entries state the
    /// survey's limits and the deferred-parsing reason.
    pub notes: Vec<String>,
}

/// Human-output honesty line (SPRINT-039 §2.3). Exposed so both interfaces
/// describe the same limitation.
pub const HONESTY_LINE: &str = "This reports what is observable, not what the agent did.";

const NOTE_METADATA_ONLY: &str = "filesystem metadata only (existence, kind, byte size, readability, -wal/-shm presence); no content database is opened, no file contents are read, and no file is created or modified";
const NOTE_WHITELIST: &str = "surface whitelist: OpenCode ~/.local/share/opencode (opencode.db + -wal/-shm, storage/, snapshot/, tool-output/) and Claude Code ~/.claude (projects/, sessions/) plus the ~/.local/share/claude/versions/ install-layout directory (listed, never opened, only to declare the installed CLI version)";
const NOTE_EXCLUDED: &str = "excluded by policy: prompt-history.jsonl, log/ directories, credential/account stores (auth.json, account.json, mcp-auth.json), and .claude.json";
const NOTE_APPROVED_USE: &str = "approved vs denied use is NOT_AVAILABLE: upstream records allow/deny only through live hooks or OTel export, never in dependable local state";
const NOTE_DECLARED: &str = "surfaces are DECLARED evidence about observability capability, never evidence of agent activity, execution, or approval";
const NOTE_DEFERRED_PARSING: &str = "Claude Code transcript parsing is deferred: the per-line format is internal and version-varying, so Pico reports presence and a *.jsonl count only and does not parse transcripts yet";

const AGENT_OPENCODE: &str = "OpenCode";
const AGENT_CLAUDE: &str = "Claude Code";

const OPENCODE_BASE: &[&str] = &[".local", "share", "opencode"];
const CLAUDE_BASE: &[&str] = &[".claude"];
const CLAUDE_VERSIONS_BASE: &[&str] = &[".local", "share", "claude", "versions"];
const JSONL_EXTENSION: &str = ".jsonl";

const LABEL_OPENCODE_SESSION_STORE: &str = "session store";
const LABEL_OPENCODE_SESSION_STORE_WAL: &str = "session store wal sidecar";
const LABEL_OPENCODE_SESSION_STORE_SHM: &str = "session store shm sidecar";
const LABEL_OPENCODE_STORAGE: &str = "storage directory";
const LABEL_OPENCODE_SNAPSHOT: &str = "snapshot directory";
const LABEL_OPENCODE_TOOL_OUTPUT: &str = "tool output directory";
const LABEL_CLAUDE_PROJECTS: &str = "session transcripts directory";
const LABEL_CLAUDE_SESSIONS: &str = "sessions directory";

/// Static surface descriptor. All whitelisted surfaces live under the user's
/// home; the workspace argument is only used to render a workspace-relative
/// display form for any future workspace-relative surface (SPRINT-039 §2.3).
struct SurfaceSpec {
    agent: &'static str,
    label: &'static str,
    base: &'static [&'static str],
    name: &'static str,
    /// When true, a present directory surface additionally reports a count of
    /// `*.jsonl` child entries (names only; no entry is opened).
    counts_jsonl_files: bool,
}

const SURFACES: &[SurfaceSpec] = &[
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE,
        base: OPENCODE_BASE,
        name: "opencode.db",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE_SHM,
        base: OPENCODE_BASE,
        name: "opencode.db-shm",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE_WAL,
        base: OPENCODE_BASE,
        name: "opencode.db-wal",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_STORAGE,
        base: OPENCODE_BASE,
        name: "storage",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SNAPSHOT,
        base: OPENCODE_BASE,
        name: "snapshot",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_TOOL_OUTPUT,
        base: OPENCODE_BASE,
        name: "tool-output",
        counts_jsonl_files: false,
    },
    SurfaceSpec {
        agent: AGENT_CLAUDE,
        label: LABEL_CLAUDE_PROJECTS,
        base: CLAUDE_BASE,
        name: "projects",
        counts_jsonl_files: true,
    },
    SurfaceSpec {
        agent: AGENT_CLAUDE,
        label: LABEL_CLAUDE_SESSIONS,
        base: CLAUDE_BASE,
        name: "sessions",
        counts_jsonl_files: false,
    },
];

/// Distinct, disjoint backing sets. Keeping them disjoint is what makes it
/// impossible to infer one distinction's level from another.
const ATTEMPTED_USE_LABELS: &[&str] = &[
    LABEL_OPENCODE_SESSION_STORE,
    LABEL_OPENCODE_STORAGE,
    LABEL_CLAUDE_PROJECTS,
];
const COMPLETED_ACTION_LABELS: &[&str] = &[
    LABEL_OPENCODE_TOOL_OUTPUT,
    LABEL_OPENCODE_SNAPSHOT,
    LABEL_CLAUDE_SESSIONS,
];

/// Probe one resolved surface using metadata only.
struct Probe {
    present: bool,
    bytes: Option<u64>,
    jsonl_count: Option<u64>,
    level: ObservabilityLevel,
}

/// Survey each supported agent's runtime surfaces and the per-distinction
/// observability matrix. Read-only; returns an empty error surface because
/// metadata failures are represented honestly as `Unknown`, not errors.
pub fn survey(workspace: &Path, home: Option<&Path>) -> Result<RuntimeReport, PicoError> {
    let mut surfaces = Vec::with_capacity(SURFACES.len());
    for spec in SURFACES {
        let resolved = resolve(home, spec.base, spec.name);
        let mut probe = probe(resolved.as_deref());
        if spec.counts_jsonl_files && probe.present {
            probe.jsonl_count = count_jsonl_files(resolved.as_deref());
        }
        let path = display_path(resolved.as_deref(), workspace, home, spec.base, spec.name);
        surfaces.push(SurfaceReport {
            agent: spec.agent.to_string(),
            label: spec.label.to_string(),
            path,
            present: probe.present,
            bytes: probe.bytes,
            jsonl_count: probe.jsonl_count,
            level: probe.level,
        });
    }
    // Deterministic ordering: agent, then label.
    surfaces.sort_by(|a, b| a.agent.cmp(&b.agent).then_with(|| a.label.cmp(&b.label)));

    let distinctions = vec![
        // (a) Configured capability is already evidenced by v0.1–v0.4 config
        // discovery; this slice adds no new claim.
        (
            Distinction::ConfiguredCapability,
            ObservabilityLevel::Observable,
        ),
        (
            Distinction::AttemptedUse,
            aggregate_level(ATTEMPTED_USE_LABELS, &surfaces),
        ),
        // (c) ALWAYS NotAvailable: there is no dependable local allow/deny
        // record. OpenCode keeps `permission` events only as live plugin
        // events (its permission table is empty) and Claude Code records
        // decisions only through live hooks or OTel export. Reading either
        // would require a daemon or hook installation, both outside V0.
        (Distinction::ApprovedUse, ObservabilityLevel::NotAvailable),
        (
            Distinction::CompletedAction,
            aggregate_level(COMPLETED_ACTION_LABELS, &surfaces),
        ),
    ];

    let version = detect_claude_version(home);
    let notes = vec![
        NOTE_METADATA_ONLY.to_string(),
        NOTE_WHITELIST.to_string(),
        NOTE_EXCLUDED.to_string(),
        NOTE_APPROVED_USE.to_string(),
        NOTE_DECLARED.to_string(),
        claude_transcript_note(&surfaces),
        claude_version_note(version.as_deref()),
        NOTE_DEFERRED_PARSING.to_string(),
    ];

    Ok(RuntimeReport {
        surfaces,
        distinctions,
        notes,
    })
}

/// Resolve a whitelisted surface under the user's home. `None` when no home is
/// supplied: the surface is then unresolved and reported `Unknown`, never
/// defaulted to the real `$HOME`.
fn resolve(home: Option<&Path>, base: &[&str], name: &str) -> Option<PathBuf> {
    let home = home?;
    let mut path = home.to_path_buf();
    for component in base {
        path.push(component);
    }
    path.push(name);
    Some(path)
}

/// Deterministic `~/`-relative (or workspace-relative) display form. Never an
/// absolute HOME path, even when the surface cannot be resolved.
fn display_path(
    resolved: Option<&Path>,
    workspace: &Path,
    home: Option<&Path>,
    base: &[&str],
    name: &str,
) -> String {
    if let Some(path) = resolved {
        if let Ok(relative) = path.strip_prefix(workspace) {
            return relative.to_string_lossy().into_owned();
        }
        if let Some(home) = home {
            if let Ok(relative) = path.strip_prefix(home) {
                return format!("~/{}", relative.to_string_lossy());
            }
        }
    }
    let mut components: Vec<&str> = base.to_vec();
    components.push(name);
    format!("~/{}", components.join("/"))
}

/// Derive presence, byte size, and observability level for one surface.
///
/// `symlink_metadata` is used deliberately: it never follows a symlink out of
/// the expected location and never opens the entry. A missing entry is
/// `NotAvailable`; an entry that exists but is unreadable, or metadata that
/// cannot be read, is honestly `Unknown`. A present readable surface is
/// `AvailableUnread` (contents are deferred to S040).
fn probe(path: Option<&Path>) -> Probe {
    let Some(path) = path else {
        return Probe {
            present: false,
            bytes: None,
            jsonl_count: None,
            level: ObservabilityLevel::Unknown,
        };
    };
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let bytes = if metadata.file_type().is_file() {
                Some(metadata.len())
            } else {
                None
            };
            let level = if is_readable(&metadata) {
                ObservabilityLevel::AvailableUnread
            } else {
                ObservabilityLevel::Unknown
            };
            Probe {
                present: true,
                bytes,
                jsonl_count: None,
                level,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Probe {
            present: false,
            bytes: None,
            jsonl_count: None,
            level: ObservabilityLevel::NotAvailable,
        },
        Err(_) => Probe {
            present: false,
            bytes: None,
            jsonl_count: None,
            level: ObservabilityLevel::Unknown,
        },
    }
}

/// Count `*.jsonl` transcript files under `path` using directory reads only.
///
/// The documented Claude layout is `projects/<project>/<session-id>.jsonl`, so
/// the count descends one bounded level into project directories; counting only
/// direct children would always report `0` on a real install. Only each entry's
/// file name and kind are inspected: no entry is opened, no per-file metadata is
/// read, and no content is captured. The walk is bounded so a pathological tree
/// cannot turn a metadata probe into a scan. Returns `None` when the directory
/// cannot be listed (absent, unreadable, or not a directory) so the caller can
/// report an honest `Unknown` count.
fn count_jsonl_files(path: Option<&Path>) -> Option<u64> {
    const MAX_ENTRIES: u64 = 10_000;
    const MAX_DEPTH: usize = 2;

    fn walk(dir: &Path, depth: usize, seen: &mut u64, count: &mut u64) {
        if depth > MAX_DEPTH || *seen >= MAX_ENTRIES {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if *seen >= MAX_ENTRIES {
                return;
            }
            *seen += 1;
            let Some(name) = entry.file_name().into_string().ok() else {
                continue;
            };
            if name.ends_with(JSONL_EXTENSION) {
                *count += 1;
            } else if depth < MAX_DEPTH && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(&entry.path(), depth + 1, seen, count);
            }
        }
    }

    let path = path?;
    if std::fs::read_dir(path).is_err() {
        return None;
    }
    let mut count = 0u64;
    let mut seen = 0u64;
    walk(path, 0, &mut seen, &mut count);
    Some(count)
}

/// Declare the installed Claude CLI version from the install layout
/// `~/.local/share/claude/versions/<v>` by listing that directory and reading
/// entry names only. Exactly one non-hidden entry is an unambiguous declaration;
/// zero or several entries are honestly `Unknown` (the active version is not
/// declared by the layout). The version entry is never opened.
fn detect_claude_version(home: Option<&Path>) -> Option<String> {
    let home = home?;
    let mut versions = home.to_path_buf();
    for component in CLAUDE_VERSIONS_BASE {
        versions.push(component);
    }
    let entries = std::fs::read_dir(versions).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| !name.starts_with('.'))
        .collect();
    names.sort();
    names.dedup();
    if names.len() == 1 {
        names.into_iter().next()
    } else {
        None
    }
}

/// Explain the Claude transcript surface's presence and `*.jsonl` count (or
/// its absence) so present-but-empty is never confused with absent. The
/// deferred-parsing reason is a separate static note.
fn claude_transcript_note(surfaces: &[SurfaceReport]) -> String {
    let surface = surfaces
        .iter()
        .find(|surface| surface.agent == AGENT_CLAUDE && surface.label == LABEL_CLAUDE_PROJECTS);
    let Some(surface) = surface else {
        return "Claude transcripts: transcript surface could not be resolved".to_string();
    };
    if surface.present {
        match surface.jsonl_count {
            Some(0) => format!(
                "Claude transcripts: {} is present but EMPTY (0 *.jsonl files) — reported distinctly from absent; no transcript file was opened",
                surface.path
            ),
            Some(count) => format!(
                "Claude transcripts: {} contains {count} *.jsonl file(s); only directory entry names were counted and no transcript file was opened",
                surface.path
            ),
            None => format!(
                "Claude transcripts: {} is present but could not be listed, so the *.jsonl count is Unknown; no transcript file was opened",
                surface.path
            ),
        }
    } else if surface.level == ObservabilityLevel::Unknown {
        format!(
            "Claude transcripts: {} could not be resolved (no HOME or unreadable), so transcript presence is Unknown",
            surface.path
        )
    } else {
        format!(
            "Claude transcripts: {} is absent; no transcript directory exists on this machine",
            surface.path
        )
    }
}

/// Explain the declared Claude CLI version fact without ever reading the binary.
fn claude_version_note(version: Option<&str>) -> String {
    match version {
        Some(version) => format!(
            "Claude CLI version {version}: DECLARED from the install layout ~/.local/share/claude/versions/<v> (directory listing only; the binary was never read)"
        ),
        None => "Claude CLI version: Unknown (no unambiguous entry under ~/.local/share/claude/versions/<v>; the binary was never read)".to_string(),
    }
}

/// Readability from permission metadata only (no open). On Unix a surface is
/// readable when any read bit is set; directories without a read bit cannot be
/// listed, so they count as unreadable. Non-Unix platforms report readable
/// because permission bits are unavailable and contents are never read.
#[cfg(unix)]
fn is_readable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o444 != 0
}

#[cfg(not(unix))]
fn is_readable(_metadata: &std::fs::Metadata) -> bool {
    true
}

/// Collapse the levels of a distinction's own backing surfaces:
/// `AvailableUnread` if any backing surface is present and readable, else
/// `Unknown` if any is unresolved/unreadable, else `NotAvailable`.
fn aggregate_level(labels: &[&str], surfaces: &[SurfaceReport]) -> ObservabilityLevel {
    let mut unknown = false;
    for surface in surfaces {
        if !labels.contains(&surface.label.as_str()) {
            continue;
        }
        match surface.level {
            ObservabilityLevel::AvailableUnread => return ObservabilityLevel::AvailableUnread,
            ObservabilityLevel::Unknown => unknown = true,
            // Runtime surfaces are never Observable, and an absent surface
            // never upgrades the aggregate.
            ObservabilityLevel::Observable | ObservabilityLevel::NotAvailable => {}
        }
    }
    if unknown {
        ObservabilityLevel::Unknown
    } else {
        ObservabilityLevel::NotAvailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "PICO_RUNTIME_SWEEP_SENTINEL_9c4f21";

    fn write_file(home: &Path, parts: &[&str], contents: &[u8]) {
        let mut path = home.to_path_buf();
        for part in parts {
            path.push(part);
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn make_dir(home: &Path, parts: &[&str]) {
        let mut path = home.to_path_buf();
        for part in parts {
            path.push(part);
        }
        std::fs::create_dir_all(path).unwrap();
    }

    fn level_of(report: &RuntimeReport, distinction: Distinction) -> ObservabilityLevel {
        report
            .distinctions
            .iter()
            .find(|(candidate, _)| *candidate == distinction)
            .map(|(_, level)| *level)
            .expect("every distinction is reported")
    }

    fn surface<'a>(report: &'a RuntimeReport, agent: &str, label: &str) -> &'a SurfaceReport {
        report
            .surfaces
            .iter()
            .find(|surface| surface.agent == agent && surface.label == label)
            .expect("surface is listed")
    }

    fn assert_no_sentinel(report: &RuntimeReport) {
        let debug = format!("{report:?}");
        assert!(
            !debug.contains(SENTINEL),
            "report must never carry surface content"
        );
    }

    #[test]
    fn distinctions_are_computed_in_isolation_without_inference() {
        let workspace = tempfile::tempdir().unwrap();

        // Only an AttemptedUse surface exists: CompletedAction must NOT follow.
        let attempted = tempfile::tempdir().unwrap();
        write_file(
            attempted.path(),
            &[".local", "share", "opencode", "opencode.db"],
            b"session",
        );
        let report = survey(workspace.path(), Some(attempted.path())).unwrap();
        assert_eq!(
            level_of(&report, Distinction::ConfiguredCapability),
            ObservabilityLevel::Observable
        );
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::AvailableUnread
        );
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::NotAvailable
        );

        // Only a CompletedAction surface exists: AttemptedUse must NOT follow.
        let completed = tempfile::tempdir().unwrap();
        make_dir(
            completed.path(),
            &[".local", "share", "opencode", "tool-output"],
        );
        let report = survey(workspace.path(), Some(completed.path())).unwrap();
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::AvailableUnread
        );

        // ApprovedUse never moves, even when other distinctions do.
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
    }

    #[test]
    fn approved_use_is_always_not_available() {
        let workspace = tempfile::tempdir().unwrap();
        // A fully populated home still cannot make approval/denial observable.
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".local", "share", "opencode", "opencode.db"],
            b"db",
        );
        make_dir(home.path(), &[".local", "share", "opencode", "tool-output"]);
        make_dir(home.path(), &[".claude", "projects"]);
        make_dir(home.path(), &[".claude", "sessions"]);
        let report = survey(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
    }

    #[test]
    fn missing_home_reports_unknown_honestly_and_never_fabricates() {
        let workspace = tempfile::tempdir().unwrap();
        let report = survey(workspace.path(), None).unwrap();

        for surface in &report.surfaces {
            assert!(!surface.present, "no HOME means nothing can be confirmed");
            assert_eq!(surface.bytes, None);
            assert_eq!(surface.level, ObservabilityLevel::Unknown);
            assert!(
                surface.path.starts_with("~/"),
                "paths stay in display form, never absolute: {}",
                surface.path
            );
        }
        assert_eq!(
            level_of(&report, Distinction::ConfiguredCapability),
            ObservabilityLevel::Observable
        );
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::Unknown
        );
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::Unknown
        );
    }

    #[test]
    fn present_absent_and_unreadable_surfaces_are_classified_honestly() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        // Present readable file: bytes known, AVAILABLE_UNREAD.
        write_file(
            home.path(),
            &[".local", "share", "opencode", "opencode.db"],
            b"0123456789",
        );
        // Present directory: bytes must stay None.
        make_dir(home.path(), &[".local", "share", "opencode", "storage"]);
        // claude sessions is deliberately absent.

        let report = survey(workspace.path(), Some(home.path())).unwrap();

        let store = surface(&report, AGENT_OPENCODE, LABEL_OPENCODE_SESSION_STORE);
        assert!(store.present);
        assert_eq!(store.bytes, Some(10));
        assert_eq!(store.level, ObservabilityLevel::AvailableUnread);
        assert_eq!(store.path, "~/.local/share/opencode/opencode.db");

        let storage = surface(&report, AGENT_OPENCODE, LABEL_OPENCODE_STORAGE);
        assert!(storage.present);
        assert_eq!(storage.bytes, None, "directory sizes are never summed");
        assert_eq!(storage.level, ObservabilityLevel::AvailableUnread);

        let absent = surface(&report, AGENT_CLAUDE, LABEL_CLAUDE_SESSIONS);
        assert!(!absent.present);
        assert_eq!(absent.bytes, None);
        assert_eq!(absent.level, ObservabilityLevel::NotAvailable);
        assert_eq!(absent.path, "~/.claude/sessions");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Unreadable file: present, size known, UNKNOWN.
            write_file(
                home.path(),
                &[".local", "share", "opencode", "opencode.db-wal"],
                b"wal!",
            );
            let wal_path = home.path().join(".local/share/opencode/opencode.db-wal");
            std::fs::set_permissions(&wal_path, std::fs::Permissions::from_mode(0o000)).unwrap();

            // Unreadable directory: present, no size, UNKNOWN.
            make_dir(home.path(), &[".local", "share", "opencode", "snapshot"]);
            let snapshot_path = home.path().join(".local/share/opencode/snapshot");
            std::fs::set_permissions(&snapshot_path, std::fs::Permissions::from_mode(0o000))
                .unwrap();

            let report = survey(workspace.path(), Some(home.path())).unwrap();

            let wal = surface(&report, AGENT_OPENCODE, LABEL_OPENCODE_SESSION_STORE_WAL);
            assert!(
                wal.present,
                "an existing but unreadable file is still present"
            );
            assert_eq!(wal.bytes, Some(4));
            assert_eq!(wal.level, ObservabilityLevel::Unknown);

            let snapshot = surface(&report, AGENT_OPENCODE, LABEL_OPENCODE_SNAPSHOT);
            assert!(snapshot.present);
            assert_eq!(snapshot.bytes, None);
            assert_eq!(snapshot.level, ObservabilityLevel::Unknown);

            // Restore permissions so the temp dir can be cleaned up.
            std::fs::set_permissions(&wal_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&snapshot_path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
    }

    #[test]
    fn surfaces_are_ordered_deterministically_and_repeatable() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".local", "share", "opencode", "opencode.db"],
            b"db",
        );
        make_dir(home.path(), &[".local", "share", "opencode", "tool-output"]);
        make_dir(home.path(), &[".claude", "projects"]);
        make_dir(home.path(), &[".claude", "sessions"]);

        let first = survey(workspace.path(), Some(home.path())).unwrap();
        let second = survey(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(first, second, "repeated surveys must be byte-equal");

        assert!(
            first
                .surfaces
                .windows(2)
                .all(|pair| (&pair[0].agent, &pair[0].label) <= (&pair[1].agent, &pair[1].label)),
            "surfaces must be sorted by agent then label"
        );
        assert_eq!(
            first.surfaces.first().map(|s| s.agent.as_str()),
            Some(AGENT_CLAUDE)
        );
    }

    #[test]
    fn survey_touches_metadata_only_and_never_reads_content() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".local", "share", "opencode", "opencode.db"],
            SENTINEL.as_bytes(),
        );
        write_file(
            home.path(),
            &[".local", "share", "opencode", "prompt-history.jsonl"],
            SENTINEL.as_bytes(),
        );
        write_file(
            home.path(),
            &[".local", "share", "opencode", "auth.json"],
            SENTINEL.as_bytes(),
        );

        let before = listing(home.path());
        let report = survey(workspace.path(), Some(home.path())).unwrap();
        let after = listing(home.path());

        assert_eq!(before, after, "survey must not create or modify any entry");
        assert!(
            !home
                .path()
                .join(".local/share/opencode/opencode.db-wal")
                .exists(),
            "survey must never create a SQLite -wal sidecar"
        );
        assert!(
            !home
                .path()
                .join(".local/share/opencode/opencode.db-shm")
                .exists(),
            "survey must never create a SQLite -shm sidecar"
        );
        assert_no_sentinel(&report);
    }

    #[test]
    fn forbidden_surfaces_are_excluded_by_policy() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".local", "share", "opencode", "prompt-history.jsonl"],
            b"prompt",
        );
        make_dir(home.path(), &[".local", "share", "opencode", "log"]);
        write_file(
            home.path(),
            &[".local", "share", "opencode", "auth.json"],
            b"secret",
        );
        write_file(home.path(), &[".claude", "account.json"], b"secret");
        write_file(home.path(), &[".claude", "mcp-auth.json"], b"secret");
        write_file(home.path(), &[".claude.json"], b"secret");

        let report = survey(workspace.path(), Some(home.path())).unwrap();

        // Only forbidden surfaces exist, so neither use distinction is present.
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::NotAvailable
        );

        for surface in &report.surfaces {
            for forbidden in [
                "prompt-history",
                "auth.json",
                "account.json",
                "mcp-auth",
                ".claude.json",
                "/log",
            ] {
                assert!(
                    !surface.path.contains(forbidden),
                    "forbidden surface leaked: {}",
                    surface.path
                );
            }
        }

        let notes = report.notes.join(" ");
        assert!(notes.contains("prompt-history.jsonl"));
        assert!(notes.contains("auth.json"));
        assert!(notes.contains("NOT_AVAILABLE"));
    }

    /// Recursive metadata listing used to prove the survey made no changes.
    /// Reads directory entries only (test-side); the survey itself never does.
    fn listing(root: &Path) -> Vec<(String, bool, u64)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, bool, u64)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((relative, metadata.is_dir(), metadata.len()));
                if metadata.is_dir() {
                    walk(root, &entry.path(), out);
                }
            }
        }
        let mut entries = Vec::new();
        walk(root, root, &mut entries);
        entries.sort();
        entries
    }

    fn claude_projects(report: &RuntimeReport) -> &SurfaceReport {
        surface(report, AGENT_CLAUDE, LABEL_CLAUDE_PROJECTS)
    }

    fn notes_text(report: &RuntimeReport) -> String {
        report.notes.join("\n")
    }

    /// Recursive byte digest used to prove a survey changed nothing. Reads
    /// bytes on the test side only; the survey itself never reads any file.
    fn digest(root: &Path) -> Vec<(String, Vec<u8>)> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                if metadata.is_dir() {
                    out.push((relative, b"dir".to_vec()));
                    walk(root, &entry.path(), out);
                } else {
                    out.push((relative, std::fs::read(entry.path()).unwrap_or_default()));
                }
            }
        }
        let mut entries = Vec::new();
        walk(root, root, &mut entries);
        entries.sort();
        entries
    }

    #[test]
    fn claude_transcript_count_counts_jsonl_entries_only() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        // The documented Claude layout is `projects/<project>/<session>.jsonl`,
        // so transcripts live one level below the projects directory.
        write_file(
            home.path(),
            &[".claude", "projects", "proj-a", "sess-1.jsonl"],
            b"a",
        );
        write_file(
            home.path(),
            &[".claude", "projects", "proj-a", "sess-2.jsonl"],
            b"b",
        );
        write_file(
            home.path(),
            &[".claude", "projects", "proj-b", "sess-3.jsonl"],
            b"c",
        );
        // Non-transcript files are never counted.
        write_file(
            home.path(),
            &[".claude", "projects", "proj-a", "notes.txt"],
            b"d",
        );
        write_file(home.path(), &[".claude", "projects", "config.json"], b"e");

        let report = survey(workspace.path(), Some(home.path())).unwrap();
        let projects = claude_projects(&report);
        assert!(projects.present);
        assert_eq!(projects.jsonl_count, Some(3));
        assert_eq!(projects.level, ObservabilityLevel::AvailableUnread);
        assert!(
            notes_text(&report).contains("contains 3 *.jsonl"),
            "the count must be reported: {}",
            notes_text(&report)
        );
    }

    #[test]
    fn claude_present_but_empty_is_distinct_from_absent() {
        let workspace = tempfile::tempdir().unwrap();

        // Present but empty: a directory exists with zero *.jsonl entries.
        let empty = tempfile::tempdir().unwrap();
        make_dir(empty.path(), &[".claude", "projects"]);
        let report = survey(workspace.path(), Some(empty.path())).unwrap();
        let projects = claude_projects(&report);
        assert!(projects.present);
        assert_eq!(projects.jsonl_count, Some(0));
        let notes = notes_text(&report);
        assert!(notes.contains("present but EMPTY"), "notes: {notes}");
        assert!(!notes.contains("is absent"), "notes: {notes}");

        // Absent: no projects directory at all.
        let absent = tempfile::tempdir().unwrap();
        let report = survey(workspace.path(), Some(absent.path())).unwrap();
        let projects = claude_projects(&report);
        assert!(!projects.present);
        assert_eq!(projects.jsonl_count, None);
        assert_eq!(projects.level, ObservabilityLevel::NotAvailable);
        let notes = notes_text(&report);
        assert!(notes.contains("is absent"), "notes: {notes}");
        assert!(!notes.contains("present but EMPTY"), "notes: {notes}");
    }

    #[test]
    fn claude_absent_case_is_honest_never_blank_reassurance() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();

        let report = survey(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::NotAvailable
        );

        let notes = notes_text(&report);
        assert!(
            notes.contains("Claude CLI version: Unknown"),
            "notes: {notes}"
        );
        assert!(
            notes.contains("Claude transcripts: .claude/projects is absent")
                || notes.contains("is absent")
        );
        assert!(
            notes.contains("deferred"),
            "the deferral reason must be explicit: {notes}"
        );
        assert!(!notes.trim().is_empty());
    }

    #[test]
    fn claude_cli_version_is_declared_from_install_layout_or_unknown() {
        let workspace = tempfile::tempdir().unwrap();

        // A single version entry is an unambiguous declared fact.
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".local", "share", "claude", "versions", "2.1.260"],
            SENTINEL.as_bytes(),
        );
        let report = survey(workspace.path(), Some(home.path())).unwrap();
        let notes = notes_text(&report);
        assert!(
            notes.contains("Claude CLI version 2.1.260: DECLARED"),
            "notes: {notes}"
        );
        assert!(
            !notes.contains(SENTINEL),
            "the version entry must never be opened or read"
        );

        // No install layout -> Unknown.
        let empty = tempfile::tempdir().unwrap();
        let report = survey(workspace.path(), Some(empty.path())).unwrap();
        assert!(notes_text(&report).contains("Claude CLI version: Unknown"));

        // Several version entries are ambiguous -> Unknown, never a guess.
        let multiple = tempfile::tempdir().unwrap();
        write_file(
            multiple.path(),
            &[".local", "share", "claude", "versions", "2.1.260"],
            b"a",
        );
        write_file(
            multiple.path(),
            &[".local", "share", "claude", "versions", "2.0.0"],
            b"b",
        );
        let report = survey(workspace.path(), Some(multiple.path())).unwrap();
        assert!(notes_text(&report).contains("Claude CLI version: Unknown"));

        // Missing HOME is Unknown too, never a fabricated version.
        let report = survey(workspace.path(), None).unwrap();
        assert!(notes_text(&report).contains("Claude CLI version: Unknown"));
    }

    #[test]
    fn claude_distinctions_match_spec_and_deferral_reason_is_present_in_notes() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".claude", "projects", "session.jsonl"],
            b"{\"type\":\"user\"}",
        );
        make_dir(home.path(), &[".claude", "sessions"]);

        let report = survey(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(
            level_of(&report, Distinction::ConfiguredCapability),
            ObservabilityLevel::Observable
        );
        assert_eq!(
            level_of(&report, Distinction::AttemptedUse),
            ObservabilityLevel::AvailableUnread
        );
        assert_eq!(
            level_of(&report, Distinction::ApprovedUse),
            ObservabilityLevel::NotAvailable
        );
        assert_eq!(
            level_of(&report, Distinction::CompletedAction),
            ObservabilityLevel::AvailableUnread
        );

        let notes = notes_text(&report);
        assert!(
            notes.contains("internal and version-varying"),
            "notes: {notes}"
        );
        assert!(
            notes.contains("does not parse transcripts yet"),
            "notes: {notes}"
        );
    }

    #[test]
    fn claude_transcript_files_are_never_opened_only_counted() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".claude", "projects", "one.jsonl"],
            SENTINEL.as_bytes(),
        );
        write_file(
            home.path(),
            &[".claude", "todos", "todo.json"],
            SENTINEL.as_bytes(),
        );
        write_file(
            home.path(),
            &[".claude", "shell-snapshots", "snapshot.sh"],
            SENTINEL.as_bytes(),
        );

        let before = digest(home.path());
        let report = survey(workspace.path(), Some(home.path())).unwrap();
        let after = digest(home.path());

        assert_eq!(before, after, "survey must not create or modify any entry");
        assert_eq!(claude_projects(&report).jsonl_count, Some(1));
        assert!(
            !format!("{report:?}").contains(SENTINEL),
            "no transcript, todo, or shell-snapshot content may be read"
        );
        assert!(!notes_text(&report).contains(SENTINEL));
        assert!(
            !home.path().join(".claude/projects/one.jsonl-wal").exists()
                && !home.path().join(".claude/projects/one.jsonl-shm").exists(),
            "no sidecar may be created"
        );
    }

    #[cfg(unix)]
    #[test]
    fn claude_transcript_count_requires_no_file_open() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let transcript = home.path().join(".claude/projects/unreadable.jsonl");
        std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        std::fs::write(&transcript, SENTINEL.as_bytes()).unwrap();
        std::fs::set_permissions(&transcript, std::fs::Permissions::from_mode(0o000)).unwrap();

        let report = survey(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(
            claude_projects(&report).jsonl_count,
            Some(1),
            "counting transcript names must not require opening the file"
        );
        assert!(!notes_text(&report).contains(SENTINEL));

        // Restore permissions so the temp dir can be cleaned up.
        std::fs::set_permissions(&transcript, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn claude_surfaces_make_no_evidence_or_observation_claim() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write_file(
            home.path(),
            &[".claude", "projects", "s.jsonl"],
            b"{\"type\":\"assistant\"}",
        );
        make_dir(home.path(), &[".claude", "sessions"]);

        let report = survey(workspace.path(), Some(home.path())).unwrap();
        let rendered = format!("{report:?}").to_lowercase();
        assert!(
            !rendered.contains("observed"),
            "no observed/execution claim may be produced"
        );
        assert!(!rendered.contains("executed"));
        assert!(!rendered.contains("confirmed"));
    }
}
