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
//! Surface whitelist (conservative; recorded in [`RuntimeReport::notes`]):
//!
//! - OpenCode: `~/.local/share/opencode/opencode.db` and its `-wal`/`-shm`
//!   sidecars, `storage/`, `snapshot/`, `tool-output/`.
//! - Claude Code: `~/.claude/projects/`, `~/.claude/sessions/`.
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
    pub level: ObservabilityLevel,
}

/// Read-only observability survey. Deterministic: surfaces are sorted by agent
/// then label and no timestamps are included (a point-in-time capability read,
/// not an event log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReport {
    pub surfaces: Vec<SurfaceReport>,
    pub distinctions: Vec<(Distinction, ObservabilityLevel)>,
    pub notes: Vec<&'static str>,
}

/// Human-output honesty line (SPRINT-039 §2.3). Exposed so both interfaces
/// describe the same limitation.
pub const HONESTY_LINE: &str = "This reports what is observable, not what the agent did.";

const NOTE_METADATA_ONLY: &str = "filesystem metadata only (existence, kind, byte size, readability, -wal/-shm presence); no content database is opened, no file contents are read, and no file is created or modified";
const NOTE_WHITELIST: &str = "surface whitelist: OpenCode ~/.local/share/opencode (opencode.db + -wal/-shm, storage/, snapshot/, tool-output/) and Claude Code ~/.claude (projects/, sessions/)";
const NOTE_EXCLUDED: &str = "excluded by policy: prompt-history.jsonl, log/ directories, credential/account stores (auth.json, account.json, mcp-auth.json), and .claude.json";
const NOTE_APPROVED_USE: &str = "approved vs denied use is NOT_AVAILABLE: upstream records allow/deny only through live hooks or OTel export, never in dependable local state";
const NOTE_DECLARED: &str = "surfaces are DECLARED evidence about observability capability, never evidence of agent activity, execution, or approval";

const AGENT_OPENCODE: &str = "OpenCode";
const AGENT_CLAUDE: &str = "Claude Code";

const OPENCODE_BASE: &[&str] = &[".local", "share", "opencode"];
const CLAUDE_BASE: &[&str] = &[".claude"];

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
}

const SURFACES: &[SurfaceSpec] = &[
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE,
        base: OPENCODE_BASE,
        name: "opencode.db",
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE_SHM,
        base: OPENCODE_BASE,
        name: "opencode.db-shm",
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SESSION_STORE_WAL,
        base: OPENCODE_BASE,
        name: "opencode.db-wal",
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_STORAGE,
        base: OPENCODE_BASE,
        name: "storage",
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_SNAPSHOT,
        base: OPENCODE_BASE,
        name: "snapshot",
    },
    SurfaceSpec {
        agent: AGENT_OPENCODE,
        label: LABEL_OPENCODE_TOOL_OUTPUT,
        base: OPENCODE_BASE,
        name: "tool-output",
    },
    SurfaceSpec {
        agent: AGENT_CLAUDE,
        label: LABEL_CLAUDE_PROJECTS,
        base: CLAUDE_BASE,
        name: "projects",
    },
    SurfaceSpec {
        agent: AGENT_CLAUDE,
        label: LABEL_CLAUDE_SESSIONS,
        base: CLAUDE_BASE,
        name: "sessions",
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
    level: ObservabilityLevel,
}

/// Survey each supported agent's runtime surfaces and the per-distinction
/// observability matrix. Read-only; returns an empty error surface because
/// metadata failures are represented honestly as `Unknown`, not errors.
pub fn survey(workspace: &Path, home: Option<&Path>) -> Result<RuntimeReport, PicoError> {
    let mut surfaces = Vec::with_capacity(SURFACES.len());
    for spec in SURFACES {
        let resolved = resolve(home, spec.base, spec.name);
        let probe = probe(resolved.as_deref());
        let path = display_path(resolved.as_deref(), workspace, home, spec.base, spec.name);
        surfaces.push(SurfaceReport {
            agent: spec.agent.to_string(),
            label: spec.label.to_string(),
            path,
            present: probe.present,
            bytes: probe.bytes,
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

    Ok(RuntimeReport {
        surfaces,
        distinctions,
        notes: vec![
            NOTE_METADATA_ONLY,
            NOTE_WHITELIST,
            NOTE_EXCLUDED,
            NOTE_APPROVED_USE,
            NOTE_DECLARED,
        ],
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
                level,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Probe {
            present: false,
            bytes: None,
            level: ObservabilityLevel::NotAvailable,
        },
        Err(_) => Probe {
            present: false,
            bytes: None,
            level: ObservabilityLevel::Unknown,
        },
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
}
