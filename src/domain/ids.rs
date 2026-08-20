//! Identifier generation.
//!
//! IDs are unique within a process and extremely unlikely to collide
//! across processes. They carry a readable prefix per domain object
//! kind (e.g. `scan_`, `res_`, `rel_`, `ev_`, `obs_`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a new unique identifier with the given prefix.
pub fn new_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}_{nanos:x}_{n}")
}
