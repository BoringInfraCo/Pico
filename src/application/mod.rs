//! Application services.
//!
//! Interfaces (CLI) call application services; application services
//! coordinate domain and persistence. See SPRINT-001.md §6 (Interface
//! separation).

pub mod init;
pub mod scan;

pub use init::{InitResult, InitService};
pub use scan::{ScanResult, ScanService};
