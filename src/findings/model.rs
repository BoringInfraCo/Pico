//! Provider-neutral Finding contracts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const FINDING_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingClass {
    UntrustedToProduction,
}

impl FindingClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UntrustedToProduction => "UNTRUSTED_TO_PRODUCTION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
}

impl FindingStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReasonCode {
    ExternalInfluenceSource,
    AgentRetrievableContent,
    AutonomousExecutionCapability,
    ReachableCredentialAuthority,
    ProductionMutationAuthority,
    NoEnforcedBoundary,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExternalInfluenceSource => "EXTERNAL_INFLUENCE_SOURCE",
            Self::AgentRetrievableContent => "AGENT_RETRIEVABLE_CONTENT",
            Self::AutonomousExecutionCapability => "AUTONOMOUS_EXECUTION_CAPABILITY",
            Self::ReachableCredentialAuthority => "REACHABLE_CREDENTIAL_AUTHORITY",
            Self::ProductionMutationAuthority => "PRODUCTION_MUTATION_AUTHORITY",
            Self::NoEnforcedBoundary => "NO_ENFORCED_BOUNDARY",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingReason {
    pub code: ReasonCode,
    pub resource_ids: Vec<String>,
    pub relationship_ids: Vec<String>,
    pub attack_path_fingerprints: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remediation {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub security_effect: String,
    pub cut_phase: String,
    pub target_resource_ids: Vec<String>,
    pub target_relationship_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub finding_version: u32,
    pub finding_class: FindingClass,
    pub status: FindingStatus,
    pub title: String,
    pub summary: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub source_resource_ids: Vec<String>,
    pub actor_resource_ids: Vec<String>,
    pub sink_resource_ids: Vec<String>,
    pub attack_path_ids: Vec<String>,
    pub attack_path_fingerprints: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub reasons: Vec<FindingReason>,
    pub remediations: Vec<Remediation>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingGenerationStatus {
    Complete,
    Limited,
    Failed,
}

impl FindingGenerationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::Limited => "LIMITED",
            Self::Failed => "FAILED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingResult {
    pub scan_id: String,
    pub finding_version: u32,
    pub status: FindingGenerationStatus,
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLimits {
    pub maximum_attack_paths_examined: usize,
    pub maximum_groups: usize,
    pub maximum_paths_per_finding: usize,
    pub maximum_evidence_per_finding: usize,
    pub maximum_reasons_per_finding: usize,
    pub maximum_remediations_per_finding: usize,
    pub maximum_emitted_findings: usize,
}

impl Default for FindingLimits {
    fn default() -> Self {
        Self {
            maximum_attack_paths_examined: 256,
            maximum_groups: 128,
            maximum_paths_per_finding: 128,
            maximum_evidence_per_finding: 512,
            maximum_reasons_per_finding: 64,
            maximum_remediations_per_finding: 64,
            maximum_emitted_findings: 128,
        }
    }
}
