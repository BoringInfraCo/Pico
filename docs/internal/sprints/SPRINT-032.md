# Sprint 032 — conservative observed-change attribution

Status: implemented; final closeout gates pending. Inventory: SPRINT-032-inventory.md.

## Frozen contract

Attribution version 1 is an additive application result over S029-compatible
COMPLETE operands. Schema remains v6 and S029's persisted observation and finding
versions remain unchanged: attribution is a separately versioned interpretation.
No discovery is rerun by diff. Existing lifecycle buckets describe observation
set movement; disappearance is never remediation without affirmative support.
Every moving graph subject and every moving finding receives a classification,
stable reasons, separate safe side provenance, and disappearance_confirmed.
Human and machine consumers must describe unconfirmed disappearance as not
observed, and must not present a causal remediation claim.

Coverage version 1 is persisted in scan metadata before final status update.
Local adapters record each bounded candidate location as inspected, incomplete,
or not attempted. Missing home is explicitly not attempted. Provider enumeration
is unknown: normalized authority results do not prove exhaustive collection.
Environment credential discovery is bounded and conditional; absent provider
subjects are never established removals in this version. Legacy or malformed
coverage remains unknown; COMPLETE never upgrades it.

Typed graph values distinguish missing, JSON null, and present values. Grants
and unknown reasons are set-like; order-only differences are ignored. Environment
classification requires affirmative paired values supported by exact-subject,
same-scan evidence metadata for the specific changed field, plus matching source
type and locator. Knowledge transitions are evidence changes. Mixed requires
both components. Unsupported or ambiguous causes remain unattributed. Display
renames and identity quality changes cannot establish security remediation.

No new MCP behavior is in this sprint. Stable public projection and MCP use the
shared application attribution in S033 and S034 respectively.

## Acceptance

Unit and real-discovery regressions cover persisted candidate coverage, omitted
home, legacy/malformed fallback, typed missing/null/value and set normalization,
exact subject collision, known/unknown evidence movement, paired affirmative
field support, mixed classification, and unconfirmed absence. Existing S024–S031
regressions remain required; golden human output updates must reflect explicitly
qualified observation absence rather than weaken safety assertions.

## Implementation evidence

Seven classifier unit regressions cover exact subject and same-scan field support,
knowledge/mixed changes, unconfirmed absence, malformed coverage versus legacy,
validated unique scope fingerprints and inspected scope equality, and evidence
quality signatures independent of regenerated IDs. Five real ScanService fixtures
cover isolated Bash allow→deny, MCP enabled→disabled, reduced collection scope,
persisted omitted-home coverage, and malformed configuration coverage.

The isolated Bash deny changes affirmative local policy but also stops conditional
provider collection. Its finding is therefore mixed, with multiple possible
causes, aggregate separate-side provenance, and no remediation claim. Multiple
unresolved graph movements without both established components stay unattributed.
Confidence-only changes require changed evidence support (class, freshness,
source, or knowledge metadata); a rating delta alone establishes no cause.

Human output calls missing observations “Not observed” and prints both sides of
attribution support. S024–S029 rendering pins were updated for that wording; all
94 S020–S029 integration regressions passed during implementation.
