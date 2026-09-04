# Pico — v0.4 Slice 4: Causal Explanation (Sprint 027)

**Status:** reference note, not a sprint spec.
**Sprint:** 027 (`docs/internal/sprints/SPRINT-027.md`)

`pico diff` names **one** primary cause for each appeared or disappeared
Finding. The cause is the smallest path-local graph change on that
Finding's attack path, ranked:

1. Bash `can_execute` effective state / relationship state
2. GitHub MCP / influence presence
3. Credential reachability
4. Mutation authority
5. Sink identity (paired fingerprint flip)

Unchanged Findings have no Cause line. PARTIAL attempts never invent a
cause. MCP has no cause tool. v0.4 is not complete.
