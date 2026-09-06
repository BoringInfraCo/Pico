# Pico — v0.4 Independent Developer Comprehension Protocol

**Status:** NOT RUN — no independent participant has been recruited or tested.
**Build / date / administrator:** pending.
**Authority:** [S035](../sprints/SPRINT-035.md), ROADMAP §8, and the carried
[v0.3 independent gate](comprehension-v0.3.md).

This is a protocol and blank evidence record, not a proxy answer sheet or a
completed comprehension result. An implementing agent cannot be the independent
participant.

## 1. Eligibility and administration

Record a participant alias and their relevant development experience. Obtain an
explicit declaration that they did not implement this feature or author the
fixtures. A founder who did either is not independent for this gate. Record the
administrator and any prior exposure to Pico or its design.

Freeze the build and output packet before testing. Hand the participant only
captured human CLI output, JSON/MCP output where needed, and ordinary product
help. Provide no source, internal sprint documents, seeded database contents,
expected-answer rubric, or explanation of the intended result. The participant
may state that output is insufficient; record that as useful evidence.

Use neutral case labels A–H rather than descriptive labels that reveal the
expected attribution. Record shown artifact names and hashes, command context,
and every extra document requested. An administrator may repeat a question or
clarify an illegible capture; record this. Explaining an attribution, suggesting
a cut point, or supplying a missing limitation is coaching and invalidates that
scenario's uncoached pass. Capture answers verbatim before discussing them.

## 2. Packet assembly — administrator only

Assemble final-build captures from S035. Do not give this table to the participant.

| Case | Capture selection | Distinction under test |
| --- | --- | --- |
| A | E2 unchanged comparison and history | Stable observations do not imply universal safety. |
| B | E3 supported permission/approval change, with before/after provenance | Supported observed environment change and the affected boundary. |
| C | E5 evidence/access loss with a newer incomplete attempt | Missing observation does not confirm path removal; freshness matters. |
| D | E6 reduced coverage or missing legacy provenance despite COMPLETE | Completion is not proof of comparable scope; attribution can remain unknown. |
| E | E7 rating movement and ambiguous causes | Confidence/severity movement is not itself an environmental cause. |
| F | E8 contract mismatch | Analysis/contract incompatibility prevents a valid posture comparison. |
| G | E9 retained history, retained diff, and pruned-pair error | First seen is relative to retained history; deleted evidence is unavailable. |
| H | E11 path/finding detail and mixed-agent posture | Carried v0.3 source/actor/authority/evidence/boundary comprehension. |

Include only positive claims the delivered implementation actually makes. If B
cannot demonstrate supported environment attribution, mark the packet incomplete;
do not coach a participant to invent the missing claim. If no active production
Finding is supported in H, preserve that uncertainty and test comprehension of
why no active Finding was produced. Do not seed a fictional live success.

## 3. Set A — change comprehension questions

Ask these questions for each relevant case; record N/A only when the question
truly does not apply, with the administrator's reason.

1. What does this output establish changed, if anything? Why would it matter?
2. Which before/after observations support that conclusion? Point to the output.
3. Did the environment change, did Pico's evidence change, is the cause unknown,
   or is the comparison invalid? What supports your interpretation?
4. Is a previously dangerous path confirmed gone, merely unobserved, unchanged,
   or not assessable from this output? What remains uncertain?
5. How current is this comparison? Is there a newer attempt the comparison does
   not incorporate, and how does that affect your confidence?
6. What does first seen or reappeared mean here? What does retained history fail
   to establish? (Required for G.)
7. What practical action, if any, would interrupt an observed path? Does this
   output establish that Pico executed it?

After all cases, show corresponding JSON/MCP output for B, C, F, and G. Ask whether
it changes the interpretation or hides a limitation visible in the human view.
A participant need not understand JSON syntax perfectly; they must not be induced
into a false safety claim by an absent or ambiguous limitation.

## 4. Set B — carried v0.3 path comprehension

Administer against H separately and record a separate outcome:

1. What externally controlled source begins the path?
2. Which autonomous actor connects influence to authority?
3. What consequential capability is reachable, and is production impact known?
4. Why would the finding be severe? What supports its confidence or uncertainty?
5. Which evidence supports the path, and what did Pico actually observe?
6. What boundary is enforced, absent, or uncertain? Distinguish the agents if
   their Bash postures differ.
7. Name at least one practical cut point and explain which edge it interrupts.
8. Did Pico prove exploitation or apply remediation?
9. If no active Finding is shown, why is that not necessarily an all-clear?

Passing Set A does not automatically pass Set B. An honest unknown-production
answer is correct when the packet's evidence leaves production unknown.

## 5. Objective scoring — administrator only

Score each applicable answer **2** (correct, independently supported by output),
**1** (partly correct or missing a noncritical detail), or **0** (wrong, unsupported,
or supplied only after coaching). Record output evidence and an explanation for
every score. Do not require exact wording or memorized enum names.

Safety-critical requirements, all mandatory:

- C/D: never infer confirmed removal, remediation, or global safety from missing
  evidence, incomplete collection, reduced scope, or COMPLETE alone.
- C: identify the newer incomplete attempt and the older comparison's freshness
  limitation when shown.
- F: identify invalid comparison due to the contract/version change; do not
  interpret it as an environmental change or empty safe diff.
- G: scope first-seen/reappearance claims to retained history and understand that
  a pruned scan cannot provide evidence through the query.
- B/E: tie an environment claim to supported observations; do not treat rating
  movement or ambiguous multiple changes as proof of one environmental cause.
- H: preserve unknown authority/production/boundary state; do not infer
  exploitation or executed remediation from observation.

For a PASS, each safety-critical answer must score 2, all other applicable
answers must score at least 1, and at least 80% of total possible points must be
awarded. Apply this rule separately to Set A and Set B. Record numerator,
denominator, N/A reasons, and failures; a high average cannot erase a critical
failure. Product output insufficient to answer a critical question is a failure
of the packet/product, not a reason to supply the answer.

Any critical failure requires diagnosing and correcting the output or packet,
then a new uncoached run. Prefer a new eligible participant; if the same person
repeats, disclose earlier exposure and use unseen equivalent cases so a rehearsed
answer cannot silently count as independent comprehension. Keep previous results.

## 6. Qualitative learning, after scoring

Ask and record verbatim:

- Which change would you act on first, and which felt noisy or informational?
- What observation told you something new or changed a decision?
- How much history would you keep, and what privacy/storage tradeoff matters?
- When would you manually scan again?
- How should an analysis-version limitation be explained?
- What change would justify a future notification, and what would make you mute it?
- Would you keep Pico installed? What was confusing or overstated?

These are learning inputs, not score targets. A negative usefulness answer must
be preserved and considered in release review; it must not be rewritten to PASS.

## 7. Blank result record

```text
Run ID:
Date / administrator:
Participant alias / relevant experience:
Independence declaration (verbatim):
Prior Pico exposure:
Build commit / dirty patch digest / binary SHA-256:
Packet artifacts and hashes:
Additional help shown / interruptions / coaching:

Case / question:
Verbatim answer:
Supporting output identified by participant:
Score (0/1/2) and reason:
Safety-critical requirement (if any):
Confusion / requested missing information:

Set A points earned / possible:
Set A safety-critical results:
Set A outcome (PASS / FAIL / NOT RUN):
Set B points earned / possible:
Set B safety-critical results:
Carried v0.3 outcome (PASS / FAIL / NOT RUN):
Qualitative answers (verbatim):
Required corrections / new run ID:
Release reviewer / decision / evidence link:
```

Current Set A outcome: **NOT RUN**. Current carried v0.3 independent outcome:
**NOT RUN**. Protocol preparation does not change the historic proxy records or
satisfy the v0.4 release gate.
