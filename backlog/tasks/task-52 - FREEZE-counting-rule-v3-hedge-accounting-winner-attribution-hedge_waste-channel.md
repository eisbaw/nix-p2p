---
id: TASK-52
title: >-
  FREEZE: counting-rule v3 - hedge accounting (winner attribution + hedge_waste
  channel)
status: To Do
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 20:29'
labels:
  - irreversible
dependencies:
  - TASK-9
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
qa+arch: net-upstream-egress-v2 is UNDEFINED for the hedge regime (marks the hedge-loser row UNRESOLVED; a hedge-loser partial is byte-indistinguishable from a truncated primary -> every hedge run is INVALID/fail-closed). So the hedge policy candidate CANNOT be measured. task-44 depends on fixing this. Define v3: attribute exactly ONE winning transfer per payload to payload egress; count hedge-LOSER bytes in a separate provenance-tagged hedge_waste channel (discriminated by request PROVENANCE, which the testproxy log must now carry - not by byte count). Extending the frozen counting rule is a deep-gate irreversible event. Ground: task-35 confirms hedge is the PRIMARY offload mechanism, so measuring it correctly is essential, not optional.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A run containing a hedge (winner + cancelled loser) is VALID; winner bytes -> payload egress, loser bytes -> hedge_waste, discriminated by request provenance in the testproxy log (bite: a truncated PRIMARY still INVALID; a hedge loser is NOT)
- [ ] #2 v3 is a version bump with rationale; existing v2 numbers remain comparable for the no-hedge regime (documented)
- [ ] #3 testproxy request log carries provenance (which fetch a byte belongs to) so hedge_waste is attributable, not guessed
<!-- AC:END -->
