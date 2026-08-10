---
id: TASK-104
title: 'Per-batch work budget: one hold-query message must not monopolise a responder'
status: To Do
assignee: []
created_date: '2026-08-10 12:18'
labels:
  - wave-2b
dependencies:
  - TASK-91
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-91 (batched hold-query).

TASK-91 caps a batch at MAX_BATCH_HOLD_KEYS = 256 keys, which bounds the WORK one message can demand to at most 256 AvailabilityIndex probes - each of which may cost one nix-store --dump of an unhashed path. That is not NEW work (the same 256 single-key probes cost the same), but it is now demanded by ONE message from ONE peer, which changes who controls the pacing.

Two concrete consequences already observed and stated as limits in the code:

1. daemon/src/discovery.rs DirectDiscovery::resolve_many bounds each chunk probe by the same PROBE_TIMEOUT (5 s) as a single probe. A COLD peer that must derive 256 large NARs to answer can exceed that and be treated as a miss. Safe direction (the fetch falls back upstream) but it UNDER-REPORTS availability, and it under-reports it exactly when a peer is most useful (a fresh peer with a lot of content).

2. There is no per-responder budget on how much derivation a batch may trigger. The task-72 serve budget bounds bytes SERVED, not bytes HASHED.

Likely shape of the fix: the responder answers from what is already derived and schedules the rest, i.e. a batch answer becomes 'yes / no / not-yet' - which is a WIRE CHANGE and therefore needs the same deep gate as TASK-91 (and probably a schema_version bump, since 'not-yet' is a third answer). Decide whether 'not-yet' is worth a version bump or whether an unanswered key should simply be Absent (today's behaviour) with a background derive.

Do NOT patch this by raising the timeout: that puts unbounded latency back into the build path, which is the exact property TASK-40 established.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A responder cannot be made to spend unbounded derivation work by one batch message, and the bound is proven by a bite (a batch of N cold large paths answers within the bound rather than timing out the whole probe)
- [ ] #2 A cold peer is not silently reported as holding nothing: the under-reporting in TASK-91's stated limit either goes away or is measured and accepted with numbers
- [ ] #3 If the answer shape changes, the claim wire is versioned, the frozen golden vectors in daemon/tests/golden/claim_wire_v1.json still pass untouched, and new vectors are pinned
<!-- AC:END -->
