---
id: TASK-94
title: 'RAW BASELINE: peer-wire break-even inequality before any codec policy'
status: To Do
assignee: []
created_date: '2026-08-10 08:43'
updated_date: '2026-08-13 21:48'
labels:
  - wave-2b
dependencies:
  - TASK-64
  - TASK-70
  - TASK-114
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Establish the raw/uncompressed peer-wire economics used by Stage A. Measure cache.nixos.org FileSize/NarSize over a reproducible signed-path sample, measure raw peer socket throughput under validated controlled link conditions, and compute the break-even inequality without smuggling compression or policy conclusions into the result. This is diagnostic evidence: raw WAN losing at every size is a valid outcome, but it cannot decide the compressed Stage-B policy. Compression implementation and re-evaluation belong to TASK-99.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 FileSize/NarSize is measured over at least 200 cache.nixos.org-signed paths spanning all size deciles, with Compression recorded; an uncompressed fixture sample is classified and excluded from the compressed-upstream aggregate.
- [ ] #2 Raw peer socket throughput is measured at at least three NAR sizes under TASK-70's externally verified link profiles; loopback results are labelled loopback and the harness refuses to label them WAN.
- [ ] #3 The report computes the break-even size from measured ratio, upstream bandwidth, peer bandwidth and discovery/dial latency; when the denominator is non-positive it prints NO SIZE THRESHOLD EXISTS, proven by a pinned negative-denominator bite.
- [ ] #4 Wire bytes, uncompressed NarSize, discovery/control bytes and protocol overhead stay in distinct fields, and provider-side counters plus shaping controls make each arm non-vacuous.
- [ ] #5 The artifact is structurally tagged diagnostic_uncompressed and cannot select a production policy; TASK-99 owns codec implementation and the compressed re-evaluation.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY: TASK-99 is the FIX for the asymmetry this task measures. Sequence them deliberately - measure the inequality first (it is the honest baseline and the cheap disproof), but do NOT conclude 'peers cannot win' from a measurement taken with compression OFF. The PRD reserved per-connection zstd at round 3 as a policy surface; the 3.6x is a deferred feature gap, not a property of the design.

DEP SURGERY 2026-08-13 (COMPASS F1 + orchestrator): dropped TASK-95 (OPTIONAL/Low store-composition census — orthogonal to this task's signed-path FileSize/NarSize sampling + raw socket throughput) and TASK-52 (hedge-accounting counting-rule v3 — this raw point-to-point break-even diagnostic has NO hedge regime and measures via direct sockets + narinfo metadata + arithmetic, NOT through the frozen net-upstream-egress rule). GUARD FOR THE IMPLEMENTER: your FIRST onboarding step is to CONFIRM this task's measurement does not route bytes through net-upstream-egress-v2/v3; if it genuinely does depend on hedge accounting, STOP, re-add --dep TASK-52, and report blocked. Kept deps 64/70/114 are all Done.
<!-- SECTION:NOTES:END -->
