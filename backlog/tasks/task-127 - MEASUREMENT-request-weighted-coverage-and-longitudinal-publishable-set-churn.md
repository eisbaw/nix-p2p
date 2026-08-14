---
id: TASK-127
title: 'MEASUREMENT: request-weighted coverage and longitudinal publishable-set churn'
status: To Do
assignee: []
created_date: '2026-08-10 22:51'
updated_date: '2026-08-14 21:48'
labels:
  - measurement
  - census
  - longitudinal
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-31
  - TASK-88
  - TASK-95
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Extend the early static store census with evidence that requires a running Iroh swarm and observation over time. Compute request- and byte-weighted publishable/resident coverage from real cold substitutions, then measure insertions and deletions from explicit versioned snapshots or an event log. A current SQLite registrationTime snapshot cannot observe deleted rows and must never be presented as churn evidence. This feeds policy-grade Stage B, not the earlier Iroh implementation gate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Real cold-substitution traces report requested-path and requested-byte fractions that are signed-public, upstream-widened-public and resident on at least one peer; request counters, not the final store contents, are the source of truth.
- [ ] #2 A versioned snapshot or append-only observation format records stable path identity, publishability, NarSize and observation time; fixture diffs prove both insertion and deletion accounting exactly.
- [ ] #3 At least 14 days of observations report daily insert/delete rates, burst maxima and byte-weighted churn, with missing intervals explicit; registrationTime alone is rejected as a deletion oracle.
- [ ] #4 The report separates cold requested coverage, resident census coverage and published coverage and never turns one into another by naming.
- [ ] #5 Artifacts carry collector/config/data hashes and feed TASK-122; if the window is not yet complete, this task stays open with the precise collection state rather than extrapolating.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
This is intentionally later than TASK-95. Environment time may block completion; that is an honest Phase-3 blocked outcome.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
