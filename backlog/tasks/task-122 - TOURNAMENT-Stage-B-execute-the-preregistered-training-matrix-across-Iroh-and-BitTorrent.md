---
id: TASK-122
title: >-
  TOURNAMENT Stage B: execute the preregistered training matrix across Iroh and
  BitTorrent
status: To Do
assignee: []
created_date: '2026-08-10 22:24'
updated_date: '2026-08-14 21:48'
labels:
  - tournament
  - measurement
  - training
  - e2e
  - wave-2c
  - deferred-pending-202
dependencies:
  - TASK-52
  - TASK-62
  - TASK-77
  - TASK-78
  - TASK-79
  - TASK-80
  - TASK-87
  - TASK-99
  - TASK-101
  - TASK-103
  - TASK-112
  - TASK-113
  - TASK-114
  - TASK-118
  - TASK-121
  - TASK-125
  - TASK-127
  - TASK-128
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Execute only the TRAINING partition defined by TASK-114 using the transport-neutral harness. Compare upstream-only, Iroh raw/compressed and BitTorrent raw/compressed across controlled pathologies, cold/warm swarms and real-network/NAT scenarios. Keep discovery-only, transport-only and full-stack real-Nix results separate. This task produces evidence and a versioned artifact; it does not choose a production default and must not read or run the holdout partition.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The frozen training manifest runs upstream-only, Iroh raw/compressed and BitTorrent raw/compressed-or-evidenced-no-go cells; every unsupported, invalid, failed and excluded cell is present in the report.
- [ ] #2 Trials are randomized/counterbalanced and paired with recorded seeds, A/A calibration, minimum N, detectable effect, confidence intervals and bottleneck-isolation checks from TASK-114.
- [ ] #3 Component discovery, component transport and full-stack real-Nix metrics are distinct records; no synthetic addition is labelled end-to-end.
- [ ] #4 Provider-side peer bytes, upstream bytes, S1/S2, latency percentiles, TTFB, bootstrap/resolve, waste, CPU/RAM/disk/fds/upload and direct/hole-punched/relay path are recorded with unambiguous units.
- [ ] #5 Privacy/participation evidence records published/query data and third-party dependencies for every arm; missing measurements fail closed rather than reading as zero.
- [ ] #6 The artifact contains the manifest/config/code hashes and a structural assertion that no holdout scenario ID, seed, topology or result was accessed.
- [ ] #7 The holdout generator is not invoked and no holdout material exists; a bite attempting generation/read from the Stage-B runner fails before scoring.
- [ ] #8 Run the frozen TASK-128 parity qualification and the exact centered joint N=100 eligibility planner over all preregistered workload strata and exact selector-versus-best-static contrasts. The training artifact exposed to TASK-44 contains only the eligibility mask, global N, catalog/interpreter/planner/config/code hashes and permitted A1 training evidence; raw A2 observations, residuals, effects and uncentered statistics remain inaccessible.
- [ ] #9 Seal A1/A2 evidence behind distinct readers after centered planning. TASK-44 receives only permitted A1 evidence plus the eligibility mask, global N and frozen hashes. Raw A2, residuals, effects and uncentered statistics are available only to the later TASK-129 validation reader after TASK-44 freezes candidate and comparator hashes; this task does not emit post-fit validation slots.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Policy-grade training evidence only. Losing to upstream, LAN-only usefulness and unsupported compression are valid outcomes.

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
