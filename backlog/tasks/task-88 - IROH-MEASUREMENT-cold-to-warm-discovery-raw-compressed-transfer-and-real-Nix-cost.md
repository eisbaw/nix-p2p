---
id: TASK-88
title: >-
  IROH MEASUREMENT: cold-to-warm discovery, raw/compressed transfer and real-Nix
  cost
status: To Do
assignee: []
created_date: '2026-08-10 05:55'
updated_date: '2026-08-14 21:48'
labels:
  - wave-2b
  - deferred-pending-202
dependencies:
  - TASK-32
  - TASK-43
  - TASK-59
  - TASK-66
  - TASK-68
  - TASK-70
  - TASK-77
  - TASK-87
  - TASK-94
  - TASK-99
  - TASK-114
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Measure the complete Iroh implementation before starting BitTorrent work. Using TASK-87, characterize cold bootstrap through steady state for raw and negotiated-compressed Iroh under controlled link profiles and a 10+ node real-Nix swarm. Keep discovery, transfer and full-stack numbers separate; record privacy/resource costs and the upstream baseline. This is the frozen Iroh reference against which later BitTorrent and tournament arms are compared, not a production policy verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Raw and compressed Iroh produce paired cold-to-warm offload curves against upstream-only, with fresh-state cold value, plateau, convergence traffic and provider-side attribution.
- [ ] #2 Total upstream egress is compared with N independent nodes in uncompressed-NAR units, while peer socket wire bytes and discovery/control bytes remain separate.
- [ ] #3 Raw/compressed TTFB and p50/p95/p99 full-build latency, CPU, RAM high-water/residency, disk, fds, upload, serve declines and compression ratio are measured under verified link profiles.
- [ ] #4 Dead/slow holder, cold index, relay use, exhausted serve budget and corrupted compressed stream have bounded non-vacuous outcomes with S1/S2 preserved.
- [ ] #5 All earlier pre-seeded/loopback offload or speedup figures are relabelled; the versioned artifact records manifest/config/code hashes and explicitly makes no cross-backend or production-default claim.
- [ ] #6 TASK-117 is blocked on this artifact so BitTorrent design starts from measured Iroh behavior rather than parallel speculation.
- [ ] #7 Only development/training scenario namespaces are accepted; the holdout generator/material is unavailable, and a deliberate attempt to load a holdout namespace fails and invalidates the run.
- [ ] #8 Bootstrap and exact-key content-resolution latency is always reported for the passing decentralized TASK-103 path with tracker and LAN disabled. Named-candidate direct query is a separate bounded non-global cell. Tracker and Mainline measurements run only when optional artifacts exist and can never replace the decentralized result; MISS UNAVAILABLE and direct hole-punched or relay paths stay distinct.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## WIRE-COST CORRECTION 2026-08-10: every peer-vs-cache number in this task is invalid until TASK-99 lands

MEASURED on 20 signed paths >10 MiB from the live cache.nixos.org: FileSize/NarSize = 0.278 aggregate
(median 0.216). cache.nixos.org serves xz; our peers serve RAW nar (daemon/src/rewrite.rs rewrites
Compression:none with FileHash=NarHash and FileSize=NarSize, asserted in daemon/tests/narinfo_rewrite.rs).
So a peer moves ~3.6x the bytes upstream moves for the same store path, and must sustain
>75 MB/s (604 Mbit/s) upload merely to BREAK EVEN before any discovery latency is counted. A home
uplink is 1.25-5 MB/s. Below that threshold NO NAR size wins, and the deficit GROWS with size.

WHY THIS INVALIDATES PUBLISHED NUMBERS: every speedup figure this project has produced was measured
against a FIXTURE upstream that also served uncompressed - task-64 added assert_unit_coincidence
which proves file_size == nar_size for exactly the speedup attrs. So none of them include the
asymmetry a real cache has. That includes the 6.1x WAN and 0.248 loopback figures.

This is the FOURTH recurrence of the NarSize-vs-FileSize unit trap in this project, and this time it
was in the orchestrator reasoning rather than in the code.

FIX AND ORDER: TASK-94 measures the inequality; TASK-99 fixes it by compressing the LINK (not the
content - the addressed unit must stay BLAKE3(raw nar) or peers compressing with different settings
produce different blob ids and lose all sharing). Do not re-derive any policy threshold, speedup, or
peer-vs-upstream ranking from this task until TASK-99 has landed and TASK-99 AC#4 has re-measured.

COHERENCE REFRAME 2026-08-14 (COMPASS flag 2 / TASK-202): this is an IROH-framed task. Under the PRD Wave-2c authority (libp2p-PRIMARY) and the now-PROVEN libp2p-kad decentralized discovery (TASK-103 MVP Done + TASK-159 resolution + TASK-179 routed netns), the PRODUCTION decentralized-discovery gate is the LIBP2P path (TASK-103 -> 191 -> 194, all Done), NOT iroh. So this task is OPTIONAL-TRANSPORT REFERENCE (an iroh comparison arm), not the production gate its title/framing implies. OWNER DECISION (COMPASS fork point, not mine to make): whether iroh remains a FUNDED transport/tournament arm at all determines this task's priority — if iroh is deprioritized under libp2p-primary, demote accordingly. Left priority unchanged pending that product call. The PRD execution-order prose (§693-734, 'GLOBAL-IROH GATE') still reads as iroh-first and needs owner-reviewed reconciliation to Wave-2c (that PRD-prose edit is TASK-202, owner-review-gated).

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
