---
id: TASK-88
title: >-
  S10 measurement: cold-start vs steady-state offload on a 10+ peer swarm (the
  real-traffic answer)
status: To Do
assignee: []
created_date: '2026-08-10 05:55'
updated_date: '2026-08-10 09:30'
labels:
  - wave-2b
dependencies:
  - TASK-87
  - TASK-77
  - TASK-66
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Owner request 2026-08-10: 'initial and steady state measurements'. This is the measurement TASK-87's harness exists to make, and it is the closest thing this project can get to the PRD's value thesis without leaving one host.

THE DISTINCTION THAT MATTERS. At t=0 nobody holds anything, so every path comes from upstream and offload is ~0 - a cold swarm CANNOT offload. As peers fetch and announce, content accumulates and offload should climb. So the headline is not a number, it is a CURVE: offload as a function of how much the swarm has already seen. Reporting a single offload figure without saying where on that curve it was taken is the exact overclaim shape this project keeps catching. The wave-1/2a offload=1.00 figures are STEADY-STATE-BY-CONSTRUCTION (the holder was pre-seeded with exactly what the client wanted) and must be relabelled as such wherever they are quoted, including README.md.

HARD DEPENDENCY on TASK-77 (announce-after-fetch): without it a node never becomes a holder for what it fetched, the swarm never grows, and there is no steady state distinct from the initial state - the measurement would be vacuous. Also TASK-66 (multi-holder): at N=10 several peers will hold the same path, and an index that replaces rather than accumulates collapses that to one, hiding both load spreading and failover.

WHAT TO MEASURE, over the cold->warm transition:
  * offload fraction vs cumulative paths seen (the curve), and the time/volume to reach a plateau
  * upstream egress: total bytes the swarm pulled from upstream vs what N independent nodes would have pulled (the actual saving, in uncompressed-NAR units - never mix with compressed transport bytes)
  * duplicate/wasted fetches: N peers wanting the same path at once (thundering herd, TESTING.md S8) - how many redundant upstream fetches and redundant peer dials
  * per-peer RAM (high-water AND point), fds, disk, using the task-65 axes and the store-residency oracle rather than peak RSS alone
  * latency distribution per substitution, split by served-from-peer vs served-from-upstream, fitted from the IN-CONTAINER realise duration (never host-side podman wall clock, which carries container setup that itself scales)
  * what fraction of requests a peer served vs declined (serve budget) vs failed

HONEST FRAMING REQUIRED: this is one host. The peer links are loopback, so peer throughput is an UPPER bound (TASK-70) and a residential uplink would likely invert the latency result (cache.nixos.org sustained ~21 MB/s in task-63's probe; a typical home uplink is 1.25-5 MB/s). Any claim about 100s/1000s of peers is model output over the measured range per S5, never a measurement, and emergent network effects are out of scope for a single-host sweep.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 An offload-vs-swarm-warmth CURVE, not a point: offload fraction reported against cumulative content the swarm has seen, with the cold-start value (expected ~0) and the plateau both stated, plus how much traffic it took to get there
- [ ] #2 Total upstream egress for the swarm compared against the N-independent-nodes baseline, in uncompressed-NAR units, under the frozen counting rule - this is the PRD's actual promise and the number that survives whichever upstream you assume
- [ ] #3 Thundering-herd cost measured: with N peers wanting the same path simultaneously, the count of redundant upstream fetches and redundant peer dials is reported, not assumed to be 1
- [ ] #4 Per-peer RAM (high-water + store residency), fds, disk and per-substitution latency split by peer-served vs upstream-served; a point whose measured concurrency does not match the intended one is INVALID
- [ ] #5 Every previously published offload figure that was steady-state-by-construction (pre-seeded holder) is relabelled as such, in README.md and in the profiler's report - a cold swarm cannot offload and the old numbers must not read as if it could
- [ ] #6 Honest limits stated: single host, loopback peer links (upper bound), no NAT/relay, and the residential-uplink inversion named explicitly
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
<!-- SECTION:NOTES:END -->
