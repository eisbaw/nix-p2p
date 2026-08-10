---
id: TASK-70
title: 'The PEER link is still loopback: every peer-advantage number is an upper bound'
status: To Do
assignee: []
created_date: '2026-08-09 15:35'
updated_date: '2026-08-10 09:29'
labels:
  - measurement
  - finding
  - transport
dependencies:
  - TASK-63
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY TASK-63. Task-63 shaped the UPSTREAM arm (per-request RTT + NAR egress cap, asserted host-side) and the ranking flipped: peers win 10-11x once the upstream is realistic. But only the upstream is shaped. The peer transport still runs over POD LOOPBACK at ~187-255 MB/s (TASK-64), a rate no real peer link reaches - 1 GbE is 125 MB/s, Wi-Fi and any WAN peer far less. So every peer-advantage number in the wan_shaped arm is an UPPER bound on the peer side at the same time as a lower bound on the upstream side, and the asymmetry is not small: a 110 MiB NAR takes ~0.55 s over pod loopback and ~0.9 s over 1 GbE before any RTT. A first-order correction is easy to state (peers still win) but it is a correction, not a measurement. WHY IT WAS NOT DONE IN TASK-63: the peer transport is iroh QUIC over UDP, so the testproxy's HTTP-level fault modes cannot touch it; tc/netem needs NET_ADMIN which rootless podman does not have. Candidate routes, none free: (a) a shaping knob INSIDE the daemon's iroh transport (pace the receive loop) - cheap and deterministic but it shapes our own code, not the link, and it would live in the product daemon which the PRD forbids for adversarial/environment logic; (b) a userspace UDP relay in the pod that paces datagrams - a real link emulator but an extra hop and its own CPU cost on the path whose throughput is in question; (c) run the two nodes in separate netns with a veth pair and tc netem under a user namespace that HAS NET_ADMIN for that netns - closest to a real link, most setup. Settle the route before building.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The peer link is shaped with an RTT and a bandwidth cap, and the shaping is ASSERTED from outside the shaper with a negative control, the same discipline as TASK-63's upstream probe (a shaper that never fired must go red with a named failure)
- [ ] #2 The shaping does NOT live in the product daemon, or if it must, it is compiled/feature-gated out of the shipped binary and that is proven
- [ ] #3 The wan_shaped speedup is re-stated with BOTH sides shaped, next to the peer-loopback number, and the report says which of the two is the upper bound
- [ ] #4 Honest limit recorded: what the chosen route still does not model (loss, jitter, competing flows, NAT traversal cost)
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
