---
id: TASK-70
title: 'The PEER link is still loopback: every peer-advantage number is an upper bound'
status: In Progress
assignee:
  - '@me'
created_date: '2026-08-09 15:35'
updated_date: '2026-08-13 21:03'
labels:
  - measurement
  - finding
  - transport
dependencies:
  - TASK-63
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY TASK-63. Task-63 shaped the UPSTREAM arm (per-request RTT + NAR egress cap, asserted host-side) and the ranking flipped: peers win 10-11x once the upstream is realistic. But only the upstream is shaped. The peer transport still runs over POD LOOPBACK at ~187-255 MB/s (TASK-64), a rate no real peer link reaches - 1 GbE is 125 MB/s, Wi-Fi and any WAN peer far less. So every peer-advantage number in the wan_shaped arm is an UPPER bound on the peer side at the same time as a lower bound on the upstream side, and the asymmetry is not small: a 110 MiB NAR takes ~0.55 s over pod loopback and ~0.9 s over 1 GbE before any RTT. A first-order correction is easy to state (peers still win) but it is a correction, not a measurement. WHY IT WAS NOT DONE IN TASK-63: the peer transport is iroh QUIC over UDP, so the testproxy's HTTP-level fault modes cannot touch it; tc/netem needs NET_ADMIN which rootless podman does not have. Candidate routes, none free: (a) a shaping knob INSIDE the daemon's iroh transport (pace the receive loop) - cheap and deterministic but it shapes our own code, not the link, and it would live in the product daemon which the PRD forbids for adversarial/environment logic; (b) a userspace UDP relay in the pod that paces datagrams - a real link emulator but an extra hop and its own CPU cost on the path whose throughput is in question; (c) run the two nodes in separate netns with a veth pair and tc netem under a user namespace that HAS NET_ADMIN for that netns - closest to a real link, most setup. Settle the route before building.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The peer link is shaped with an RTT and a bandwidth cap, and the shaping is ASSERTED from outside the shaper with a negative control, the same discipline as TASK-63's upstream probe (a shaper that never fired must go red with a named failure)
- [x] #2 The shaping does NOT live in the product daemon, or if it must, it is compiled/feature-gated out of the shipped binary and that is proven
- [ ] #3 The wan_shaped speedup is re-stated with BOTH sides shaped, next to the peer-loopback number, and the report says which of the two is the upper bound
- [x] #4 Honest limit recorded: what the chosen route still does not model (loss, jitter, competing flows, NAT traversal cost)
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

## AC#1/#2/#4 LANDED; AC#3 DEFERRED to TASK-198 (2026-08-13)

SETTLED ROUTE (c), proven on this box: `unshare -Urn` yields a user+net namespace whose map-root grants FULL caps (CapEff 000001ffffffffff) WITHOUT real root, so ip/tc work. The load-bearing detail the earlier spike missed: with BOTH veth ends in ONE netns the kernel short-circuits the pair locally and netem never shapes (the 100% 'loss' artifact). FIX: move the peer end into a SECOND netns via the child-pid pattern — fork `unshare -n sleep`, address it by /proc/<pid>/ns/net, `ip link set veth1 netns <pid>`, configure with `nsenter -t <pid> -n`. netem delay+rate applied to BOTH egress directions => symmetric RTT ~= 2*delay.

ARTIFACTS (all on script/measurement surface, NEVER in the shipped daemon):
  - scripts/shaped_link.py        — driver + PURE oracle assert_shaping() + --self-test + honest limits
  - scripts/shaped_link_inner.sh  — in-namespace nested-netns/veth/netem setup (child-pid pattern), exact-pid cleanup trap
  - scripts/shaped_link_xfer.py   — sender-timed bulk TCP (drain-ack => rate is an endpoint clock OUTSIDE netem's own accounting)
  - scripts/check_shaping_out_of_daemon.py — AC#2 guard, wired into `just independence`

AC#1 (shaping asserted host-side + negative control, oracle must bite): DONE. Oracle refuses the run unless the injected RTT is recovered on the shaped arm AND the unshaped control RTT is ~0 AND shaped throughput is near the cap (bit, not collapsed) AND the unshaped control is MEASURABLY faster (>=2x) — a shaper that never fired goes RED with a named cause (task-63 discipline). `shaped_link.py --self-test` proves non-vacuous: baseline accepted, all 6 mutations + 2 truncations bitten.
AC#2 (not in the shipped binary, proven): DONE by construction (script-only) + gate-enforced: check_shaping_out_of_daemon.py scans the 7 shipped crate src/ trees for netem/veth/unshare/tc-qdisc/ip-netns/NET_ADMIN/shaped_link tokens — 80 src files clean — and runs in `just independence`.
AC#4 (honest limits): DONE — HONEST_LIMITS block printed by the tool + here: models mean RTT + a rate cap only; does NOT model loss, jitter, competing/cross traffic, NAT-traversal cost, real-NIC offload/CPU; a veth pair over ONE host's shared kernel, not two machines.
AC#3 (re-state wan_shaped speedup with BOTH ends shaped): DEFERRED to TASK-198 (blocked on TASK-70 + TASK-99). Per this task's own WIRE-COST CORRECTION, no peer-vs-upstream speedup may be re-derived until link compression (task-99) lands — the peer byte-volume depends on it. Producing a number now would be one task-99 invalidates. NOT faked.

REAL SPIKE (this box, 10 MiB, delay 20ms, cap 100mbit): shaped RTT 48.2ms throughput 77.4mbit; unshaped RTT 0.1ms throughput 56294mbit (loopback veth). Oracle PASS. Clean teardown, no orphan netns/processes. (77mbit vs 100 cap = short-transfer TCP ramp at 40ms RTT; well inside the 'capped, not collapsed' band. The default 40 MiB runs closer to the cap.)

GOTCHA for TASK-198: profile_p2p.py + daemon/examples/iroh_throughput.rs are iroh-worded; the shipped primary transport is now libp2p-stream. AC#3 must run the REAL libp2p two-node NAR transfer through this shaped-link primitive (not the raw-TCP probe that validates the primitive itself).
<!-- SECTION:NOTES:END -->
