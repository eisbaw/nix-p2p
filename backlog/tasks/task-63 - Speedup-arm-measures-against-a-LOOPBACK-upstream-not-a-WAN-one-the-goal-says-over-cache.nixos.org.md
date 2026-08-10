---
id: TASK-63
title: >-
  Speedup arm measures against a LOOPBACK upstream, not a WAN one - the goal
  says 'over cache.nixos.org'
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 13:26'
updated_date: '2026-08-10 09:30'
labels: []
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-42's speedup arm compares peer-served against the local testproxy, which has ~0 RTT and 758 MB/s. That is not the yardstick the owner goal names ('speed up over cache.nixos.org'), and it inverts the result: the peer path measured 3.5x SLOWER (realise 0.562s peers-on vs 0.159s peers-off) purely because the fake upstream is faster than any real one. TASK-35 measured the REAL upstream: median narinfo->nar gap ~300 ms, tail to 3.08 s. Until the upstream arm carries realistic RTT/bandwidth, every speedup and every slow-HIT policy threshold derived from it is fitted to an artifact. Two routes: (a) traffic-shape the testproxy arm (inject RTT + bandwidth cap from the task-35 distribution) - cheap, deterministic, no external dependency, no TLS needed; (b) front the real cache.nixos.org - needs TASK-22 (testproxy TLS) + TASK-24 (daemon TLS upstream) and is non-deterministic/rate-limit-sensitive. Prefer (a) for the modeling arms and keep (b) as a validation spot-check. Do not delete the loopback arm - it is the useful zero-latency control.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 just profile grows a WAN-shaped upstream arm whose injected RTT/bandwidth are derived from task-35's measured real-upstream distribution, and the shaping is asserted (measured RTT matches the injected one), not assumed
- [x] #2 The speedup/offload report distinguishes the loopback-control arm from the WAN-shaped arm; no single unqualified 'speedup' number is emitted
- [x] #3 Re-state the peers-on-vs-peers-off latency comparison against the WAN-shaped arm; the loopback before-numbers (0.562s vs 0.159s, speedup 0.283) are pinned as the control
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
ROUTE (a): traffic-shape the testproxy arm. Route (b) (real cache.nixos.org) is NOT built.

WHERE THE SHAPING IS INJECTED: in the testproxy, via its EXISTING fault modes 1
(per-kind added latency) and 8 (throttle_nar_bps). Rationale: (i) environment/
adversarial behaviour already lives in the fixture and never in the product
daemon (PRD rule); (ii) the primitives exist, are unit-tested and are driven
through the Pod seam's `proxy_faults`, so no new hop and no new CPU on the
measured path; (iii) it is MEASURABLE FROM OUTSIDE - the host can time requests
against the published proxy port, which is on the far side of the shaper.
Rejected: a Python TCP relay between daemon and testproxy (adds a hop and CPU to
the measured path, and would have to re-implement pacing); `tc netem` (needs
NET_ADMIN, unavailable rootless).

SHAPING PARAMETERS, derived not invented:
  rtt_ms = 50            per-request added latency on cache-info/narinfo/nar
  bandwidth = 20 MiB/s   NAR egress cap, in bytes_compressed_wire per second
Derivation is recorded next to the constants: task-35/TESTING.md records
steady-state RTT 50-110 ms to the Fastly PoP and a head-of-closure gap min of
41 ms; direct probes from this host (2026-08-09) measure TCP connect 27-78 ms
and sustained single-stream 21.4 MB/s over a 56 MB NAR. Both parameters are
chosen at the UPSTREAM-FAVOURABLE end of the measured evidence so the arm
understates, never overstates, any peer advantage.

WORK:
1. profile_p2p.py: `UpstreamShaping` dataclass + frozen constants with
   provenance; `--wan-rtt-ms` / `--wan-bandwidth-mibs` / `--wan-probe-only`.
2. `measure_upstream_link()` - HOST-SIDE probe through the published proxy port
   (outside the shaper): median per-request latency over N narinfo GETs and
   achieved NAR bytes/s, measured UNSHAPED then SHAPED in the same pod through
   the same channel.
3. `shaping_violations()` - PURE. Asserts (a) the recovered latency delta is the
   injected RTT within tolerance, (b) the achieved NAR rate is the injected cap
   within tolerance, and (c) THE ANTI-VACUITY CHECK: the unshaped control must be
   materially faster than the shaped observation, else the probe cannot tell
   shaped from unshaped and that is a NAMED failure, not a pass. Non-empty =>
   the run fails.
4. `run_speedup_arms` runs TWICE: `loopback_control` (unshaped, unchanged, so it
   stays comparable to the pinned before-numbers) and `wan_shaped`.
5. AC#2 enforced MECHANICALLY, not editorially: every speedup ratio key carries
   its upstream condition as a suffix (`..._loopback_control` / `..._wan_shaped`),
   gated by `speedup_qualifier_violations()`; and the human summary is refactored
   to `human_summary_lines()` so `human_summary_violations()` can gate every line
   mentioning a speedup for a condition label. Both proven by mutation in
   --self-test.
6. TASK-68 (cheap-if-possible): rename the throughput key to
   `realise_rate_...` and say it is 1/realise_s x a constant and NOT a transport
   rate; ADD a real transport rate at the cache boundary from the testproxy's own
   per-record bytes_sent/duration_ms.
7. Gates: build, lint, test, e2e, and at least one full `just profile`.
<!-- SECTION:PLAN:END -->

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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE 2026-08-09. The speedup arm now races the peer path against TWO NAMED
upstream conditions and the report cannot state a speedup without saying which.

ROUTE (a): shaped in the testproxy via its existing fault modes 1 (per-request
latency) and 8 (throttle_nar_bps). Route (b) not built, as directed.

PARAMETERS, DERIVED: RTT 50 ms/request (bottom of task-35's measured 50-110 ms
to cache.nixos.org's Fastly PoP; this host measures 27-78 ms per TCP round
trip); cap 20 MiB/s in bytes_compressed_wire/s (this host sustained 21.4 MB/s
single-stream from cache.nixos.org over a 56.6 MB NAR; task-35's tail gaps imply
6.8-9.8 MB/s).

AC#1 - ASSERTED, TWICE, AND PROVEN BY MUTATION. `probe_upstream_link` times the
proxy HOST-SIDE through the published port, outside the shaper, unshaped then
shaped over the same channel, per request KIND; `measured_link_rate_violations`
then asserts the arm's OWN link rate at the cache boundary over the SCORED runs,
closing the temporal and path gaps the probe leaves. The anti-vacuity clause -
the unshaped control must be materially faster or it is a NAMED failure - is
what makes it an oracle rather than a reading. Measured: narinfo 1.20->51.47 ms,
NAR TTFB 1.35->51.69 ms, 1394.6->20.004 MB/s (0.954x cap), control headroom
66.5x. Two LIVE mutations, both exit 1 with named violations: (a) shaping never
armed; (b) `latency_nar_ms` alone dropped - which the FIRST version of this
oracle passed green, and which the per-kind check now catches.

AC#2 - MECHANICAL. Every speedup ratio key carries its condition as a suffix;
`speedup_qualifier_violations` rejects a bare one, a dropped condition, a
camelCase evasion, and now prose. `human_summary_violations` gates the PRINTED
text and its verdict is persisted into the JSON. All proven by mutation.

AC#3 - RE-STATED, with the control pinned (n=10/arm, 110 MiB):
  loopback_control  peers-off 0.1706 s / peers-on 0.6174 s -> speedup 0.276
                    (peers 3.6x slower), link 1073.3 MB/s
  wan_shaped        peers-off 5.9194 s / peers-on 0.6383 s -> speedup 9.274
                    (peers 9.3x faster), link 19.9 MB/s
  egress offload 1.00 in both. RANKING FLIPPED = True. The pinned task-42
  control (0.562 / 0.159 / 0.283) reproduces within noise.

THE FINDING: the task-42 3.5x peer deficit is a property of the UPSTREAM, not of
the peer transport. It binds only against an alternative source faster than
~2 Gb/s, which on this testbed is one machine nobody owns.

GATES: build/lint/test/e2e rc=0 (26 e2e scenarios; 209 cargo tests; profile
self-test ALL PASS), `just profile` rc=0 usable=True. TESTING.md records the
parameters, their derivation, the assertion, both mutations and the limits.

HONEST LIMITS, all recorded in the report and in TESTING.md: the shaper models
SERVICE LATENCY and EGRESS RATE, not a link - no slow start, no
receive-window-over-RTT ceiling, so the bandwidth-delay product is absent by
construction. The PEER side is NOT shaped (still pod loopback at 187-255 MB/s),
so the peer advantage is an UPPER bound on the peer side -> TASK-70. The arm is
NOT a clean lower bound on the upstream cost: charging a full RTT per request
costs ~4% in the other direction. And the 9.27x MAGNITUDE is approximately
(peer rate / cap), sampled at ONE cap - the FLIP is robust, the number is linear
in a knob. Sweeping it is TASK-44's crossover curve.

FOLLOW-UPS: TASK-70 filed (shape the peer link). TASK-67 carried the number with
a recommendation to CLOSE as not-worth-it (the link binds long before the peer
transport does). TASK-68 partly closed - the realise-rate key is renamed and a
real transport rate added for the UPSTREAM; the peer-side half and the
mechanical derived-quantity gate stay open, recorded there. Lessons
forward-carried to TASK-44, TASK-43 and TASK-65.
<!-- SECTION:FINAL_SUMMARY:END -->
