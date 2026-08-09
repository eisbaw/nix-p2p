---
id: TASK-63
title: >-
  Speedup arm measures against a LOOPBACK upstream, not a WAN one - the goal
  says 'over cache.nixos.org'
status: Done
assignee:
  - '@me'
created_date: '2026-08-09 13:26'
updated_date: '2026-08-09 16:26'
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
## Forward-carried from TASK-64: your arm is what decides whether the deficit matters

TASK-64 root-caused the 3.6x. The finding hands you a specific number to test.

The peer transport's ceiling is ~255 MB/s per connection for iroh-blobs and
187 MB/s for the product's full fetch path (110 MiB loopback, medians,
`just iroh-bench`). 255 MB/s is ~2.0 Gb/s. So:

  * On 1 GbE (125 MB/s), Wi-Fi, or any WAN link, the LINK is the binding
    constraint and the peer transport is nowhere near it. The 3.6x deficit
    simply does not exist on a realistic network.
  * The deficit only binds where the alternative source is faster than about
    2 Gb/s - which on this testbed means exactly one thing: the loopback
    testproxy, which does 1042 MB/s of TCP with 64 KiB writes.

So the task-42 3.6x is mostly a statement about YOUR arm being unrealistic, not
about iroh being slow. That is the single most valuable thing your WAN-shaped
upstream can establish, and it is worth an explicit AC: once the upstream arm is
shaped like a real cache, REPORT whether the peer path is still slower, and by
how much. The likely answer is that peers win, and the whole task-64 deficit
becomes a footnote.

Please also carry this into how you report: state the upstream arm's achieved
BYTES PER SECOND next to the peer path's, so the comparison is link-vs-link.
And note that `nix-store --realise` seconds carry unpack + sha256 NarHash +
store registration, so a realise-rate is NOT a transport rate (that confusion is
TASK-68).

TASK-67 (parallel/striped peer fetch, 2.54x measured headroom) is deliberately
BLOCKED on your number: if the link binds, TASK-67 should be closed as
not-worth-it rather than implemented.

## Progress: shaping landed and ASSERTED (AC#1 evidence)

Route (a). Shaping injected in the TESTPROXY via its existing fault modes 1
(per-kind added latency) and 8 (throttle_nar_bps) - the fixture is where
environment behaviour belongs (PRD: never in the product daemon), the
primitives were already unit-tested, and the proxy port is published to the
host, which is what makes the shaping observable from OUTSIDE the shaper.
Rejected: a Python TCP relay (an extra hop + CPU on the path whose throughput
is in question), and `tc netem` (needs NET_ADMIN; not available rootless).

Injected: RTT 50 ms per request (cache-info/narinfo/nar), cap 20 MiB/s in
bytes_compressed_wire per second.

MEASURED, host-side through the published proxy port, `--wan-probe-only`:
  unshaped median request  1.115 ms   ->  shaped  51.388 ms   (recovered 50.27 ms)
  unshaped NAR rate  1522.8 MB/s      ->  shaped  20.013 MB/s (0.954 x cap)
The unshaped control is 72x the cap, so the measurement channel is nowhere near
the limiter - that is the anti-vacuity half of the check, and it is asserted,
not assumed.

BITE PROVEN BY LIVE MUTATION. `UpstreamShaping.fault_params()` was temporarily
made to return "" (shaping configured but never armed) and the same probe rerun:
  recovered RTT 0.03 ms, shaped rate 3055.2 MB/s (145.7 x cap)
  -> exit 1 with two NAMED violations:
     "injected RTT NOT recovered: ... 0.0 ms, outside [40.0, 80.0] ms"
     "injected bandwidth cap NOT achieved: ... outside [14680064, 23068672]"
Mutation reverted; self-test ALL PASS afterwards.

The pure `shaping_violations` is additionally mutation-proven in --self-test
(shaped==unshaped, cap-only failure, slow-channel vacuity, slow-unshaped-latency
vacuity, missing measurement).

## RESULT: the ranking flips. `just profile` rc=0, usable=True

Full run, defaults (swarm 1,2,4,8,16 x3 replicates; 10 runs x 2 arms x 2
upstream conditions; workload lib + big = 110 MiB, `Compression: none`):

  loopback_control (~0 RTT, unshaped - the CONTROL, kept deliberately)
      peers-off 0.1915 s (sd 0.0376, p95 0.2388)
      peers-on  0.6446 s (sd 0.0774, p95 0.6981)
      speedup 0.297 (peers 3.4x SLOWER); observed range 0.196-0.549
      upstream link rate 977.8 MB/s (wire)
  wan_shaped (50 ms/request, 20 MiB/s wire cap, both ASSERTED)
      peers-off 5.9189 s (sd 0.0303, p95 5.9642)
      peers-on  0.6255 s (sd 0.0850, p95 0.7243)
      speedup 9.46 (peers 9.5x FASTER); observed range 7.86-13.47
      upstream link rate 19.9 MB/s (wire)
  egress offload = 1.00 in BOTH conditions. RANKING FLIPPED = True.
  PINNED task-42 control (0.562 / 0.159 / 0.283) reproduces within noise.

Swarm axis unchanged and still green: 15/15 valid, per-peer VmHWM 19.8-21.8 MiB
flat, swarm total O(n) R^2=0.9981, no red flags.

ANSWER TO TASK-64's FORWARD-CARRIED QUESTION: the 3.5x peer deficit is a
property of the upstream, not of the peer transport. It only binds against an
alternative source faster than ~2 Gb/s, which on this testbed is exactly one
machine. Against a 20 MiB/s upstream the peer path runs ~9x the link and the
LINK binds first. Carried to TASK-67 with the recommendation to close it.

## GOTCHAS AND REJECTED APPROACHES (feed-forward)

* Route (b) - fronting the real cache.nixos.org - NOT built, as directed. It
  needs TASK-22 + TASK-24 and is rate-limit-sensitive. Keep it as a spot-check.
* REJECTED: a Python TCP relay between daemon and testproxy. It adds a hop and
  CPU to the exact path whose throughput is under measurement, and would have to
  re-implement pacing the testproxy already does.
* REJECTED: `tc netem`. Needs NET_ADMIN; rootless podman does not have it. This
  is also why the PEER link could not be shaped -> TASK-70.
* The shaper is a SERVICE-LATENCY + EGRESS-RATE shaper, not a link emulator: one
  delay per REQUEST plus body pacing. No slow start, no
  receive-window-over-RTT ceiling, so the bandwidth-delay product is absent BY
  CONSTRUCTION and the WAN arm still flatters the upstream. TASK-64's point that
  WAN is window-over-RTT bound is therefore only PARTLY exercised.
* The bandwidth cap is in bytes_compressed_wire per second. It coincides with
  NarSize only because the speedup payloads are `Compression: none` and
  `assert_unit_coincidence` CHECKS it. Add a compressed payload and the cap and
  any NarSize rate stop being the same number.
* The daemon's narinfo disk cache is on in both arms, so the injected
  per-request RTT is paid in full only on a pod's first run. Realistic, but it
  means the RTT knob moves the WAN result far less than the bandwidth knob does.
* `prewarm_upstream_cache` was added to EVERY speedup pod in EVERY condition on
  purpose: the WAN condition has to probe the proxy anyway, so probing only
  there would have left the WAN arm warm and the CONTROL cold - a confound that
  DIFFERS between the two things being compared, which is worse than one present
  in both.
* Timeouts were checked, not assumed: 110 MiB at 20 MiB/s is ~5.9 s, well inside
  FETCH_TIMEOUT 60 s, and the pacing sleeps every 64 KiB so BODY_IDLE_TIMEOUT
  10 s is never approached. The arm is not sitting on a timeout ceiling.
* `--wan-probe-only` exists precisely so the shaping oracle can be re-proven in
  ~40 s instead of ~30 minutes. Use it after touching the shaping.

## REVIEW ROUND (mped-architect + qa-test-runner) - what it found, all fixed

The reviewers found two HIGH findings that were real holes in the oracle, not
presentation. Recording them because both are reusable lessons.

1. A FAILED CONDITION DISCARDED THE ONE THAT SUCCEEDED. `run_speedup_arms`
   raises on an unverified shaper; `run_speedup_conditions` had no per-condition
   guard, so a WAN failure unwound the loop and threw away ten minutes of valid
   loopback CONTROL runs. Tell: every downstream consumer already handled a
   non-ran condition and NOTHING at runtime could produce that shape - only the
   self-test could. Dead handling code for a state the producer cannot reach is
   a reliable smell that the producer is wrong.
2. THE SHAPING WAS JUDGED IN THE WRONG PLACE, TWICE. Verified once, at pod
   creation, on the HOST->proxy path - then 20 runs were scored on the IN-POD
   daemon->proxy path with nothing re-checking. Fixed by judging each probe at
   probe time AND adding a second, independent assertion over the SCORED runs'
   own link rate at the cache boundary (data the report already carried). That
   is the transferable lesson: an oracle beside the measurement is weaker than
   an oracle over it.

MOST VALUABLE FINDING, and it was mine-plus-theirs: the probe only ever observed
the NARINFO latency. `latency_nar_ms` was armed on the arm's DOMINANT request
and never looked at. Proven by live mutation: drop `latency_nar_ms` from the
query string and the cap still fires (0.96x) and the narinfo RTT is still
recovered - the round-1 checker went GREEN on a half-armed shaper. The fix
measures NAR time-to-first-byte and checks per request KIND; the same mutation
now exits 1 naming the NAR. A per-knob oracle must observe EVERY knob, not the
easiest one.

Also fixed: prewarm warmed only `big` while claiming to warm the workload;
`ranking_flipped: false` was emitted when fewer than two conditions produced a
number (now null); the human-summary gate's verdict never reached the persisted
JSON (the artifact said compliant:true while the process exited 1); the JSON
gate read only KEYS while the summary gate read TEXT, so "peers measured 3.5x
SLOWER" in a prose field passed one and would have been rejected verbatim by the
other; "any peer advantage this shows is a lower bound" was an OVERCLAIM (see
below); ~758 MB/s was quoted five times as the loopback link rate when it was
task-42's REALISE rate (the TASK-68 confusion), measured link rate is ~1073
MB/s; the self-test hand-rolled its own condition block, already four keys
adrift, so the gates were proven against a shape the real run does not produce.

## THE OVERCLAIM, kept visible because it is the kind that recurs

"Both knobs are upstream-favourable, so any peer advantage is a lower bound" is
FALSE as stated. The knob VALUES are upstream-favourable; the MODEL is not
uniformly so. The delay is charged per REQUEST and a real client on a reused
keep-alive connection does not pay a fresh round trip for each one - ~5 x 50 ms
= ~0.25 s of a 5.92 s peers-off realise, about 4%, in the upstream's disfavour.
Only the PEER-side bound is clean (peer arm unshaped => upper bound on the peer
side). `shaping_fidelity.bias_directions` now lists both signs and magnitudes.

## AND THE ONE ABOUT THE HEADLINE NUMBER

With the peer arm unshaped, `latency_speedup_mean_wan_shaped` is approximately
(peer-path rate / cap). Its MAGNITUDE is therefore linear in a knob, sampled at
exactly one cap. The FLIP is robust - it happens anywhere below ~187 MB/s - but
9.27x is not a property of the system alone. Do not quote it as one. Sweeping
the cap is TASK-44's crossover curve; `--wan-bandwidth-mib-s` exists for it.
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
