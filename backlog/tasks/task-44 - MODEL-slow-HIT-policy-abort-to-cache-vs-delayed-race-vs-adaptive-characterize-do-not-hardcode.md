---
id: TASK-44
title: >-
  MODEL: slow-HIT policy (abort-to-cache vs delayed-race vs adaptive) -
  characterize, do not hardcode
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 15:47'
labels: []
dependencies:
  - TASK-43
  - TASK-52
  - TASK-63
  - TASK-62
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The owner-named policy archetype. Do NOT hardcode a policy - MODEL the three candidates under the slow-peer-HIT scenario (task-G) and report which wins on wall-clock + net egress (hedge losers counted in the reserved hedge_waste channel): (a) abort-to-cache after T; (b) delayed-race/hedge (start cache fetch, first past the NarHash gate wins, cancel loser); (c) adaptive (abort if throughput < X for T). Then FILE the chosen-policy implementation as its own task grounded in this data. This is design-for-data, per the owner goal.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The 3 candidates measured under the slow-peer scenario: wall-clock + net egress (incl hedge_waste) reported per candidate, with the threshold sensitivity (T, X) swept
- [ ] #2 A recommendation with the data behind it; the chosen policy filed as a NEW implementation task (not implemented here)
- [ ] #3 Honest limit: loopback/container throughput is not residential-uplink; the model states what real-network validation it still needs
- [ ] #4 BOTH REGIMES: every candidate measured against the loopback control AND the TASK-63 WAN-shaped upstream. A recommendation valid only on loopback is not a recommendation - the sign of this whole question is set by upstream speed, which the loopback arm fakes at 758 MB/s and ~0 RTT
- [ ] #5 The STREAMING COMMIT DEADLINE is an explicit modeled constraint (post-TASK-62): abort-to-cache is only free BEFORE the first body byte is committed to Nix. Model hedge as 'hold the response head until first-past-the-gate, then commit and stream' with its bounded-buffer cost - not as 'run both to completion and pick a winner'
- [ ] #6 The headline deliverable is the HEDGE-DELAY vs OFFLOAD-RETENTION curve with the crossover as a function of upstream bandwidth/RTT - not a winner. Hedging immediately against a fast upstream makes the cache always win, collapsing offload toward 0 with hedge_waste = the entire NAR every time; 'no candidate justified' is a legitimate outcome
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (qa#1/arch#6/codex#7 + task-35): (1) DEPENDS ON task-52 (counting-rule v3) - v2 CANNOT measure hedge (every hedge run is INVALID/fail-closed; hedge-loser indistinguishable from truncated primary). Without v3 this task produces unfalsifiable numbers deciding the core latency mechanism. (2) task-35 GROUNDING: hedge is the PRIMARY offload mechanism (real gap 300ms-3s, prefetch viable ONLY on the tail of large closures, never the head/small builds). So the model is 'hedge tuning + when-to-prefetch-on-the-tail', not prefetch-vs-hedge. (3) Trace-model oracle cases with KNOWN winners (validate the model picks the right one); declared sweep ranges for T/X; cache-only AND peer-only baselines; 'NO candidate justified' is a VALID outcome. (4) hedge_waste bytes from task-52's provenance-tagged channel. Stale-ref: 'task-G'=task-43.

FORWARD-CARRY from task-51: the conservative safety envelope is the PROVISIONAL DEFAULT your policy model replaces/measures against. Current default slow-HIT behavior = bounded abort -> fall back to upstream (the simplest safe thing; NO hedge/delayed-race/adaptive). Knobs to model: SafetyEnvelope{dial_timeout=10s, body_idle_timeout=10s, total_timeout=60s} (all PROVISIONAL, injectable via IrohTransport::with_envelope) + the streaming NarSize cap (a safety invariant, NOT a tunable - keep it). The floor task-43 asserts is your lower bound: whatever policy you pick must still never unbounded-hang, never OOM, never serve wrong bytes. The NarSize bound is the SIGNED NarSize (uncompressed), never FileSize. Measure your model against this default as the baseline.

## Forward-carried from task-42 (profiling harness)

THE DISTRIBUTIONS YOU ASKED FOR, MEASURED. `just profile --report <f>` emits
them; the shapes live under `measured.speedup.{peers_on,peers_off}`:
`realise_s` (n/mean/stdev/p95/min/max + every raw value) and
`throughput_bytes_uncompressed_nar_per_s`. Latency is the IN-CONTAINER
`nix-store --realise` duration, never the podman wall clock.

MEASURED, this host, 110 MiB + 64 KiB payloads, loopback, 10 valid runs/arm:
- peers-ON realise mean 0.690 s (p95 ~0.71, stdev ~0.035)
- peers-OFF realise mean 0.184 s
- latency 'speedup' 0.267 -> THE PEER PATH IS ~3.7x SLOWER THAN THE CACHE HERE
- egress offload 1.0 (100% of payload WIRE bytes; peers-ON crossed 0 bytes)
- throughput: iroh 168 MB/s vs HTTP-through-daemon 660 MB/s (both NarSize units;
  the payloads are `compression: none` and the instrument ASSERTS
  file_size == nar_size, so wire and NarSize coincide by checked precondition)

WHAT THAT MEANS FOR YOUR POLICY MODEL, stated so you do not over-fit to it: the
'upstream' in this testbed is an in-pod testproxy on loopback, which is an
unrealistically FAST cache. The honest read is that the peer path costs ~0.5 s
of extra latency to save 100% of egress on this host - so the slow-HIT policy
question is NOT hypothetical, it is the normal case here. Against a REAL
upstream (task-35: median narinfo->nar gap ~300 ms, up to 3.08 s at closure
tails) the sign may flip; model BOTH regimes and say which one each conclusion
belongs to. Do not quote 0.267 as a product number.

RAM IS THE BINDING CONSTRAINT, NOT DISK. The iroh blob store is `MemStore`
(daemon/src/transport_iroh.rs), and the addressed unit is the WHOLE NAR, so both
ends resident-size the payload: holder peak RSS 248 MiB for a 110 MiB NAR
(2.15x), fetching node 141 MiB, versus 10.7 MiB for the peers-OFF daemon. A
hedge that runs a peer fetch and a cache fetch CONCURRENTLY therefore costs
memory as well as the loser's bytes - budget it in the model, and see TASK-54.

SWARM SIZE DID NOT MOVE LATENCY. Over n = 1..16 holder peers the client's p95
realise fitted O(1) (class NOT identifiable, R^2 0.0) and per-peer RSS/fds were
flat. So a slow-HIT policy tuned on 1..16 peers has no measured swarm-size
dependence to account for - and equally, this sweep gives you no evidence about
100s/1000s beyond the labelled model outputs.

REPLICATES ARE NOT OPTIONAL (task-18's lesson, re-confirmed the hard way): with
--repeats 1 the client latency axis fitted O(n log n) and raised a RED FLAG;
with --repeats 3 the same axis fitted O(1). A class that moves between runs is
not a law.

## Forward-carried from TASK-64: the peer-vs-upstream cost model, measured

Numbers your policy model should use instead of guessing (all 110 MiB, loopback,
medians, `just iroh-bench`, daemon/examples/iroh_throughput.rs):

  * Peer path, product's own `IrohTransport::fetch`: 187 MB/s, ~616 ms.
  * Peer path, transport floor (iroh-blobs, no copy/verify):  255 MB/s.
  * Loopback TCP (the unrealistically fast upstream stand-in): 1042 MB/s.
  * FOUR concurrent peer connections: 649 MB/s AGGREGATE (2.54x) at 7.81 CPU
    cores vs 2.95 for one. Per-connection limit, not machine-wide.

THREE things this should change in the model:

1. The peer path's ceiling is ~2.0 Gb/s per connection and 73% of its per-byte
   cost is inherent to QUIC-over-UDP, not to our code. So a hedge/race policy
   must NOT be tuned as if the peer path could be made to match a local HTTP
   cache. It cannot, on loopback. On any link at or below ~2 Gb/s the link binds
   first and the peer path is competitive - which is the regime that matters.
   Model the two regimes separately; a single global policy tuned on loopback
   numbers will be wrong for every real deployment.
2. CPU is a real policy cost, not free. The peer path burns 2.6-3.0 CPU cores
   while moving 187 MB/s; the TCP arm burns 1.15 cores at 1042 MB/s. That is
   ~14x the CPU per byte. A policy that races peer-and-upstream on every fetch
   is not merely wasteful of bandwidth, it is expensive in CPU on the CLIENT.
   Whatever hedge you choose, price the CPU.
3. Latency is not linear in bytes at the small end. At 8 MiB the product fetch
   is ~48 ms and at 110 MiB ~616 ms, so per-byte cost dominates well before the
   payload sizes that matter; the fixed dial cost is small. A delayed-race timer
   can therefore be set from a bytes-per-second estimate rather than needing a
   separate small-object case.

Also: the provisional SafetyEnvelope's BODY_IDLE_TIMEOUT of 10 s is enormous
relative to these numbers - a healthy 110 MiB fetch completes in ~0.6 s. That
is fine as a floor but it is not a policy, exactly as task-51 said.

## Forward-carried from TASK-63: the two regimes your AC#4 names now EXIST, with their fidelity limits

`scripts/profile_p2p.py` has `UPSTREAM_CONDITIONS = ("loopback_control",
"wan_shaped")`. Reuse them; do not invent a third yardstick.

WHAT YOU INHERIT
  * `UpstreamShaping(rtt_ms, bandwidth_bytes_compressed_wire_per_s)` and
    `.fault_params()` - arms testproxy fault modes 1 + 8 through the Pod seam.
    CLI: `--wan-rtt-ms`, `--wan-bandwidth-mib-s`, so you can SWEEP the upstream
    the way your AC#6 crossover curve needs.
  * `probe_upstream_link()` + the PURE `shaping_violations()` - measures the
    shaping host-side, outside the shaper, unshaped then shaped over the same
    channel, and FAILS when the unshaped control cannot be told from the shaped
    one. Any arm you add at a new (RTT, bandwidth) point must run this, or the
    threshold you fit is fitted to an unverified shaper.
  * `--wan-probe-only`: one pod, arm, assert, exit. The cheap way to check a new
    shaping point actually bites before spending a sweep on it.
  * Frozen defaults with their derivation in the constants: RTT 50 ms (bottom of
    task-35's measured 50-110 ms), cap 20 MiB/s (this host's sustained
    single-stream 21.4 MB/s from cache.nixos.org; task-35's tail gaps imply
    6.8-9.8 MB/s). BOTH at the upstream-favourable end deliberately.

THE MEASURED BASELINE YOUR MODEL FITS AGAINST (n=10/arm, 110 MiB):
  loopback_control  peers-off 0.1915 s / peers-on 0.6446 s -> speedup 0.297
  wan_shaped        peers-off 5.9189 s / peers-on 0.6255 s -> speedup 9.46
  upstream link 977.8 MB/s vs 19.9 MB/s. Ranking FLIPS between conditions.

WHAT THE SHAPING DOES NOT MODEL - this bounds what your thresholds can claim:
  * NO per-round-trip RTT inside a transfer, NO TCP slow start, NO
    receive-window-over-RTT ceiling. The bandwidth-delay product is absent by
    construction, so a real high-BDP link degrades WORSE than this arm shows and
    a hedge trigger tuned here will fire LATER than it should on a real link.
  * NO TLS handshake cost (task-22/24), no loss/jitter, no CDN shielding.
  * The PEER side is NOT shaped (pod loopback, 187-255 MB/s). Your hedge-delay
    vs offload-retention crossover is therefore fitted against a peer that is
    unrealistically FAST, which biases the crossover toward "hedge later".
    TASK-70 owns shaping the peer link; if it lands before you fit, use it.
  * The daemon's narinfo disk cache is enabled in both arms, so the injected
    per-request RTT is paid in full only on the first run of a pod. A model that
    depends on narinfo RTT must control for that.

ONE MORE TRAP, on the counting side. The bandwidth cap is applied to bytes on
the WIRE (FileSize units). It coincides with NarSize only because the speedup
arm's payloads are `Compression: none` and `assert_unit_coincidence` CHECKS it.
If you add a compressed payload, the cap and any NarSize-denominated rate stop
being the same number - that is the unit trap this project has hit three times.
<!-- SECTION:NOTES:END -->
