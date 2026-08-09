---
id: TASK-44
title: >-
  MODEL: slow-HIT policy (abort-to-cache vs delayed-race vs adaptive) -
  characterize, do not hardcode
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 13:33'
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
<!-- SECTION:NOTES:END -->
