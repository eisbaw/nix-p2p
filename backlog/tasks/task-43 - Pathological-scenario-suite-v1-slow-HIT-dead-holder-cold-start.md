---
id: TASK-43
title: 'Pathological scenario suite v1: slow-HIT, dead-holder, cold-start'
status: To Do
assignee: []
created_date: '2026-08-08 20:13'
updated_date: '2026-08-09 17:46'
labels: []
dependencies:
  - TASK-42
  - TASK-51
  - TASK-62
  - TASK-66
  - TASK-72
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The first cut of the S8 pathological matrix (the rest deferred to wave-2b re-plan). Using the testproxy throttle (mode 8) + iroh peer control: (1) slow/throttled peer on a HIT; (2) dead/unreachable holder after a positive claim; (3) DHT/discovery cold-start empty index. Each asserts the S8 good behavior (bounded time, correct fallback, never wrong bytes, never unbounded hang) and FEEDS the profiling harness (task-F) with the resource/latency cost. Findings drive policy (task-H).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the 3 scenarios runs in the harness and asserts its S8 good-row behavior with a bite (the assertion fails if the daemon hangs/serves-wrong/unbounded)
- [ ] #2 Each scenario emits its profiling cost (added latency, wasted bytes, RAM) into the task-F report
- [ ] #3 Honest limit: which pathological cases are NOT yet covered (NAT, herd, lying-claim, churn) named for the wave-2b re-plan
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION (arch#3/qa#4/codex#5): (1) The slow-HIT policy does NOT exist at task-43 runtime (task-44 models it, later task implements). So task-43 asserts ONLY the WEAK invariant - never unbounded-hang, never wrong bytes - via the task-51 conservative safety envelope (dep added). Do NOT assert 'policy fires'. (2) PIN numeric bounds; add a per-cell FAULT-OFF baseline (like the wave-1 fault x depth matrix) so the bite bites. (3) Rename 'DHT cold-start' -> 'minimal-discovery cold-start' (no DHT in wave-2a, codex#7). (4) Collects traces to FEED task-44's policy model.

FORWARD-CARRY from task-51: the pathological suite should assert the envelope bounds as the FLOOR (never unbounded-hang, never OOM, never wrong bytes). Good rows already proven in daemon/tests/iroh_safety_envelope.rs and reusable as models: slow-HIT/stalled-peer -> bounded abort (body-idle) -> upstream fallback; dead-holder -> bounded dial-timeout failure; oversized-blob (> signed NarSize) -> streaming TooLarge abort with memory bounded (streamed << blob). Injection points for the suite: IrohTransport::with_envelope(short bounds) for determinism; a stalling ProtocolHandler (accept then sleep) for the mid-transfer stall; a black-hole UDP socket + IrohPeerAddr::new(validNode, deadAddr) for the dead holder; seed a big NAR + fetch with a small expected_size for the NarSize abort. Bites were validated by mutation (neutralize cap / enlarge the specific bound -> falls to coarse backstop). These are the PROVISIONAL floor, not task-44's tuned policy.

## Forward-carried from task-18 (S5 scale-sweep machinery)

- Pathological arms need a resource observation point. `scripts/scale_sweep.py` has one that
  works and is fail-closed: `read_node(role, pid, at)` reads VmHWM/VmRSS/fd-count HOST-SIDE from
  /proc of the container init pid (`Pod.host_pid(role)`, rootless podman -> our own uid). Reuse
  it rather than shelling into the container: `grep` and `find` are NOT in the e2e image, so an
  in-container probe returns rc=127 and passes vacuously (this trap bit twice now).
- `parse_status_kb` RAISES on a missing field. Keep that discipline in the pathological suite:
  a slow/dead-holder arm that cannot read a resource must invalidate the observation, never
  record 0 - "unknown reads as zero" flatters exactly the scenarios you are trying to catch.
- A pathological arm involving several clients must MEASURE the overlap
  (`scale_sweep.max_overlap` over the REALISE_T0_NS/REALISE_T1_NS markers) before claiming a
  thundering herd happened. Proven on real containers that a fleet can silently serialise.
- `Pod.client_run_bg(..., jobs=, conns=, start_at_ns=)` gives you N simultaneous clients behind
  a shared start instant - useful for the thundering-herd case. Knobs default to 1/1 so nothing
  else changes.
- If a pathological arm produces a superlinear RAM/latency law, feed it through
  `scalefit.fit_scaling` + `scalefit.red_flags_for` so the red flag is surfaced under the same
  S5 rules rather than in prose.

## Forward-carried from task-42 (profiling harness)

THE TOPOLOGY YOU EXTEND ALREADY EXISTS. `Pod(..., p2p_holders=N)` runs node-a
plus node-b..node-bN, each a real independently-seeded iroh provider PROCESS
(task-42 ran N=16, i.e. 17 daemons in one pod, 15/15 sweep points valid). N=1 is
byte-for-byte the task-41 two-node S6 topology, so nothing you inherit is a
special case. `Pod(..., state_root=)` bind-mounts a HOST dir per daemon role as
its --narinfo-cache-dir; `pod.state_dir(role)` gives you the host side to walk.

DEAD-HOLDER IS ALREADY HALF-SPECIFIED BY WHAT THE SWARM CANNOT DO.
`InMemoryDiscovery::announce` REPLACES on key, so `--p2p-claim` cannot express
a multi-holder claim (last write wins). Your dead-holder/failover scenario
therefore needs a claim surface that carries >1 holder before 'fast failover to
the NEXT holder' is even testable - today the only failover is peer -> upstream,
which S6 already covers. Treat that as a PREREQUISITE, not a detail: without it
the failover case degenerates into the fallback case you already have.

REUSE, DO NOT REBUILD. `scripts/profile_p2p.py` has the pieces your suite needs:
`score_run()` (frozen counting rule + in-container REALISE_NS in one verdict),
`summarize_profile_arm()`, `dir_footprint()` (host-side, fail-closed on a
missing dir), and `hwm_gap_summary()`. `scale_sweep` still owns /proc sampling
and `max_overlap()`.

TRAPS THAT COST ME TIME:
- `e2e.die` inside a pod bring-up is `sys.exit(2)`, NOT an exception in the
  caught tuple. With 17 containers per point there are 17 chances for one holder
  to miss its identity announcement, and an uncaught SystemExit kills the WHOLE
  run. profile_p2p catches SystemExit, invalidates the POINT when code == 2, and
  re-raises anything else (notably the SIGTERM handler's 143). Copy that.
- A peers-ON arm can silently become a peers-off arm: if the holder does not
  serve, the build succeeds via upstream and every number is still 'valid'. Assert
  the holder's OWN provider counter (`pod.node_b_served_bytes`) advanced by the
  full workload, per run. profile_p2p records `peer_serve_shortfall_runs`.
- `grep`/`find`/`du` are NOT in the e2e image. Anything you want to know about a
  container, observe HOST-side.
- Running `just profile`/`scale-sweep`/`measure`/`e2e` concurrently makes them
  tear down each other's pods (one shared podman label) - filed as TASK-58.

MEASURED BASELINE YOUR PATHOLOGICAL CASES DEVIATE FROM (this host, 110 MiB
`big` payload, loopback):
- peer-served realise 0.690 s mean vs upstream 0.184 s -> the peer path is
  ~3.7x SLOWER than a loopback cache while offloading 100% of payload wire bytes.
- iroh throughput 168 MB/s (NarSize units) vs HTTP-through-daemon 660 MB/s.
- holder peak RSS 248 MiB for a 110 MiB NAR (2.15x); fetching node 141 MiB;
  peers-OFF daemon 10.7 MiB. Both ends resident-size the whole NAR.
- swarm size 1..16 had NO measurable effect on client latency (fitted O(1), class
  not identifiable) and none on per-peer RSS/fds (O(1), 19-21 MiB, 10-11 fds).
  Only the HOST total grows: O(n), R^2=0.9996.

## Forward-carried from TASK-63: which upstream your pathological cells run against

TASK-63 made the upstream a NAMED variable, not an assumption. `just profile`
now has `UPSTREAM_CONDITIONS = ("loopback_control", "wan_shaped")` and the
report refuses to state a speedup without one.

FOR THIS SUITE, three concrete consequences:

1. Your slow-HIT cell is a comparison against an ALTERNATIVE SOURCE, so its
   verdict depends on how fast that source is. Against `loopback_control` the
   upstream serves 110 MiB at 977.8 MB/s, so ANY peer looks slow and
   "abort to cache" always wins; against `wan_shaped` the upstream serves at
   19.9 MB/s and a "slow" peer can still be the faster option. Run the cell
   under BOTH, or state which one it is - a single-condition slow-HIT trace
   would hand TASK-44 a policy input fitted to a machine no user owns.

2. Reuse, do not re-express, the shaping: `profile_p2p.UpstreamShaping` +
   `probe_upstream_link` + the pure `shaping_violations`. It arms the SAME
   testproxy fault modes your suite already uses for throttling (mode 8), plus
   mode 1 for RTT. `--wan-probe-only` checks a shaping point cheaply.

3. THE ORACLE LESSON, which is the transferable part: TASK-63's shaping is
   asserted from OUTSIDE the shaper, unshaped-then-shaped over the same channel,
   and the check FAILS when the unshaped control cannot be told from the shaped
   one. That anti-vacuity clause is what makes it an oracle rather than a
   reading. Your throttled-peer cells need the same shape: measure the injected
   slowness independently and require the fault-off baseline to be materially
   different, or a cell where the throttle silently did not arm passes green.
   Proven here by live mutation (stub the fault-arming -> exit 1, two named
   violations), not by reading the code.
<!-- SECTION:NOTES:END -->
