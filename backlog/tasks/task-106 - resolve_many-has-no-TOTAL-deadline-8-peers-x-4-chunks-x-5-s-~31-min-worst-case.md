---
id: TASK-106
title: >-
  resolve_many has no TOTAL deadline: 8 peers x 4 chunks x 5 s = ~31 min worst
  case
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 14:06'
updated_date: '2026-08-16 03:37'
labels:
  - wave-2b
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found by the TASK-91 DEEP gate (mped-architect M1), deferred there deliberately to keep that cycle bounded.

DirectDiscovery::resolve_many bounds each PROBE at PROBE_TIMEOUT (5 s) but bounds NOTHING in aggregate. A 1000-path closure chunks to 4 probes per peer; with 8 configured peers that is 32 sequential probes, so a set of silent peers costs 8 x 4 x 5 s = ~160 s per resolve_many call, and a pathological configuration reaches ~31 minutes. The whole point of PROBE_TIMEOUT is that a miss must not leak latency into the Nix build path; batching multiplied the number of bounded waits without adding a bound over their sum.

It also CONTRADICTS a rule the same file already states: PeerQuery::query_batch documents that a per-PEER fault propagates rather than burning the other 255 keys, because retrying against a peer we cannot reach is pure waste. resolve_many does the opposite - it logs the failed chunk and continues to the next chunk against the SAME peer.

WHAT IS NEEDED
- A total deadline for one resolve_many call (the closure resolution is on the build path; the caller has a budget, not the individual probe).
- On a per-PEER fault, abandon that PEER's remaining chunks rather than the current chunk only - matching the rule query_batch already states.
- Decide whether peers should be probed CONCURRENTLY; today they are strictly sequential, which is also why the AC#3 baseline is the most naive possible one.

This lands with TASK-100 because that task re-shapes the same call: do not inherit the assumption that a per-probe bound is a bound.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 resolve_many is bounded in TOTAL, not only per probe, and the bound is asserted by a test with N silent peers
- [x] #2 A per-PEER fault abandons that peer's remaining chunks, matching the rule query_batch already documents
- [x] #3 The sequential-vs-concurrent peer decision is made explicitly and written down, not left implicit
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN (TASK-106):
AC#1 total deadline: add RESOLVE_MANY_TIMEOUT const (30s = 6x PROBE_TIMEOUT, half the fabric-iroh FETCH_TIMEOUT/60s total) as a DirectDiscovery field; in resolve_many compute deadline=Instant::now()+total, check remaining before each peer/chunk, bound each chunk probe at min(probe_timeout, remaining). Hard-bounds the SUM while preserving partial results (keys already resolved are returned; the rest fold to upstream). BITE: N HangingQuery peers, probe=50ms, total=200ms => returns ~200ms not N*50ms; mutation removing the deadline restores the N*probe blowup.
AC#2 per-peer abandonment: on the two peer-fault arms (query_batch Err, timeout Err) BREAK the chunk loop (abandon the peer remaining chunks) instead of continue, matching query_batch documented rule. Protocol-defense arms (misaligned len, out-of-range offer) stay chunk-skip because the peer DID answer in time. BITE: 2-chunk closure (257 keys) against a counting faulting peer => called once not twice.
AC#3 decision: KEEP SEQUENTIAL. Rationale in FINAL note.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (commit 092abc8). All 3 ACs met, both bites mutation-proven, full gate green.

TOTAL DEADLINE: RESOLVE_MANY_TIMEOUT = 30s (6x PROBE_TIMEOUT, half fabric-iroh FETCH_TIMEOUT). PROVISIONAL backstop; never fires on a live peer set (first peer answers in ms). Taken once at entry, each probe clamped to min(probe_timeout, remaining), peer loop stops when spent; partial results returned, unresolved keys fold to a clean miss -> upstream (task-40 safe direction). No float (integer Instant/Duration).

PER-PEER ABANDON (AC#2): query_batch-error and probe-timeout arms now continue to the NEXT peer (continue in the labeled peer loop) instead of the next chunk of the same peer, matching the rule PeerQuery::query_batch documents. Per-answer defence failures (misaligned length / out-of-range offer index) still only skip that chunk (the peer answered in time; not a connectivity fault).

SEQ-vs-CONCURRENT (AC#3): KEEP SEQUENTIAL, deliberate. The total deadline bounds the sequential worst case regardless of N; the residual (a silent early peer spending budget a live later peer could use) degrades to a SAFE miss -> upstream, a performance opportunity cost not a correctness bug. Sequential preserves cross-peer key subtraction (a later peer is asked only about still-unresolved keys) and the deterministic first-Have-wins / failover order (task-66). Concurrency would sacrifice both and needs a bounded fan-out + Have tiebreak = the versioned execution plan TASK-100 AC#5 owns and must NOT hardcode before holdout. NOTE for TASK-100: this total-deadline + per-peer-abandon shape is now in place; thread the CALLER budget through the seam and subsume RESOLVE_MANY_TIMEOUT.

BITES (mutation-proven):
- resolve_many_is_bounded_in_total_not_per_probe: 50 silent peers, probe 100ms, total 300ms -> returns <1.5s. Mutation (neuter the budget check) -> 5.06s, assertion fails.
- a_faulting_peer_abandons_its_remaining_chunks: 2-chunk (257-key) closure vs a counting faulting peer -> 1 probe. Mutation (continue-peers -> continue) -> 2 probes, assertion fails.

GATE (nix dev shell): cargo test -p daemon-core -p daemon ALL PASS; cargo fmt --check clean; cargo clippy -p daemon-core -p daemon --all-targets -- -D warnings clean; scripts/check-no-floats.py clean; just e2e ALL 5 SCENARIOS PASSED incl s6-p2p (11/11, 75.2s total).

HARD CONSTRAINT honored: PROBE_TIMEOUT unchanged; the fix is a TOTAL deadline + per-peer abandonment, not a raised/multiplied per-probe timeout. No FROZEN surface touched.

LIMITS/FOLLOW-UPS: 30s is a provisional internal default, not the caller budget (TASK-100 supersedes). Lands with TASK-100 which re-shapes this call. Deadline granularity is per-chunk boundary (a single in-flight probe still runs up to its clamped bound), which is exactly the intended precision. README.md was already dirty pre-task and left untouched.
<!-- SECTION:FINAL_SUMMARY:END -->
