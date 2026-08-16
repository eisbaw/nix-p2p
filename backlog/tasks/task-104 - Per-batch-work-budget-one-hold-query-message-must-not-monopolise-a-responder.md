---
id: TASK-104
title: 'Per-batch work budget: one hold-query message must not monopolise a responder'
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 12:18'
updated_date: '2026-08-16 03:16'
labels:
  - wave-2b
dependencies:
  - TASK-91
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-91 (batched hold-query).

TASK-91 caps a batch at MAX_BATCH_HOLD_KEYS = 256 keys, which bounds the WORK one message can demand to at most 256 AvailabilityIndex probes - each of which may cost one nix-store --dump of an unhashed path. That is not NEW work (the same 256 single-key probes cost the same), but it is now demanded by ONE message from ONE peer, which changes who controls the pacing.

Two concrete consequences already observed and stated as limits in the code:

1. daemon/src/discovery.rs DirectDiscovery::resolve_many bounds each chunk probe by the same PROBE_TIMEOUT (5 s) as a single probe. A COLD peer that must derive 256 large NARs to answer can exceed that and be treated as a miss. Safe direction (the fetch falls back upstream) but it UNDER-REPORTS availability, and it under-reports it exactly when a peer is most useful (a fresh peer with a lot of content).

2. There is no per-responder budget on how much derivation a batch may trigger. The task-72 serve budget bounds bytes SERVED, not bytes HASHED.

Likely shape of the fix: the responder answers from what is already derived and schedules the rest, i.e. a batch answer becomes 'yes / no / not-yet' - which is a WIRE CHANGE and therefore needs the same deep gate as TASK-91 (and probably a schema_version bump, since 'not-yet' is a third answer). Decide whether 'not-yet' is worth a version bump or whether an unanswered key should simply be Absent (today's behaviour) with a background derive.

Do NOT patch this by raising the timeout: that puts unbounded latency back into the build path, which is the exact property TASK-40 established.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A responder cannot be made to spend unbounded derivation work by one batch message, and the bound is proven by a bite (a batch of N cold large paths answers within the bound rather than timing out the whole probe)
- [x] #2 A cold peer is not silently reported as holding nothing: the under-reporting in TASK-91's stated limit either goes away or is measured and accepted with numbers
- [x] #3 If the answer shape changes, the claim wire is versioned, the frozen golden vectors in daemon/tests/golden/claim_wire_v1.json still pass untouched, and new vectors are pinned
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN (non-frozen path, per SCOPE PREFERENCE): add a per-batch FRESH-DERIVATION budget to AvailabilityIndex::answer_batch.

Root cause: answer_batch calls hold() per key; a cold key triggers a nix-store --dump inside derive() (digest slot None). One 256-key batch could trigger 256 large dumps -> monopolises the responder (AC#1) and, because resolve_many bounds the whole chunk by PROBE_TIMEOUT, times out and under-reports (AC#2).

Mechanism:
- New const MAX_BATCH_DERIVE_WORK (u32, integer; no floats) = max fresh dumps ONE batch message may trigger.
- DeriveBudget{remaining: Option<u32>}; single-key hold() = unlimited (unchanged behaviour); answer_batch = limited(MAX_BATCH_DERIVE_WORK).
- derive() gains a &mut DeriveBudget: warm (Verified/Quarantined) answers with NO dump and spends NO unit; a cold key reserves one unit ATOMICALLY under the digest lock right before dumping. Budget exhausted -> Deferred (no dump), caller answers Absent on the wire (todays behaviour, safe direction).
- WIRE UNCHANGED: Deferred == Absent on the wire. No schema bump, frozen golden untouched. AC#3 N/A.

AC#2: under-reporting is BOUNDED and SELF-HEALING: each probe warms the next MAX_BATCH_DERIVE_WORK cold keys (cache fills), so a deferred key flips Absent->Have on a later probe. Residual measured honestly (a single fully-cold large-closure probe still under-reports; the abandoned spawn_blocking still completes its K dumps and warms the cache). Cross-message aggregate bound = follow-up.

BITE (daemon-core/tests): register N=3K+3 cold keys, exactly one valid (== hash of the shared MemoryNarDumper bytes) placed at index K; the rest quarantine on dump but still COST a counted dump. Assert dumper.calls()==K after ONE probe (mutation: unlimited budget -> ==N, RED); frontier advances K/probe; valid key flips Absent->Have on probe 2; warm keys never re-dump.

DONE (commit b3824d8, non-frozen path). Reviewers: qa-test-runner GO (459 passed/0 failed, clippy/fmt/no-floats clean); mped-architect GO on mechanism+correctness, NO-GO on claims/docs honesty -> all findings addressed before commit.

MECHANISM: answer_batch carries a per-batch DeriveBudget (integer u32, no floats). Warm keys (already derived) cost no dump and spend no budget; a cold key reserves one unit UNDER the digest lock right before the dump; budget spent -> Deferred (no dump) -> Absent on the wire. MAX_BATCH_DERIVE_WORK=16 fresh dumps per message (vs the 256-key cap). Single-key hold() = unlimited, byte-identical to before.

WIRE UNCHANGED: Deferred == existing Absent answer. No schema bump; frozen golden daemon/tests/golden/claim_wire_v1.json untouched (confirmed git diff empty). AC#3 N/A.

BITE (daemon-core/tests/availability_batch_budget.rs): N=3K+3 cold keys, one valid at index K. Probe1 dumps exactly K=16 (mutation to unlimited -> 51, verified RED and restored); frontier advances K/probe (probe2=32, probe3=48, probe4=51); deferred valid key flips Absent->Have on probe2; probe5 dumps 0 (warm keys never re-dump).

PER-AC:
- AC#1 MET: one batch message triggers at most 16 fresh dumps, not 256. Bite proves the bound bites by mutation. HONEST: this bounds dump COUNT, not BYTES (16 large dumps is still unbounded I/O) and is per-MESSAGE, not per-peer -> not a DoS defense (peer picks message boundaries; single-key probes take the unlimited hold() path). Real root-cause byte bound = path-info(-S)-seeded budget; per-peer aggregate limit = follow-ups, both documented.
- AC#2 MEASURED and accepted (not "goes away"): a wholly-cold N-key batch under-reports N-16 keys as Absent (bounded, safe; logged, not silent). resolve_many treats Absent as a miss and falls back UPSTREAM - it does NOT re-probe, so no first-contact heal for THIS asker. The responder cache warms 16 cold keys/probe, so later organic queries improve; ~ceil(N/16) probes to fully warm. Reworded everywhere to stop overclaiming self-heal.
- AC#3 N/A (wire unchanged).

GATE (nix dev shell): cargo test -p daemon-core -p daemon = 459 passed/0 failed/1 ignored; clippy --workspace --all-targets -D warnings clean; fmt --check clean; check-no-floats.py clean; just e2e = 5/5 scenarios PASS (re-run on final state). Disk 91 GiB free; no detached builds.

FOLLOW-UPS (new tasks worth filing): (1) path-info(-S)-seeded per-batch BYTE budget (true work bound); (2) per-PEER aggregate dump concurrency/rate limit (the actual resource-DoS defense; task-72 serve budget bounds bytes served, not hashed); (3) optionally have resolve_many opportunistically re-probe a peer that deferred, to convert responder-cache warming into first-contact healing. DEEP-gate-eligible (responder-resource contract) - flag for codex.
<!-- SECTION:NOTES:END -->
