---
id: TASK-107
title: >-
  Batch-path log hygiene and two small clarity defects (TASK-91 deferred
  findings)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 14:07'
updated_date: '2026-08-16 03:59'
labels:
  - wave-2b
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Three findings from the TASK-91 DEEP gate, all deferred there to keep the fix cycle bounded. None is a correctness defect; all three are cheap and were verified by review, not guessed.

M3 - UP TO 256 eprintln! PER BATCH. AvailabilityIndex::answer_batch logs one line per key that could not be answered, and the compatibility shim in PeerQuery::query_batch logs one line per failed key. A responder whose store has been GC'd out from under it therefore emits 256 lines for ONE message, and a peer can provoke that with one 91-byte query. Aggregate to a single line plus a count (and, if useful, the first offending key), which is both quieter and more readable than 256 near-identical lines.

M4 - A TEST NAME THAT OVERSTATES WHAT IT PROVES.
discovery.rs::the_in_process_batch_really_crosses_the_wire_not_the_shim proves the batch is ENCODED ONCE (it asserts the native transport refuses an over-cap batch, which only a real encode can do). It does NOT prove one network round trip - there is no network in that test. Rename to say what it checks, e.g. the_in_process_batch_is_encoded_once_not_looped_per_key.

M5 - entry().or_insert_with() USED FOR ITS SIDE EFFECT, THEN LOOKED UP AGAIN.
DirectDiscovery::resolve_many builds its position map with an or_insert_with closure that pushes onto the 'pending' vector as a side effect, then immediately does a second get_mut on the same key. Both the side-effecting closure and the double lookup are avoidable; match on the Entry directly.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The batch path logs at most a bounded number of lines per message, with the count reported; proven by a test that provokes many per-key faults
- [x] #2 the_in_process_batch_... is renamed to state what it actually proves
- [x] #3 resolve_many builds its position map without a side-effecting or_insert_with and without the second lookup
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PLAN (in progress). M3: split the batch-fault logging from its computation so it is testable in-process. answer_batch -> a private answer_batch_reporting core that RETURNS the operator notes (Vec<String>); the public method emits them. The per-key Err arm now ACCUMULATES a count + first offender and emits ONE aggregate line, not one eprintln per key. Same for the PeerQuery::query_batch shim, factored into a crate-private run_query_batch_shim returning its notes. Bites: a unit test provokes many per-key faults (via a limited-budget answer_batch over lied/mismatched keys, and via a faulting mock for the shim) and asserts notes.len() is bounded, not ~N. M4: rename the_in_process_batch_really_crosses_the_wire_not_the_shim -> the_in_process_batch_is_encoded_once_not_looped_per_key; update 2 refs in daemon/examples/closure_discovery.rs. M5: rebuild resolve_many position map by matching on the Entry (no side-effecting or_insert_with, no second get_mut); must compose with the TASK-106 break/continue peers control flow. Gate: cargo test -p daemon-core -p daemon, fmt, clippy -D warnings, check-no-floats; confirm TASK-106 bites still green.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE. M3 (AC#1): batch-path fault logging aggregated. answer_batch split into a private answer_batch_reporting core that RETURNS a Vec<String> of operator notes (at most one line per fault CLASS, each naming the COUNT + first offender); the public method only emits them. Before: one eprintln per faulting key (bounded post-task-104 to MAX_BATCH_DERIVE_WORK=16 for the responder, but up to MAX_BATCH_HOLD_KEYS=256 for the shim). After: 1 aggregated fault line per batch. Same treatment for the PeerQuery::query_batch compatibility shim, factored into a crate-private run_query_batch_shim returning its notes. Two bites assert notes.len() is bounded not N: availability::tests::batch_fault_logging_is_aggregated_not_one_line_per_key (16 real NarHash-mismatch faults -> 1 fault line, count reported; +1 deferral line) and discovery::tests::shim_batch_fault_logging_is_aggregated_not_one_line_per_key (256 per-key answer faults -> 1 line, count reported). Behaviour unchanged: every faulting/deferred key still answers Absent, all-absent batch offers nothing. M4 (AC#2): renamed the_in_process_batch_really_crosses_the_wire_not_the_shim -> the_in_process_batch_is_encoded_once_not_looped_per_key (it proves encoded-once via the over-cap refusal; there is no network in the test); updated 2 refs in daemon/examples/closure_discovery.rs. M5 (AC#3): resolve_many position map now matches on Entry (Occupied appends a position; Vacant pushes to pending once + inserts vec![i]) - removed the side-effecting or_insert_with closure and the second get_mut; composes with the TASK-106 break/continue-peers flow, both TASK-106 bites (resolve_many_is_bounded_in_total_not_per_probe, a_faulting_peer_abandons_its_remaining_chunks) still green. GATE (nix shell): cargo test -p daemon-core -p daemon exit 0 (daemon_core lib 209 passed/1 pre-existing ignored; all integration + daemon green); cargo fmt --check clean; cargo clippy --workspace --all-targets -D warnings clean; scripts/check-no-floats.py clean. just e2e NOT run (log/clarity/refactor only, no serving-path or wire change). LIMITS: the two M3 bites observe the RETURNED notes vector (deterministic, in-process) rather than capturing real stderr, so they prove the aggregation decision is bounded and bite a revert-to-per-key mutation via notes.len(); a hypothetical future inline eprintln added OUTSIDE answer_batch_reporting/run_query_batch_shim would not be caught. No wire/behaviour/FROZEN-surface change.
<!-- SECTION:FINAL_SUMMARY:END -->
