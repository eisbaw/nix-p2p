---
id: TASK-107
title: >-
  Batch-path log hygiene and two small clarity defects (TASK-91 deferred
  findings)
status: To Do
assignee: []
created_date: '2026-08-10 14:07'
labels:
  - wave-2b
dependencies: []
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
- [ ] #1 The batch path logs at most a bounded number of lines per message, with the count reported; proven by a test that provokes many per-key faults
- [ ] #2 the_in_process_batch_... is renamed to state what it actually proves
- [ ] #3 resolve_many builds its position map without a side-effecting or_insert_with and without the second lookup
<!-- AC:END -->
