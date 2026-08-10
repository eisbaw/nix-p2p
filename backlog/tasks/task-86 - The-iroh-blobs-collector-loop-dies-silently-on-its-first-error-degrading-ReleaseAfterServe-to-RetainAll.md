---
id: TASK-86
title: >-
  The iroh-blobs collector loop dies silently on its first error, degrading
  ReleaseAfterServe to RetainAll
status: To Do
assignee: []
created_date: '2026-08-09 23:03'
updated_date: '2026-08-10 22:35'
labels:
  - forward-carried-from-task-72
dependencies:
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FORWARD-CARRIED FROM TASK-72 (mped-architect review, S5). UPSTREAM BEHAVIOUR, verified in the pinned source: iroh-blobs 0.103 src/store/gc.rs run_gc() does

    if let Err(e) = gc_run_once(&store, &mut live).await { error!(...); break; }

- the loop EXITS, permanently. The task-61 supply model rests entirely on that loop: once it is gone, StoreRetention::ReleaseAfterServe silently becomes RetainAll and the node starts holding everything it serves, which is precisely the property task-72 removed.

AND WE CANNOT SEE IT. There is no tracing subscriber installed anywhere in daemon/src, so upstream's error!() goes nowhere. The only observable signal is IROH-STORE-RESIDENT drifting upward, and nothing watches it.

WHAT IS NEEDED (the daemon should own liveness for a loop it depends on and cannot observe):
  * a residency watchdog: if store residency stays above the in-flight total for longer than N sweep intervals, say so LOUDLY on stdout with the same IROH- prefix convention the harness already parses;
  * and/or install a tracing subscriber so upstream's own error is not swallowed;
  * consider whether the daemon should drive sweeps itself rather than delegate to a task whose death it cannot detect - note gc_run_once is NOT public (store::gc is a private module; only GcConfig/ProtectCb/ProtectOutcome are re-exported), so 'drive it ourselves' currently means a custom Store impl.

BITE IT BY MUTATION: inject a store error (or a supplier that makes gc_run_once fail) and prove the watchdog fires. A watchdog that has never been seen to fire is not a watchdog.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A collector that has stopped is DETECTED and reported, not inferred later from a memory graph
- [ ] #2 The detector is proven by mutation: the collector is deliberately killed and the alarm fires on a named check
<!-- AC:END -->
