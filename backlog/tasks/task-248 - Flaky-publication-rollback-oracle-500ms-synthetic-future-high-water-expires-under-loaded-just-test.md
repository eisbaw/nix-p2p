---
id: TASK-248
title: >-
  Flaky publication rollback oracle: 500ms synthetic future high-water expires
  under loaded just test
status: Done
assignee: []
created_date: '2026-08-18 05:48'
updated_date: '2026-08-18 06:34'
labels:
  - flaky
  - test-infra
  - clock
  - gate
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Exposed by the mandatory TASK-177 pre-commit QA run. fabric-iroh::iroh_publication_authority::tests::expired_pending_is_not_resurrected_and_high_water_survives_clock_rollback seeds a high-water only 500,000 microseconds ahead of wall clock, performs durable state setup, then expects recovery sequence == high_water + 1. Under the loaded workspace run, wall time advanced about 553ms, so the rollback precondition had expired and production correctly selected the newer wall clock; the exact assertion failed by 53,306 microseconds. The isolated rerun passed, confirming timing sensitivity. Fix the oracle at its owning boundary. Do not accept a lucky rerun, an ignored test, an unbounded stress loop, or an arbitrary sleep/retry.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Root-cause and mechanically distinguish an expired synthetic rollback precondition from a production high-water sequencing defect.
- [x] #2 Make the rollback scenario deterministic, preferably with a clock seam; if a real-clock window remains, bind it to the actual operation deadline and assert the rollback precondition before recovery so scheduler load cannot silently change the tested branch.
- [x] #3 Preserve a biting negative control: a mutation that ignores the durable future high-water or resurrects the expired pending record must fail, while current production logic passes.
- [x] #4 The focused test, full fabric-iroh library tests, and canonical workspace test gate pass without retrying the failing assertion for a lucky result.
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Commit 5149462 adds a private publication wall-clock seam used consistently by recovery, sequencing, visibility, and refresh scheduling. The regression freezes time, reaches the expired-pending branch with matching revisions/locations, preserves the durable high-water, and retains resurrection/sequence/request-count bites. Focused test 1/1, full workspace 1,125 passed, and just e2e 9/9 scenarios passed without retry.
<!-- SECTION:FINAL_SUMMARY:END -->
