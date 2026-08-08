---
id: TASK-34
title: 'Flaky test: testproxy connection_reset_fault_yields_no_response'
status: Done
assignee: []
created_date: '2026-08-08 16:53'
updated_date: '2026-08-08 17:58'
labels: []
dependencies:
  - TASK-2
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Noted during task-11 (not caused by it): testproxy/tests/faults.rs::connection_reset_fault_yields_no_response intermittently fails, passes on rerun. A flaky test erodes gate trust (a real failure looks like flake, a flake blocks a good commit). Diagnose the race (likely a timing assumption on when the reset lands vs when the client reads) and make it deterministic or mark+fix.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Root cause identified (the timing race)
- [x] #2 Test made deterministic - runs green 20x in a row
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
CLOSED by task-13. Root cause: the testproxy integration test helper (testproxy/tests/common/mod.rs::raw_request) classified ONLY io::ErrorKind::ConnectionReset as a valid 'no response' observation; the connection-reset fault tears the socket at an arbitrary point relative to the client's write/read, so under load the abnormal close surfaces as ConnectionAborted / BrokenPipe / UnexpectedEof (or on the write leg), which the old helper let ?-propagate into the test's .unwrap() -> the intermittent panic. Fix: classify the whole connection-dropped family on BOTH the write and read legs as a deterministic no_response(). Verified 25x green in a row; full faults binary green. Not a product bug - the daemon/testproxy behaviour was correct; the TEST oracle was too narrow.
<!-- SECTION:NOTES:END -->
