---
id: TASK-135
title: OPTIONAL operate the content-discovery tracker service safely
status: To Do
assignee: []
created_date: '2026-08-11 05:50'
updated_date: '2026-08-11 19:55'
labels:
  - iroh
  - discovery
  - tracker
  - optional
  - comparison
  - tournament
  - service
  - persistence
  - privacy
dependencies:
  - TASK-90
  - TASK-102
  - TASK-114
  - TASK-115
  - TASK-134
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Optional post-DHT experiment. Operate the centralized tracker service only to measure it against decentralized discovery in later tournament scenarios. Own service lifecycle verified leases persistence health and resource bounds. It cannot qualify production or satisfy TASK-103 or TASK-132 and must remain default-off with its central dependency explicit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Validate a passing TASK-134 protocol artifact before service code or evidence runs.
- [ ] #2 Expose explicit listen state health bounded request key provider concurrency rate work and storage limits graceful shutdown and no public default deployment.
- [ ] #3 Use signed idempotent monotonic bounded leases with refresh withdrawal expiry replay rejection concurrent-provider preservation and crash-safe persistence.
- [ ] #4 Verify announcers under bounded deadlines and reject lying unreachable stale replayed corrupted or out-of-band publications without converting failures to MISS.
- [ ] #5 Exact-key lookup returns bounded provider NodeIds and offers without addresses inventory enumeration or unasked holdings and lookup and publication remain independently authorized.
- [ ] #6 Tournament evidence labels local versus public deployment authority and reports latency availability privacy operating cost and failure behavior without production qualification claims.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deferred comparison infrastructure. It is deliberately absent from the mandatory TASK-126 to TASK-103 to TASK-132 chain.
<!-- SECTION:NOTES:END -->
