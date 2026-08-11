---
id: TASK-101
title: OPTIONAL tracker comparator behind ContentDiscovery
status: To Do
assignee: []
created_date: '2026-08-10 09:27'
updated_date: '2026-08-11 20:02'
labels:
  - iroh
  - discovery
  - tracker
  - optional
  - comparison
  - tournament
dependencies:
  - TASK-83
  - TASK-89
  - TASK-100
  - TASK-102
  - TASK-103
  - TASK-115
  - TASK-134
  - TASK-135
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Optionally integrate the tracker service behind ContentDiscovery as a centralized comparison mechanism for later measurements and tournament scenarios. This task is not on the production qualification path and cannot satisfy decentralized NAR-to-provider discovery. It must remain independently default-off and clearly report its central service dependency. TASK-103 is the mandatory content-discovery implementation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Tracker lookup and publication are separate default-off ContentDiscovery capabilities with typed bounded outcomes and no implicit relay LAN DHT or node publication.
- [ ] #2 Publication consumes TASK-102 and daemon-originated current-run eligibility state while query-only mode emits zero announces.
- [ ] #3 Exact-key lookup returns bounded provider NodeIds and offers without dialable addresses inventory enumeration or unasked holdings.
- [ ] #4 Failure outage expiry lying service and address-resolution errors remain typed and bounded and are never converted to a clean MISS.
- [ ] #5 Evidence labels the tracker as centralized and optional and no artifact can be substituted for decentralized-content-discovery-v1 or TASK-132 qualification.
- [ ] #6 Tournament outputs may compare tracker latency availability privacy and operating cost against decentralized discovery after TASK-103 passes.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Demoted by owner requirement on 2026-08-11: a central tracker is optional comparison infrastructure only. Do not schedule before the mandatory TASK-126 to TASK-103 path.
<!-- SECTION:NOTES:END -->
