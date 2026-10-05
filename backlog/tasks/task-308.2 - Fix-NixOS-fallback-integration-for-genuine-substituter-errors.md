---
id: TASK-308.2
title: Fix NixOS fallback integration for genuine substituter errors
status: Done
assignee: []
created_date: '2026-10-04 21:23'
updated_date: '2026-10-05 07:47'
labels: []
dependencies: []
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Use the reproduction to correct shipped integration, preserving HTTP semantics: actual 404 stays 404, transport failure remains 502, upstream 503 remains 503. Make the Nix fallback policy explicit and overridable, document any source-build behavior, preserve require-sigs and trusted keys. Remove inaccurate unconditional fallback claims from affected documentation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Shipped configuration passes the new real-Nix failure regression; opt-out behavior is tested.
- [x] #2 Parallel QA and architecture reviews plus required CI gates pass on the exact implementation tree.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation a11d6ee7819a34cc886312c972191d42b00755db sets overridable fallback=true only when the module is enabled; signatures, trusted keys, HTTP statuses and explicit opt-out are preserved. Parallel QA and architecture reviews passed. CI run 37240672888 reports the two-version metadata regression step successful; build/lint/unit/commit-message and audit jobs also passed. Default/full E2E completion is still pending, so this task remains open. The user subsequently explicitly authorized immediate deployment before completion of the remaining gates. Deployment health is distinct from E2E proof; no live-host E2E tests were run.

Final verification: CI run 37240672888 completed successfully on exact implementation a11d6ee. Targeted regression 204/204, default E2E 19/19 scenarios, full E2E 49/49 scenarios; build/lint/unit/commit-message and audit jobs passed. Required parallel QA/architecture reviews passed before the draft implementation commit. All three requested systems were activated on this revision, with active daemons, responding localhost cache endpoints, fallback=true and require-sigs=true. The separate routed-upstream restriction issue remains TASK-308.3 and is not fixed by client fallback.
<!-- SECTION:NOTES:END -->
