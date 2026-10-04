---
id: TASK-308.2
title: Fix NixOS fallback integration for genuine substituter errors
status: To Do
assignee: []
created_date: '2026-10-04 21:23'
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
- [ ] #1 Shipped configuration passes the new real-Nix failure regression; opt-out behavior is tested.
- [ ] #2 Parallel QA and architecture reviews plus required CI gates pass on the exact implementation tree.
<!-- AC:END -->
