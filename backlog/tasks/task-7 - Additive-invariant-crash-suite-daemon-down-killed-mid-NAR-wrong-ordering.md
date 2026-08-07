---
id: TASK-7
title: 'Additive-invariant crash suite: daemon down, killed mid-NAR, wrong ordering'
status: To Do
assignee: []
created_date: '2026-08-07 21:55'
labels: []
dependencies:
  - TASK-5
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
S2 made into standing e2e scenarios: (a) daemon absent at nix-daemon store-open; (b) daemon SIGKILLed at ~50% of a >=100MB NAR transfer; (c) regression guard on nix-cache-info priority (daemon must actually be preferred, and its loss must actually fall back). Architect round-2 finding: mid-stream crash yields truncated NAR - Nix must hash-fail and refetch from fallback, store never corrupted.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All three scenarios green in just e2e; kill-mid-transfer shows truncated-transfer event in test-proxy log AND successful fallback build (both asserted)
- [ ] #2 Post-crash: nix-store --verify-path (or equivalent) proves no corrupt store path exists
- [ ] #3 Scenarios run against compose harness; marked for reuse by the VM layer
<!-- AC:END -->
