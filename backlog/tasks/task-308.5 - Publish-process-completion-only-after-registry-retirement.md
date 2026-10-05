---
id: TASK-308.5
title: Publish process completion only after registry retirement
status: In Progress
assignee: []
created_date: '2026-10-05 09:17'
updated_date: '2026-10-05 10:00'
labels: []
dependencies: []
references:
  - 'https://github.com/eisbaw/nix-p2p/actions/runs/37286832002/job/111687736122'
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
CI on 94a2274 failed cancellation_reaps_with_a_full_stream_receiver: job.wait returned while registry.active_len was still 1. run_worker publishes its result and notifies waiters before removing its child-free registry entry, so a completed job can remain observable as active. This blocks the routed-upstream dogfooding rollout.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Child-free registry retirement precedes result visibility for both polling and blocking waiters.
- [x] #2 Existing cancellation and panic cleanup tests pass without adding sleeps or weakening their assertions.
- [ ] #3 Build, lint and required Podman/NixOS VM CI gates pass on the corrected tree.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fix retires the child-free registry entry before result publication and notification. PGID clearing and operational-failure recording still precede retirement; locks are acquired sequentially. Existing cancellation regression is retained unchanged. Architecture review approved. Pinned rustfmt check and git diff --check passed; no local FAST/BROAD/E2E execution. Exact-tree CI is pending under the disclosed CI-only bootstrap workflow.

CI revision 53e2e96206f6f59ab2454f00cbdf3507a0301af4 passed the complete fast gate: build, lint, tests and commit-message policy. Both cancellation_reaps_with_a_full_stream_receiver and post_spawn_panic_reaps_child_and_grandchild_before_unregistering passed with their assertions intact. The routed NixOS VM passed on this revision too. Required normal/full Podman gates remain pending, so AC3 and rollout remain open. Evidence: https://github.com/eisbaw/nix-p2p/actions/runs/37289336993/job/111695978730
<!-- SECTION:NOTES:END -->
