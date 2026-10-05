---
id: TASK-308.4
title: Recognize completed HTTP bodies without a final empty poll
status: In Progress
assignee: []
created_date: '2026-10-05 08:39'
labels: []
dependencies: []
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The routed-upstream NixOS VM on b947d90 (CI run 37283391060, job 111676920271) successfully realized and verified a fresh signed input-addressed output through both local services in 576ms, with metadata HTTP200 in166ms. Both daemons nevertheless logged substitution-aborted with all296bytes, causing the unchanged completion-provenance oracle to fail. LoggingBody and BoundedBody hide authoritative inner end-of-stream; Hyper can stop polling after a fixed-length final frame. Related completed TASK-31 tests always drain through an extra None poll and miss this boundary.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Regression covers consuming a final fixed-length frame then dropping without another poll, including initially empty bodies.
- [ ] #2 Authoritative EOF reaches accounting through the bound wrapper; partial drops, pending terminal errors and oversized transfers stay aborted, never inferred complete from size equality.
- [ ] #3 Unchanged real multi-node NixOS VM completion-log oracle and required CI gates pass on the fix, with observed evidence recorded.
<!-- AC:END -->
