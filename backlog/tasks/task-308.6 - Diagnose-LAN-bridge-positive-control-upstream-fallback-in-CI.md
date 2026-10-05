---
id: TASK-308.6
title: Diagnose LAN bridge positive-control upstream fallback in CI
status: In Progress
assignee: []
created_date: '2026-10-05 10:10'
updated_date: '2026-10-05 10:13'
labels: []
dependencies: []
references:
  - 'https://github.com/eisbaw/nix-p2p/actions/runs/37289336993/job/111695978220'
parent_task_id: TASK-308
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
On revision 53e2e96 the default Podman E2E suite passed 18 of 19 scenarios, but libp2p-lan-share-isolation-bridge failed its positive-control provenance assertion: helper H realized the correct output with one LAN-upstream NAR request instead of peer-only transfer. The provider-announcement gate and fixed convergence sleep had completed. Current teardown discards daemon logs for this assertion failure, so the exact discovery/transfer cause is not yet known. This blocks deployment; the full suite did not run.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Retain provider/helper failure diagnostics before topology teardown without weakening the zero-upstream assertion.
- [ ] #2 Identify and correct the observed discovery, serving, or test-readiness cause using CI evidence.
- [ ] #3 Required default and full Podman suites plus routed NixOS VM pass on the final revision before deployment.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Read-only reviews found no direct causal path from the recent EOF or completion-order changes: this topology serves static seed files, and H uses the unchanged NarStreamBody for peer bodies. This does not prove a flake. Diagnostic patch retains the single fresh realization, fixed wait and zero-upstream assertion; captures client output, one statistics snapshot, daemon logs, provider/helper states and proxy request records before teardown. CI will run this scenario first, then retain the normal and full gates. No speculative readiness or product fix is claimed.
<!-- SECTION:NOTES:END -->
