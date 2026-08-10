---
id: TASK-125
title: 'TOURNAMENT Stage A: uncompressed Iroh versus BitTorrent qualification'
status: To Do
assignee: []
created_date: '2026-08-10 22:30'
updated_date: '2026-08-10 22:57'
labels:
  - tournament
  - diagnostic
  - uncompressed
  - e2e
  - wave-2c
dependencies:
  - TASK-14
  - TASK-43
  - TASK-46
  - TASK-88
  - TASK-94
  - TASK-112
  - TASK-113
  - TASK-114
  - TASK-119
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Run the first comparative tournament only after the production-shaped Iroh path has been measured, the raw BitTorrent vertical slice works, and cross-backend property/fuzz gates exist. Compare upstream-only, raw Iroh and raw BitTorrent using the frozen TASK-114 manifest. This is a qualification of harness attribution, discovery traces, transfer correctness and failure behavior. It is structurally forbidden from selecting production policy; compression may already exist for Iroh but is disabled in every Stage-A arm.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Upstream-only, raw Iroh and raw BitTorrent run as randomized/counterbalanced paired full-stack real-Nix arms with fresh client/store/cache/discovery state and recorded seeds.
- [ ] #2 All artifacts carry diagnostic_uncompressed=true, omit policy_candidate fields, and are rejected by the Stage-B policy reader; a bite proves Stage-A data cannot fit or select a default.
- [ ] #3 Provider-side peer bytes, upstream-byte contrast, S1 identity, bounded S2 fallback, discovery/control bytes, resolve/bootstrap, TTFB, latency, CPU/RAM/disk/fds and path attribution are recorded with distinct units.
- [ ] #4 Iroh and BitTorrent receive equivalent scenario inputs and resource limits, while backend-specific unsupported cells and third-party dependencies remain explicit rather than normalized away.
- [ ] #5 A/A calibration, invalid-run accounting, minimum N/detectable effect, shaping anti-vacuity and dead/corrupt-provider bites pass before results are published.
- [ ] #6 The report states only qualification findings and raw-protocol tradeoffs. Winner/default/adaptive-policy language makes the gate fail.
- [ ] #7 Stage A can read only diagnostic/development inputs; holdout generation and namespaces are unavailable, and an attempted access is a gate failure recorded in the artifact.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The user explicitly allows the first tournament without compression. Stage B later compares raw and compressed options.
<!-- SECTION:NOTES:END -->
