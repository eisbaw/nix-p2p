---
id: TASK-125
title: 'TOURNAMENT Stage A: uncompressed Iroh versus BitTorrent qualification'
status: To Do
assignee: []
created_date: '2026-08-10 22:30'
updated_date: '2026-08-14 21:48'
labels:
  - tournament
  - diagnostic
  - uncompressed
  - e2e
  - wave-2c
  - deferred-pending-202
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
priority: low
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

COMPASS 2026-08-14 (stale-framing flag): this Stage-A tournament is framed 'uncompressed Iroh vs BitTorrent' but Wave-2c makes libp2p-stream the PRIMARY transport (TASK-157 shipped) and libp2p-kad the mandatory discovery layer (TASK-103). Racing iroh vs BitTorrent while EXCLUDING the default libp2p-stream arm measures two non-default transports. RE-SCOPE before this runs: include libp2p-stream as the reference arm, or explicitly justify its omission. Same iroh-worded staleness TASK-198 records for profile_p2p.py + iroh_throughput.rs. ALSO: the value-thesis answer (TASK-99: compression is the binding constraint, near-parity on constrained uplinks, LAN needs pipelining) means the tournament's axis shifted from transport-choice to compression-throughput+discovery — this task is rung-6 and correctly parked behind its large dep wall + the pipelining cornerstone (F1).

Deprioritized to Low in the Wave-2c cleanup (2026-08-14): libp2p-PRIMARY trunk proven (libp2p-kad discovery + store-supply + streamed NAR). Per PRD §634-691 (normative owner-direction authority) content discovery is libp2p-kad; iroh is an OPTIONAL transport only. This task belongs to a superseded-discovery / premature-tournament / far-future-BitTorrent / optional-comparator track. Fate confirmed by TASK-202 (owner-gated §693-743 reconcile). Reversible — not deleted; revisit after 202.
<!-- SECTION:NOTES:END -->
