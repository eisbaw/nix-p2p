---
id: TASK-114
title: >-
  GROUNDING: two-stage Iroh/BitTorrent tournament contract and falsifiable
  scenario manifest
status: To Do
assignee: []
created_date: '2026-08-10 22:14'
updated_date: '2026-08-10 22:56'
labels:
  - grounding
  - tournament
  - wave-2c
dependencies:
  - TASK-42
  - TASK-51
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Reconcile PRD.md and TESTING.md into the durable negative-feedback contract before implementing more discovery or transport. Stage A is an uncompressed diagnostic qualification; Stage B is the policy-grade training tournament with upstream, Iroh and BitTorrent raw/compressed-or-evidenced-unsupported arms. Discovery, transport and full-stack real-Nix results remain separate. Predeclare objectives, hard constraints, scenario generation and privacy/resource observables. Holdout material must not exist until implementations, interpreter and candidate artifacts are frozen; only its generation contract is declared now. Losing to upstream or rejecting public P2P is valid.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 PRD.md is reconciled with this wave: discovery substrate is evidence-gated rather than pre-set DHT-authoritative, fresh installs do not publish/join public networks by default, Iroh-first sequencing is explicit, and the latency/egress kill criterion is rewritten as a context-specific decision rule rather than both descoped and thesis-killing.
- [ ] #2 TESTING.md defines the four strongest signals: no-injection Iroh build, no-injection BitTorrent build, diagnostic raw Stage A, and Stage-B training plus later holdout. Fresh state, provider bytes, upstream contrast, S1 and bounded S2 are mandatory.
- [ ] #3 A versioned scenario-generation contract defines workload/store placement, topology strata, RTT/bandwidth/loss/jitter, NAT/relay, Nix concurrency, holder count, churn/herd/lying/slow peers and leech fraction; unsupported cells are explicit.
- [ ] #4 For each deployment profile the PRD/manifest predeclare exactly one primary lexicographic/scalar decision rule and numeric margin (including full-build latency versus upstream egress/provider upload), with S1/S2/privacy and numeric resource ceilings as hard constraints; no acceptable candidate is valid.
- [ ] #5 Stage A contains upstream-only, raw Iroh and raw BitTorrent component/full-stack arms, is labelled diagnostic_uncompressed and is structurally rejected by policy fitting.
- [ ] #6 Stage B training contains upstream-only plus Iroh raw/compressed and BitTorrent raw/compressed-or-evidenced-no-go; unsupported cells remain in the matrix.
- [ ] #7 Validity requires randomized/counterbalanced paired trials, recorded seeds, all invalid/excluded runs, A/A calibration, minimum N/detectable effect, confidence intervals, bottleneck isolation and METRIC_UNUSABLE above the decision margin.
- [ ] #8 Metrics keep compressed cache bytes, peer socket bytes, NarSize, hedge/prefetch waste, discovery/control bytes, build latency percentiles, TTFB, bootstrap/resolve, CPU/RAM/disk/fds, provider upload, success/fallback and confirmed network path in distinct units.
- [ ] #9 Every arm has anti-vacuity: disabled discovery restores upstream egress, dead provider yields bounded fallback, corruption fails S1/gate-2, neutralized shaping is detected, and Stage-A input is rejected by the fitter.
- [ ] #10 Only development/training scenarios are materialized before TASK-123. The holdout distribution/generator and reveal procedure are versioned now, but exact holdout IDs/seeds/topologies are generated after code/interpreter/candidate hashes freeze; TASK-88/125/80/122/44 access attempts fail.
- [ ] #11 Discovery privacy observables record published keys/records, query recipients and IP/NodeId exposure, tracker/DNS/relay/Mainline dependencies, client-only/server participation and whether consume-only suppresses publication, serving and/or lookup leakage.
- [ ] #12 The contract names decision owners and task/artifact boundaries; changing objective, constraints, generator or profile after training starts creates a new experiment version and fresh holdout.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave-2c design-for-test and PRD reconciliation gate. Preserve S1/S2. Holdout data does not exist before TASK-123; only a frozen generation/reveal protocol does.
<!-- SECTION:NOTES:END -->
