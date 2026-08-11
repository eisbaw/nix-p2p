---
id: TASK-114
title: >-
  GROUNDING: two-stage Iroh/BitTorrent tournament contract and falsifiable
  scenario manifest
status: Done
assignee:
  - '@me'
created_date: '2026-08-10 22:14'
updated_date: '2026-08-11 02:29'
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
- [x] #1 PRD.md is reconciled with this wave: discovery substrate is evidence-gated rather than pre-set DHT-authoritative, fresh installs do not publish/join public networks by default, Iroh-first sequencing is explicit, and the latency/egress kill criterion is rewritten as a context-specific decision rule rather than both descoped and thesis-killing.
- [x] #2 TESTING.md defines the four strongest signals: no-injection Iroh build, no-injection BitTorrent build, diagnostic raw Stage A, and Stage-B training plus later holdout. Fresh state, provider bytes, upstream contrast, S1 and bounded S2 are mandatory.
- [x] #3 A versioned scenario-generation contract defines workload/store placement, topology strata, RTT/bandwidth/loss/jitter, NAT/relay, Nix concurrency, holder count, churn/herd/lying/slow peers and leech fraction; unsupported cells are explicit.
- [x] #4 For each deployment profile the PRD/manifest predeclare exactly one primary lexicographic/scalar decision rule and numeric margin, including full-build latency versus upstream egress/provider upload; S1/S2/privacy and the existing evidence-backed numeric safety caps are hard constraints, no acceptable candidate is valid, and a complete owner-reviewed TASK-120 numeric upload/RAM/disk/fd/discovery/announcement budget artifact is a fail-closed prerequisite before Stage-B training.
- [x] #5 Stage A contains upstream-only, raw Iroh and raw BitTorrent component/full-stack arms, is labelled diagnostic_uncompressed and is structurally rejected by policy fitting.
- [x] #6 Stage B training contains upstream-only plus Iroh raw/compressed and BitTorrent raw/compressed-or-evidenced-no-go; unsupported cells remain in the matrix.
- [x] #7 Validity requires randomized/counterbalanced paired trials, recorded seeds, all invalid/excluded runs, A/A calibration, minimum N/detectable effect, confidence intervals, bottleneck isolation and METRIC_UNUSABLE above the decision margin.
- [x] #8 Metrics keep compressed cache bytes, peer socket bytes, NarSize, hedge/prefetch waste, discovery/control bytes, build latency percentiles, TTFB, bootstrap/resolve, CPU/RAM/disk/fds, provider upload, success/fallback and confirmed network path in distinct units.
- [x] #9 Every arm has anti-vacuity: disabled discovery restores upstream egress, dead provider yields bounded fallback, corruption fails S1/gate-2, neutralized shaping is detected, and Stage-A input is rejected by the fitter.
- [x] #10 Only development/training scenarios are materialized before TASK-123. The holdout distribution/generator and reveal procedure are versioned now, but exact holdout IDs/seeds/topologies are generated after code/interpreter/candidate hashes freeze; TASK-88/125/80/122/44 access attempts fail.
- [x] #11 Discovery privacy observables record published keys/records, query recipients and IP/NodeId exposure, tracker/DNS/relay/Mainline dependencies, client-only/server participation and whether consume-only suppresses publication, serving and/or lookup leakage.
- [x] #12 The contract names decision owners and task/artifact boundaries; changing objective, constraints, generator or profile after training starts creates a new experiment version and fresh holdout.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Reconcile PRD decisions for private-by-default, evidence-gated discovery, Iroh-first ordering, deployment-specific decisions, and version governance while retaining superseded provenance.
2. Make TESTING.md the versioned two-stage experiment contract: Stage A diagnostic isolation, Stage B policy training, scenario generator, validity/metrics/privacy contracts, anti-vacuity, and delayed holdout reveal.
3. Self-audit all 12 acceptance criteria, record durable notes through backlog CLI, and run nix develop -c just build/lint/test/e2e. Leave the reviewable diff uncommitted for independent QA and architecture review.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## TASK-114 current implementation record

Scope is PRD.md, TESTING.md and this tracker record only. No implementation, holdout material, staging, commit or push was created. Contract versions remain nix-p2p-tournament-v1 and nix-p2p-scenarios-v1. Status and all AC boxes remain open pending independent architecture/QA review.

Owner-authorized AC4 amendment:
- Existing evidence-backed numeric safety caps are hard constraints now.
- A complete owner-reviewed TASK-120 upload/RAM/disk/fd/discovery/announcement budget artifact is a fail-closed prerequisite before Stage-B training. Missing content fails before generation; no absent product budget was invented and TASK-42 remains calibration only.

Current architecture:
- Performance opportunity and fault qualification are separate. Four coarse full-real-Nix workload strata/profile carry inference; component and injected-fault rows carry mandatory hard qualification gates only.
- Stage A has six A1/A2 base-label slots and Stage B ten. Unsupported labels remain explicit/nonnumeric. A1 alone drives TASK-44 selection. Planning centers all observed A1/A2 direction and exposes only a fixed-N=100 eligibility mask/hashes; raw A2, residuals, effects and uncentered statistics never reach TASK-44.
- Before calibration, TASK-128 freezes the causal-trace schema/replay interpreter and complete JCS planning catalog: at most 16 exact selector artifacts/profile crossed with all at most four capable best-static comparators, hence 64 contrasts/profile and 192 total. Families, ranges, training-filled values and post-calibration selector invention are forbidden.
- Every dynamic selector has four fixed live-replay parity scenario classes. Each selector/class binds separate A1 and A2 execution IDs and runs two independently fresh live executions; each live label is compared only with replay of its matching base-arm label trace. The four scenarios reuse qualification rows, so clusters remain 592/profile and 2368/partition. Worst parity work is 3*16*4*2=384 live slots. Base Stage-B work is 2368*10=23680 slots; the total ceiling is 24064.
- The planning catalog hashes linked-coordinate-v1 and the exact numeric alternative/null injection object. Boundaries/alternatives are: consume 0.05/0.075; egress 0.20/0.30; LAN log benefit -log(0.95)/1.5 times that; public relative log relief log(1.10)/1.5 times that; public absolute log relief 0/log(1.10); upper latency guard log(1.10)/0. A/A alternatives are zero with both +/-m_aa boundaries (egress 0.05, latency log(1.05), relief log(1.10)). Values use integer rational/scaled-log-ratio JCS encodings, never JSON floats.
- The frozen solver jointly shifts linked fraction/payload/avoided-byte, latency-ratio and relief numerator/upload coordinates. Shared physical views cannot diverge. It recomputes every target and forbids clipping, projection or retries. Any nonfinite, negative-byte, nonpositive required denominator/relief or target mismatch marks only that contrast injection_domain_ineligible.
- Each contrast has at most 64 hypothesis cases (57 worst public), 128 synthetic N=100 experiments/case and the exact 10000-draw final four-stratum bootstrap. The checked maximum remains 192*64*128*10000=15728640000 contrast-decision evaluations. N=125 is not simulated and cannot rescue N=100.
- TASK-44 uses A1 to choose one deterministic best-static arm and an exact pre-enumerated selector with an eligible matching contrast. No match means no candidate; comparator swapping/new thresholds are forbidden. A failed parity check marks every comparator contrast containing that selector, not unrelated selectors.
- TASK-122 emits one hashed validation-slot artifact/profile. Present validated/validation_no_go slots bind candidate/comparator hashes. A training no-candidate slot instead has explicit absent candidate/comparator references and A2 validation not_applicable; hash fields are forbidden. TASK-123 requires hashes only for present references, executes only validated slots, and never reassigns an absent/no-go slot or narrows the three-profile multiplicity family.
- Concrete exclusion identity remains arm-order-independent and includes workload/topology, roles, placements, initial state and scheduled events. Holdout remains post-freeze, witnessed, append-only, one-attempt and no-reroll.

Acceptance evidence remains mapped to all 12 unchecked criteria. Stage A is structurally rejected by policy fitting; unsupported Stage-B cells stay explicit; metrics/privacy/anti-vacuity and owner/task/version boundaries remain normative.

Verification status:
- Earlier build/lint/test/e2e and QA records apply to prior hashes, not this corrective iteration.
- Per orchestration instruction, full gates are not run here. Independent architecture/QA and repository gates remain required before commit.
- No e2e-full or e2e-vm claim is made.

Final independent gate: qa-test-runner GO and mped-architect GO on PRD 2b4c921f, TESTING c41dbdb2 and pre-close tracker 5c157c3c. Required nix develop build/lint/test/e2e all exited 0; e2e passed 5/5 scenarios and 48/48 checks in 75.5 s. Exact planning-injection, both-label parity, no-candidate validation, joint-planner, holdout and all 12 AC audits passed. The following checkbox/status/final-summary mutation is tracker-only and is not an implementation change.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Froze the Iroh-first two-stage tournament contract and falsifiable bounded scenario generator. Stage A is raw diagnostic only; Stage B compares upstream, Iroh raw/zstd and BitTorrent raw/compressed-or-evidenced-no-go. The contract separates opportunity inference from fault qualification, preserves private-by-default operation, requires owner-reviewed TASK-120 budgets, uses exact A1/A2 joint N=100 planning over a finite selector/comparator catalog, and seals a witnessed single-attempt holdout with no reroll. Upstream-only and no acceptable candidate remain valid outcomes.
<!-- SECTION:FINAL_SUMMARY:END -->
