---
id: TASK-240
title: >-
  Operator-contract observability: live --status endpoint + metrics exporter +
  drill oracles (TASK-120 AC#4/#5/#6 residual)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-17 03:19'
updated_date: '2026-08-17 07:34'
labels:
  - operator
  - observability
  - production
  - follow-up
dependencies: []
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-120 (Done) delivered the operator-contract SAFETY CORE runtime-enforced. Three observability ACs are Partial (renderers + vocabulary exist + are unit-tested; the live wiring is pending): AC#4 a live --status endpoint fed by RUNNING node state (real bootstrap health, holder counts, direct/relay path, current budget use, miss-vs-unavailable) - the OperatorStatus renderer + StatusInputs exist; wire them to a running node query. AC#5 a live metrics exporter that APPLIES the PrivacyPolicy redaction + bounded-cardinality MetricLabel vocabulary (both exist) to real emitted metrics. AC#6 the four operational drill ORACLES (restart / dependency-outage / exhausted-budget / kill-switch) as executable e2e/VM assertions that yield actionable health while the S2 additive invariant holds. Integers only; no frozen-wire change; do not weaken the fail-safe defaults. Relates TASK-45 (fresh-host operator journey).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-240 progress (implementer): landed the LIVE observability wiring reusing the TASK-120 renderers/vocab.
- daemon-core/src/observ.rs (NEW): RuntimeMetrics SSOT (bounded-cardinality integer counters keyed only by MetricLabel/LookupOutcome), Observability bundle rendering status+metrics through PrivacyPolicy, StatusFacts seam, and a DEDICATED loopback admin listener (serve_admin) for GET /nix-p2p/status + /nix-p2p/metrics.
- Recording boundaries (single-writer, no double count): PeerFabricNarSource records the typed miss/unavailable/found + holder count; FallbackNarSource records hit_upstream once. TooLarge recorded as neither.
- daemon-libp2p: --status-listen (OFF by default; loopback admin surface), --status/--metrics client subcommands, SwarmStatusFacts (live bootstrap health via SwarmHandle::is_connected), PostFetchAnnounce::budget_used (live from the enforced ledger).
- AC#4 status + AC#5 metrics: complete with mutation-proven redaction/bounded-cardinality/recording bites. peer_path direct/relay is an HONEST PARTIAL (needs swarm ConnectedPoint::is_relayed exposure; documented follow-up).
- AC#6: 4 drill oracles (restart/dependency-outage/exhausted-budget/kill-switch) as in-process integration tests through the real run() serving+admin path, each asserting the health signal AND the S2 additive invariant; mutation-proven. Network-level containerized fault-injection versions are a documented follow-up.
- mped-architect (Mark-emulator) design review: conditional GO; incorporated dedicated loopback listener, torn-read fix (single mutex snapshot), single recording boundary, dropped last_content from the scrapeable /metrics surface.
- Gates so far GREEN: cargo test (daemon-core 259 + daemon-libp2p 31/28 + drills 4 + integration), fmt --check, clippy --workspace --all-targets -D warnings, check-no-floats, check-golden-vectors (byte-identical), check-discovery-no-shortcut --self-test. TASK-120 operator safety bites re-run, no regression. NO frozen-wire change. just e2e running.

TASK-240 mped code review (Mark-emulator): NO-GO (small, bounded) -> fixed, now GO-ready.
- F1 (SSOT drift): status/preflight announce_budget denominator came from contract.caps (always default 256) while the enforced cap = --libp2p-announce-budget. FIXED at root: build_contract now sets caps.announce_distinct_paths_budget = cfg.libp2p_announce_budget, so the reported CAP equals the enforced one. New bite: announce_budget_cap_follows_the_flag_for_the_surface (mutation: pin to default -> reddens).
- F2 (torn read): render_status read last_lookup() then last_holders() in two lock acquisitions, splicing across lookups. FIXED: single-lock last_snapshot() accessor; render_status uses it.
- N3 (silent failure): record_lookup now logs on a poisoned observability mutex (fail-open, not fail-silent).
- N1 (peer_path none vs unknown) and N2 (SwarmStatusFacts is_connected loop untested) recorded as explicit follow-ups (see new task).
Re-gated after fixes: cargo test green (daemon-core observ 5, daemon-libp2p main 29 incl F1 bite, drills 4, integration), clippy --workspace --all-targets -D warnings clean, fmt clean.
NOTE: first just e2e FAILED to build only because the new observ.rs/operator_drills.rs were untracked (nix flake source excludes untracked files); git add staged them and e2e was re-run.

DONE-with-residual (LIGHT gate). Commit 82664c9. AC#4 live --status (loopback admin listener, off-by-default, real state, PrivacyPolicy-redacted, mutation-proven) Complete; AC#5 redacting metrics exporter (bounded-cardinality MetricLabel, redacted-by-default mutation bite) Complete; AC#6 drill oracles (restart/outage/exhausted-budget/kill-switch, each asserting health + the S2 additive invariant) Complete as in-process. Additive instrumentation only (golden byte-identical); new dep = tokio io-util feature (audit RC 0); TASK-120 safety 21/21 no-regression; just e2e 8/8. RESIDUAL -> TASK-242 (network-level containerized fault-injection + peer_path relay-detection + SwarmStatusFacts runtime test).
<!-- SECTION:NOTES:END -->
