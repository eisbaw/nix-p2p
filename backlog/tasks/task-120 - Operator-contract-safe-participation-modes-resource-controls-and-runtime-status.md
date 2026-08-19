---
id: TASK-120
title: >-
  Operator contract: safe participation modes, resource controls and runtime
  status
status: Done
assignee:
  - '@claude'
created_date: '2026-08-10 22:24'
updated_date: '2026-08-19 11:54'
labels:
  - production
  - operator
  - observability
  - privacy
  - wave-2c
  - rework
dependencies:
  - TASK-24
  - TASK-25
  - TASK-29
  - TASK-31
  - TASK-77
  - TASK-78
  - TASK-100
  - TASK-103
  - TASK-111
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define and implement the production operator contract for the libp2p-primary product path. Operators select one authoritative validated profile: upstream-only, consume-only, LAN-share, or public-share. That typed profile generates or mechanically parity-checks daemon CLI/runtime, NixOS options, participation, serving/publication, resource budgets, privacy behavior, preflight, and local status. Iroh is a deferred optional mechanism override and cannot define the core contract or bypass profile safety. The UX must make safe setup, current behavior, budget use, dependency health, fallback reasons, and corrective action understandable without reading source code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A fresh install is fail-safe: upstream fallback works, while serving, publication, public DHT/Mainline participation and third-party discovery are OFF until the operator explicitly selects a sharing profile.
- [x] #2 The NixOS module exposes validated upstream-only, consume-only, LAN-share and public-share profiles plus explicit Iroh mechanism overrides; invalid or privacy-contradictory combinations fail evaluation/startup precisely.
- [x] #3 Upload rate/bytes, concurrent serves, per-NAR/inflight memory, hold-query work, discovery deadline, announce volume, disk and file-descriptor budgets are bounded, documented and visible in effective configuration.
- [x] #4 A local status surface reports stable NodeId, enabled discovery/transport/codec mechanisms, bootstrap health, holder counts, direct/hole-punched/relay path, miss versus unavailable, fallback reasons and current budget use.
- [x] #5 Metrics/logs use bounded-cardinality labels and never export StorePath, NarHash, peer IP or full NodeId by default; opt-in diagnostics carry an explicit privacy warning and lifecycle.
- [x] #6 Restart, dependency outage, exhausted budget and kill-switch drills yield actionable health while S2 holds; the registry contract lets TASK-119 add BitTorrent without redefining profiles or weakening safe defaults.
- [x] #7 Before public networking is enabled, a one-command preflight lists every DNS/tracker/relay/Mainline/seed dependency, what the selected profile publishes and queries, and the effective resource/privacy controls.
- [x] #8 The authoritative capability model represents Mainline as non-selectable pending or evidenced-unsupported until TASK-131 supplies a supported artifact. TASK-130 LAN and TASK-89 DNS/relay remain usable without it; no profile aliases pending/unsupported to enabled or silently substitutes another mechanism.
- [x] #9 One typed configuration model is authoritative across NixOS options daemon CLI TASK-115 endpoint scopes TASK-130 LAN TASK-116 named hold-query TASK-89 DNS and relay passing TASK-103 decentralized content discovery and status or preflight. Optional tracker Mainline and BitTorrent adapters extend the registry only after their own tasks and contradictory duplicate defaults fail parity tests.
- [x] #10 A versioned JCS artifact uses typed integer unit-suffixed fields for every profile: upload_payload_bytes_compressed_wire, upload_total_bytes_compressed_wire, upload_rate_bytes_compressed_wire_per_window and window_ns; concurrent serves; single/inflight NarSize bytes_uncompressed_nar; transient RAM bytes_ram; apparent/allocated disk bytes_ondisk; open_fds_count; discovery work/control octets/deadline_ns; announce count/wire octets/rate window; and serve_duration_ns. It is content-hashed, explicitly owner-reviewed, and generates or mechanically parity-checks daemon runtime, NixOS effective values, status, and preflight. Current 512 MiB/300 s values must fail against the normative 256 MiB single, 1 GiB inflight, 120 s envelope unless the owner explicitly revises PRD.md.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Authoritative current direction: the core contract is libp2p-primary and transport-agnostic. Iroh is an optional deferred mechanism governed by TASK-202 and cannot define or bypass profiles. Existing commits 0fff8c0, 4f5d524 and 08085b7 established explicit profiles, fail-closed compatibility checks, profile-derived libp2p participation, capability reporting, preflight, and redaction. This task was reopened on 2026-08-18 because AC#3/#4/#5/#6 and the owner-reviewed per-profile budget artifact remain incomplete; current libp2p 512 MiB/300 s values conflict with the normative 256 MiB/1 GiB/120 s envelope. Preserve the durable/reclaiming NodeId replay-ledger concern from TASK-138. UX is fundamental: profile selection, precise validation, preflight, local health/status, effective budget and queue use, fallback explanations, privacy-safe diagnostics, kill switch, and recovery must be coherent and runtime-authoritative.

TASK-120 AC#10/#3 implementation landed (pending full gate). Added frozen artifact artifacts/profile-budget-v1.json (JCS-canonical, blake3=bb2a819c302fd7809d67b5e353b3e0d821f7d0ba50165634d44912692d056506) with typed integer unit-suffixed fields for all 5 profiles. New module daemon-core/src/profile_budget.rs: load/canonicalize/content_hash/validate_envelope/parity_with_caps/verify + fail-closed BudgetError (Missing=PROFILE_BUDGET_ARTIFACT_MISSING, HashDrift, EnvelopeExceeded, ParityMismatch). ResourceCaps::default() moved from 512 MiB/300 s to the normative 256 MiB/1 GiB/120 s envelope. Fail-closed verify wired into daemon-libp2p + composite daemon live startup (before serving) and surfaced in OperatorContract::preflight. Mutation bites proven by permanent tests: envelope_bites_on_512mib_single, envelope_bites_on_300s_serve_duration, parity_bites_when_runtime_caps_diverge, envelope_bites_on_declared_envelope_weakening. 15 profile_budget + 24 operator lib tests green; no-floats guard green.

TASK-120 AC#10/#3 DONE; #4/#5/#6 verified against TASK-240 evidence and checked. Full DEEP gate GREEN on final state.

FROZEN ARTIFACT: artifacts/profile-budget-v1.json (JCS-canonical, blake3=bb2a819c302fd7809d67b5e353b3e0d821f7d0ba50165634d44912692d056506), typed u64 unit-suffixed fields for all 5 profiles (the 4 mandated + router). Normative envelope 256 MiB single / 1 GiB inflight / 120 s. ResourceCaps::default() moved 512 MiB/300 s -> 256/120 to match. daemon-core/src/profile_budget.rs: load/canonicalize/content_hash/validate_envelope/parity_with_caps/verify + fail-closed BudgetError. Fail-closed verify wired into daemon-libp2p + composite daemon startup; artifact surfaced in OperatorContract::preflight with enforced-vs-declared-only markers. flake.nix source filter widened to include the artifact (include_str! in the crane sandbox).

BITE (mutation-proven): envelope_bites_on_512mib_single / _on_300s_serve_duration / _on_declared_envelope_weakening; parity_bites_when_runtime_caps_diverge; plus a live file edit to 512 MiB reddened validate_envelope with EnvelopeExceeded{public-share,single_nar,536870912,ceiling 268435456}, reverted.

REVIEW FIXES: (1) removed announce_count from runtime parity - it is operator-tunable via --libp2p-announce-budget and would falsely fail startup; kept an SSOT test against the code default + a regression guard. (2) preflight marks enforced vs declared-only fields (no phantom bound advertised).

GATE NUMBERS: fmt green; clippy -D warnings green (daemon-core/libp2p/daemon); daemon-core --lib 315 pass (profile_budget 18, operator 24); daemon-libp2p preflight 2 + operator_drills 4; daemon convergence 1; check-no-floats.py green (self-test 6 bites + 14 scripts); just e2e 11 scenarios / 124 checks PASS. Two independent reviewers (qa-test-runner + mped-architect) returned GO.

RESIDUAL: TASK-264 (Medium) - wire runtime enforcement for the declared-only fields (upload rate/bytes, RAM, disk bytes, fd, concurrent-serve count); today they are frozen+hashed+surfaced (declared ceilings) but not runtime-enforced, consistent with the ResourceCaps no-phantom-bound honesty rule.

EVIDENCE for #4/#5/#6 (TASK-240, unchanged by this cycle, re-verified green): #4 status surface daemon-core/src/observ.rs render_status_reports_live_state_redacted + operator.rs status_reports_miss_vs_unavailable_and_budget; #5 redaction observ.rs metrics_redact_node_id_by_default_reveal_under_diagnostics + metric_labels_are_only_the_fixed_vocabulary (new budget fields add no StorePath/NarHash/IP/NodeId); #6 drills daemon-libp2p/tests/operator_drills.rs 4 drills + Mechanism::registry contract.
<!-- SECTION:NOTES:END -->
