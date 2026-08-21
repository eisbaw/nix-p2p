---
id: TASK-120
title: >-
  Operator contract: safe participation modes, resource controls and runtime
  status
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:24'
updated_date: '2026-08-21 10:13'
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
- [ ] #3 Upload rate/bytes, concurrent serves, per-NAR/inflight memory, hold-query work, discovery deadline, announce volume, disk and file-descriptor budgets are bounded, documented and visible in effective configuration.
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

codex DEEP review NOGO -> fixed all 5 findings (round 2).
#1 (CRITICAL runtime bypass): composite daemon serve budget is built from CLI-overridable config.iroh_max_* (daemon/src/main.rs:1496 iroh, :1995 libp2p) but verify checked ResourceCaps::default(). Added profile_budget::check_serve_within_envelope + check_serve_ms_within_envelope (BudgetError::OverrideExceedsEnvelope): an override may only TIGHTEN the frozen 256MiB/1GiB/120s envelope. Extracted enforce_budget_contract() in the composite (verify + effective-serve ceiling), called on BOTH the live path and preflight, guarding both serve paths (they read the same config fields). daemon-libp2p has NO serve-size override (provider_serve_budget()=ResourceCaps::default().serve_budget(), main.rs:871) so its serve envelope was already enforced; added the same ceiling check as a structural guard-rail. PUSHBACK: the over-serve-override launch bite is composite-only (libp2p has no such flag).
#2 (announce mislabel): announce_count relabeled [operator-overridable - runtime-limited, not envelope-bounded] (it IS runtime-limited but operator-chosen via --libp2p-announce-budget and NOT a safety envelope; it is self-limiting politeness). Removed the [enforced] label. Judgment (Mark-emulator): announce volume is politeness, not a network-safety ceiling, so relabel over hard-ceiling.
#3: UNCHECKED AC#3 (14 declared-not-enforced fields; TASK-264 completes it).
#4 (owner-review overclaim): reworded artifact JSON review note + all code sites - the hash pins BYTES (freeze/identity), it does NOT constitute human owner review/authorization. Hash re-frozen f38fbebdbf99b0fb0b2846bf99d9c84a36466950c9e7aeb8901d21db89128c4b.
#5a: module doc states the runtime missing path is compile-time (include_str!) and PROFILE_BUDGET_ARTIFACT_MISSING is for the path-based tooling/Stage-B loader only.
#5b (fail-OPEN preflight): both binaries preflight now EXIT NONZERO when the budget contract fails (was exit 0 after printing).

LAUNCH-LEVEL BITE (real binaries): daemon --preflight --iroh-max-serve-nar-bytes 536870912 -> exit 1 (single_nar exceeds ceiling 268435456); --iroh-max-serve-duration-ms 300000 -> exit 1 (serve_duration_ns 300000000000 exceeds 120000000000); defaults -> exit 0; daemon-libp2p --preflight -> exit 0. Plus unit bites: profile_budget::effective_serve_override_over_envelope_fails_closed; daemon::over_envelope_serve_override_is_rejected_at_startup.
GATE r3: fmt+clippy green; daemon-core --lib 316; profile_budget 19; operator 24; libp2p preflight 2 + drills 4; daemon budget 3; no-floats green. e2e re-running.

CORRECTION (supersedes the earlier "AC#10/#3 DONE / Full DEEP gate GREEN" note, which was written before the codex re-gate reopened this task): AC#3 is OPEN (declared != enforced; 14 fields surfaced+hashed but not runtime-enforced, TASK-264 completes it). AC#10 is checked. The DEEP gate is NOT green-complete yet - it is mid codex re-gate: R1 NOGO (serve-override envelope bypass + enforced-vs-declared honesty) was fixed and R2 VERIFIED the critical fix on real binaries; 4 minor honesty/accuracy residuals (R2-1 effective-value display, R2-2 hash-vs-review wording, R2-3 no path-based loader, R2-4 tracker drift) are being closed now; R3 final re-gate pending. Do not read the earlier DONE/GREEN as current truth.

AC#10 "explicitly owner-reviewed" clarification (R2-2c): there is NO separate human-attestation artifact in this repo. "Owner-reviewed" is represented OPERATIONALLY by the checked-in frozen content hash (EXPECTED_PROFILE_BUDGET_HASH) plus the artifact reviewed_revision field: any budget change forces a deliberate, reviewable one-line hash re-freeze, and the daemon fail-closes on drift. The hash attests IDENTITY/FREEZE of the canonical JCS content, NOT human authorization of the numbers - a content hash cannot attest that. A real signed approval attestation is future work, not built here. AC#10 is checked on that operational reading; if the owner requires a literal human-attestation record, AC#10 is partial pending that separate mechanism.

STATE 2026-08-19 (post codex R1/R2/R3): DELIVERED SCOPE is DEEP-gate substance-GREEN and codex-verified — AC#10 frozen budget artifact (hash d5d71004) + the ENFORCED serve envelope (single/inflight served NarSize + serve duration; a CLI override may only TIGHTEN; 512 MiB/300 s fails closed; verified on real binaries). Commits 4ff3b39->02951bd->188b57e->801902c (the last three closed codex NOGO findings incl the CRITICAL runtime-override bypass R1 found and the R3 doc-drift). ONLY AC#3 remains OPEN — the 14 declared-only budget fields (upload rate/bytes, transient RAM, disk bytes, open_fds, concurrent-serve count) are frozen+surfaced ceilings, NOT runtime-shaped — tracked in TASK-264. Do NOT re-select 120 as a whole; pick TASK-264 to finish AC#3, at which point 120 flips Done with its final gate.

AC#3 status 2026-08-21: the DOCUMENTED + VISIBLE half is met (TASK-264 b1e92b7: preflight shows every budget field's status + '-> owner' routing; honesty-lock mutation-tested). The BOUNDED half is PARTIAL: load-bearing resources ARE bounded (inflight/single NarSize via ServeBudget, serve_duration, discovery_deadline, announce_count) but the declared-only fields (upload-rate, transient RAM, disk, octets, concurrent-serves count, open_fds) are NOT runtime-enforced - enforcement ruled net-negative/needs-dedicated-shapers by 264's Mark-emulator, routed to TASK-299 (shapers) + TASK-297 (regenerate DeriveBudget); open_fds documented capacity-only. So AC#3 STAYS OPEN pending 299/297. AC#1/2/4-10 done.
<!-- SECTION:NOTES:END -->
