---
id: TASK-229
title: >-
  Responder derivation-resource DoS defense: per-PEER byte-seeded budget (not
  per-message dump-count) for hold-query probes
status: Done
assignee:
  - '@claude'
created_date: '2026-08-16 03:18'
updated_date: '2026-08-17 12:52'
labels:
  - daemon-core
  - discovery
  - resource
  - hardening
  - security
dependencies:
  - TASK-104
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-104. TASK-104 added a per-BATCH derivation-work budget (MAX_BATCH_DERIVE_WORK=16 fresh nix-store --dump per batch message), closing AC#1 (one MESSAGE cannot trigger unbounded dumps). Two real resource-safety residuals remain, honestly disclosed at TASK-104 and worth the proper responder-resource DoS defense that TASK-100/TASK-120 need:
1. A dump COUNT does not bound BYTES hashed - 16 large cold dumps is still unbounded I/O. The root-cause bound is a nix path-info -S (NarSize) seeded BYTE budget that can REFUSE a probe before dumping, so the responder work is bounded in bytes, not dump-count.
2. A per-MESSAGE bound is NOT a DoS defense: a hostile peer picks message boundaries (many 16-dump batches, or single-key hold() probes which take the UNLIMITED path). The actual defense is a per-PEER AGGREGATE derivation budget (bytes and/or count) over a time window - the hashing analog of TASK-72's serve budget (which bounds bytes SERVED, not HASHED). The single-key hold() unlimited path must also be brought under this per-peer bound.
Also (minor, from TASK-104): resolve_many could opportunistically re-probe a peer that deferred (convert responder-cache warming into first-contact healing); and MAX_BATCH_DERIVE_WORK=16 is a conservative placeholder, tune from a real per-deployment disk/CPU I/O ceiling. This is a frozen-adjacent resource-contract task (feeds the TASK-120 operator budgets) - DEEP-gate. Do NOT fix by raising PROBE_TIMEOUT (TASK-40).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TASK-229 IMPLEMENTED (not Done; orchestrator owns Done after the DEEP gate).

DESIGN. peer_fabric::DeriveBudget (config, mirrors ServeBudget; integers only): per-peer bytes + per-peer dump-count + GLOBAL bytes ceiling + rolling window. daemon_core::derive_ledger::PeerDeriveLedger is the stateful enforcer: per-peer + one global fixed-window {start_millis,bytes,dumps}, keyed by the AUTHENTICATED NodeId (== the libp2p PeerId seed, per ids.rs), integer MonotonicClock seam (SystemClock prod, ManualClock tests), global-first then per-peer check, commit-both-or-nothing, saturating_add. NarDumper gains nar_size() answered WITHOUT dumping (CommandNarDumper=nix-store -q --size; MemoryNarDumper=bytes.len; RegularFileNarDumper=fstat) - the R1 refuse-before-dump seed. AvailabilityIndex responder API renamed to answer_for_peer / answer_batch_for_peer (asker NodeId + &PeerDeriveLedger); the old per-batch DeriveBudget count struct renamed BatchDeriveAllowance; local self-probe hold() stays unbounded (claim/publish/learn are node-initiated, must answer truly). In derive(): reserve the per-message count FIRST (bounds the size-queries too, so a 256-key cold batch does <=MAX_BATCH_DERIVE_WORK size-queries+dumps, not 256), then nar_size + ledger.try_admit; any refusal defers Absent WITHOUT dumping. Operator: ResourceCaps gains derive_* fields + derive_budget() + 4 effective_lines; --status renders derive_budget_global_bytes=used/CAP read LIVE from the ledger (aggregate integer, no per-peer id -> PrivacyPolicy-safe).

RESIDUAL STATUS: R1 refuse-before-dump CLOSED; R2 per-peer aggregate CLOSED; single-key hold() flood CLOSED; global Sybil-floor ceiling CLOSED; reported-honestly CLOSED.

BITES (daemon-core/tests/responder_derive_budget.rs), each RED-without / GREEN-with by mutation:
 1 refuses_an_oversize_cold_probe_before_dumping: MemoryNarDumper.calls()==0 on refusal; mutation (disable ledger gate) -> dump happens, calls==1.
 2 per_peer_budget_bounds_probes_spread_across_messages: 5 single-key messages, budget 2 NARs -> 2 Have; mutation (per-message ledger) -> 5 Have.
 3 single_key_hold_flood_is_bounded_not_unlimited: per-peer dump-count cap 3 -> 3 Have of 6; mutation removing ONLY the count clause reddens ONLY this bite.
 4 global_ceiling_bounds_a_many_peer_flood: 5 distinct peers, global 2 NARs -> 2 Have; mutation removing ONLY RefusedGlobal reddens ONLY this bite.
 5 status_reports_derive_budget_used_over_cap_as_integers: --status shows 6000/CAP live; mutation (report 0) reddens. Integers only (u64 parse).
Also batch_answer_is_bounded_by_the_per_peer_ledger (batch path draws the same ledger). Mutation attribution verified: global-only mutation reddened ONLY bite 4; count-only ONLY bite 3; ledger-off reddened 1-4 not 5.

NO REGRESSION: TASK-104 batch bite (exact 16/probe, unlimited ledger) green; TASK-56 quarantine-Absent green; TASK-120/240/242 operator+observ bites green (effective_lines 9->13, parity+status tests updated); no_enumeration guard updated for the rename (still bites).

GATE (nix dev shell, ACTUAL): cargo test --workspace --no-fail-fast = 1051 passed / 0 failed. fmt --check clean. clippy --workspace --all-targets -D warnings clean (+ daemon evidence-fixture clean). check-no-floats REAL rc0; check-golden-vectors byte-identical rc0 (frozen wire untouched - receiver-side admission only); check-discovery-no-shortcut REAL rc0. just audit rc0. just e2e = 9/9 scenarios PASS (250s). Disk ~89 GiB free.

HONEST LIMITS. (1) NO over-libp2p hold-query RESPONDER exists on the shipped path yet, so no live wire call site authenticates a remote PeerId to key the ledger and daemon-libp2p Observability.derive_ledger is None (CAP still visible in --preflight). The enforcer + bounded API are ready and proven; the wave-2a InProcessPeerQuery transport is threaded (unlimited by default, with_derive_ledger for the bound). Live-wire threading + live used/CAP reporting = TASK-243. This is the honest premise correction: 229 delivers the mechanism + bites, not a live-wire responder that did not exist. (2) Global ceiling is the responder last line, NOT full Sybil defence (per-subnet / identity-cost = TASK-205). (3) nar_size adds one nix-store -q --size subprocess per admitted cold peer key (bounded per message by the count cap); caching NarSize on the Entry = TASK-243. (4) DeriveBudget defaults (1 GiB/64-dumps per peer, 4 GiB global, 60s) are CONSERVATIVE PLACEHOLDERS not a measured I/O ceiling (same honesty as MAX_BATCH_DERIVE_WORK=16); tune per deployment = TASK-243.

CLARIFICATION (DEEP gate, codex+mped): the earlier R1/Sybil-floor "CLOSED" wording is closed on the BYTES-HASHED axis ONLY. Non-hashing-axis residuals carried to TASK-243 AC#4-9: fresh-ledger-lifetime + hold() footgun, NarSize size-query fork bound, global dump-COUNT ceiling, per-peer map eviction, single-key refusal observability, true sliding-window (tumbling worst case is up to 2x cap across a boundary). Codex NOGO on fail-closed EDGES fixed in 6038d9a: zero/sub-ms window clamped to 1s (written back), MAX-cap checked_add (over-cap refused not admitted), status used/CAP single-sourced from the live ledger + derive line OMITTED when no live ledger (no synthetic zero), tumbling window documented honestly. Core confirmed sound by both reviewers: no live responder exists; enforcement inside core answer_for_peer/answer_batch_for_peer; NarSize uncompressed unit; integers only; frozen wire byte-identical.

DEEP GATE PASSED (2026-08-17). Commits 80b47cc + 6038d9a + 0e922f2. qa GREEN (1053/0, e2e 9/9), mped GO (conditions applied), codex R1 NOGO->fixed->R2 code-GO/doc-NOGO->fixed->R3 GO-VERDICT-229R2. Mechanism DONE on the bytes-hashed axis (per-peer+global DeriveBudget keyed by authenticated PeerId, refuse-before-dump via NarSize, enforced inside core answer_*_for_peer). Live-wire responder + 6 non-hashing residuals -> TASK-243 AC#1-9.
<!-- SECTION:NOTES:END -->
