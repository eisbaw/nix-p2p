---
id: TASK-243
title: >-
  Wire the authenticated-PeerId hold-query RESPONDER over libp2p and report the
  live DeriveBudget
status: To Do
assignee: []
created_date: '2026-08-17 11:04'
updated_date: '2026-08-17 16:52'
labels:
  - daemon-core
  - discovery
  - resource
  - hardening
  - security
dependencies:
  - TASK-229
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-229. TASK-229 built the responder derivation-DoS enforcer (PeerDeriveLedger: per-peer byte+dump-count over a window keyed by authenticated NodeId, plus a global Sybil-floor ceiling), the pre-dump NarSize query (NarDumper::nar_size, refuse-before-dump), the bounded responder API (AvailabilityIndex::answer_for_peer / answer_batch_for_peer), the operator-contract DeriveBudget (ResourceCaps::derive_budget + effective_lines) and the --status used/CAP line. It is PROVEN by 5 mutation bites in daemon-core/tests/responder_derive_budget.rs and wired into the wave-2a InProcessPeerQuery transport (defaults to an unlimited ledger; with_derive_ledger injects a bounded one). HONEST GAP this task closes: there is NO over-libp2p hold-query RESPONDER on the shipped path yet, so no live wire call site authenticates a remote PeerId to key the ledger and no live PeerDeriveLedger charges in the daemon-libp2p binary (Observability.derive_ledger is None there; the CAP is still visible in --preflight). When the libp2p inbound hold-query responder is built, it must: (1) construct PeerDeriveLedger::new(contract.caps.derive_budget()) once, (2) pass the inbound connection's authenticated PeerId as the asker into answer_for_peer/answer_batch_for_peer, (3) pass Some(ledger) into Observability so --status/--metrics report the live used/CAP. Also (perf follow-up from 229): cache the queried NarSize on the Entry so a cold peer probe does not re-spawn nix-store -q --size on every window; and tune the placeholder DeriveBudget defaults (1 GiB/64-dumps per peer / 4 GiB global per 60s) from a measured per-deployment disk/CPU I/O ceiling.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The over-libp2p inbound hold-query responder keys a shared PeerDeriveLedger by the AUTHENTICATED remote PeerId and calls answer_for_peer/answer_batch_for_peer, proven by an over-the-wire bite that a per-peer/global flood is bounded
- [ ] #2 daemon-libp2p passes Some(ledger) into Observability so --status reports the LIVE derive_budget_global_bytes used/CAP, read from the enforcing ledger (not a mirror)
- [ ] #3 NarSize is cached per Entry so a repeated cold peer probe does not re-spawn the size query each time; placeholder DeriveBudget defaults are revisited against a measured I/O ceiling
- [ ] #4 Responder uses ONE shared responder-lifetime enforcing ledger (never fresh-per-request, which would defeat cross-message aggregation); the unbounded local hold() cannot be reached by the inbound responder path (rename to hold_local or a guard asserting no inbound handler calls hold) [codex#3/mped#5]
- [ ] #5 The NarSize size-query (nix-store -q --size) is itself per-peer bounded: a refused-before-dump cold probe cannot drive an unbounded fork/exec flood (cap or charge the size-query per peer) [mped#2]
- [ ] #6 A GLOBAL dump-COUNT ceiling (companion to max_dumps_per_peer) bounds total fresh dumps so a many-PeerId tiny-NAR Sybil flood cannot exceed it under the global byte floor [mped#3]
- [ ] #7 The per-peer ledger map evicts stale entries (drop a peer window when it rolls empty, or periodic GC) so a churning/Sybil peer population cannot slowly exhaust memory [mped#4]
- [ ] #8 Single-key responder refusals are observable (a refusal counter or operator note), consistent with the batch path and the fail-loud discipline [mped#6]
- [ ] #9 The derivation budget uses a true sliding/rolling window so the effective bound is cap, replacing the tumbling window whose worst case is up to 2x cap across a boundary [229-D/codex]
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
PREMISE RE-SCOPE (COMPASS 2026-08-17 + orchestrator call-graph check). This task as filed targets the over-libp2p hold-query RESPONDER (answer_for_peer/answer_batch_for_peer + PeerDeriveLedger) — but that surface lives in daemon-core/src/discovery.rs / InProcessPeerQuery and is wave-2a SCAFFOLDING with NO production caller (same class as the reverted TASK-232). The shipped libp2p path serves via kad provider-records to the /nar/3 stream, not hold-queries. The REAL shipped DoS surface is fabric-libp2p/src/server.rs serve(ServeBudget) -> ServeGate where a peer-triggered nix-store --dump regenerate-on-demand runs (Libp2pNarSupplier, TASK-193/158/191), fed by the swarm accept loop (swarm.rs ~1688). That dump work is bounded by ServeBudget (bytes SERVED) but NOT by a per-peer DeriveBudget (bytes hashed). TASK-229 built PeerDeriveLedger but daemon-libp2p ships derive_ledger=None. RE-SCOPE before dispatch: charge the per-peer DeriveBudget on the shipped SERVE/regenerate path keyed by the authenticated remote PeerId (available at the accept loop), with an OVER-THE-WIRE mutation bite (a peer flood drives the ledger to cap and the serve declines; neutralise the charge -> flood succeeds unbounded). Premise-check the exact serve->supplier->dump call site first; if it is already adequately per-peer-bounded, park 243 and note why. AC#1 (over-libp2p responder keying) and the hold() footgun AC re-point at the SERVE path, not a hold-query responder.
<!-- SECTION:NOTES:END -->
