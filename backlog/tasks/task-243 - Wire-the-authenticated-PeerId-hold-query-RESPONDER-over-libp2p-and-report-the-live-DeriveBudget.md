---
id: TASK-243
title: >-
  Wire the authenticated-PeerId hold-query RESPONDER over libp2p and report the
  live DeriveBudget
status: To Do
assignee: []
created_date: '2026-08-17 11:04'
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
<!-- AC:END -->
