---
id: TASK-219
title: >-
  fabric-libp2p: general multi-relay /p2p-circuit resolution (propagate relay
  identity through the DHT) — ROUTE 2 follow-up to TASK-218
status: To Do
assignee: []
created_date: '2026-08-15 15:35'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
dependencies:
  - TASK-218
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-218 landed ROUTE 1: a discovery-only consumer RESOLVES a NAT'd provider's /p2p-circuit dial-address by CONSTRUCTING it from the provider PeerId (discovered via kad) plus a relay it already knows from bootstrap config (NodeConfig.known_relays / Libp2pNodeLocator). GENERALITY LIMIT: this only works when the provider reserved on a relay THIS consumer already knows (the single shared-relay case: the harness, and the common known-public-relay deployment). The fully general MULTI-RELAY case — consumer does NOT know which relay a provider chose — is unresolved. Root cause diagnosed in TASK-218: the provider's /p2p-circuit address is DROPPED in the identify->kad->FIND_NODE address path on the relay (libp2p 0.54), so kad get_closest_peers returns only the provider's DIRECT (private, unreachable behind NAT) address. Two candidate fixes: (A) make the /p2p-circuit address survive identify->kad so get_closest_peers returns it (libp2p-kad 0.54 internals — FORK RISK, non-converging-internals hazard, spike before committing); (B) an ADDITIVE relay-hint offer in the record codec (TASK-156-shaped FROZEN-SEAM wire-review change) so a provider advertises which relay(s) it reserved on — more honest than patching kad internals, but touches the frozen codec and needs wire review. Evaluate (B) first. Fabric repro to extend: fabric-libp2p/tests/nat_dht_resolve.rs. Do NOT weaken check-discovery-no-shortcut.py (discovery stays kad-exclusive; relay identity must arrive via kad/record, not out-of-band injection).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A consumer that does NOT know a NAT'd provider's relay from config resolves the provider's /p2p-circuit dial-address and fetches byte-identical through that relay, proven against a topology with >= 2 relays where the provider reserves on a relay NOT in the consumer's bootstrap set
- [ ] #2 The relay identity reaches the consumer through kad/the record (not out-of-band injection); check-discovery-no-shortcut.py and the kad-exclusive discovery guarantee are NOT weakened
- [ ] #3 If ROUTE (B) is taken: the record-codec change is ADDITIVE, wire-reviewed, and does not break the frozen golden vectors
<!-- AC:END -->
