---
id: TASK-219
title: >-
  fabric-libp2p: general multi-relay /p2p-circuit resolution (propagate relay
  identity through the DHT) — ROUTE 2 follow-up to TASK-218
status: Done
assignee:
  - '@claude'
created_date: '2026-08-15 15:35'
updated_date: '2026-08-18 06:34'
labels:
  - libp2p
  - fabric
  - nat
  - hardening
dependencies:
  - TASK-218
  - TASK-156
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-218 landed ROUTE 1: a discovery-only consumer RESOLVES a NAT'd provider's /p2p-circuit dial-address by CONSTRUCTING it from the provider PeerId (discovered via kad) plus a relay it already knows from bootstrap config (NodeConfig.known_relays / Libp2pNodeLocator). GENERALITY LIMIT: this only works when the provider reserved on a relay THIS consumer already knows (the single shared-relay case: the harness, and the common known-public-relay deployment). The fully general MULTI-RELAY case — consumer does NOT know which relay a provider chose — is unresolved. Root cause diagnosed in TASK-218: the provider's /p2p-circuit address is DROPPED in the identify->kad->FIND_NODE address path on the relay (libp2p 0.54), so kad get_closest_peers returns only the provider's DIRECT (private, unreachable behind NAT) address. Two candidate fixes: (A) make the /p2p-circuit address survive identify->kad so get_closest_peers returns it (libp2p-kad 0.54 internals — FORK RISK, non-converging-internals hazard, spike before committing); (B) an ADDITIVE relay-hint offer in the record codec (TASK-156-shaped FROZEN-SEAM wire-review change) so a provider advertises which relay(s) it reserved on — more honest than patching kad internals, but touches the frozen codec and needs wire review. Evaluate (B) first. Fabric repro to extend: fabric-libp2p/tests/nat_dht_resolve.rs. Do NOT weaken check-discovery-no-shortcut.py (discovery stays kad-exclusive; relay identity must arrive via kad/record, not out-of-band injection).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 In a >=2-relay topology, consumer C bootstraps only R1 while provider P has a live reservation only on R2; C discovers P's signed Libp2p offer, resolves R2 through kad, and fetches the exact NAR through R2 with no provider or R2 address injected into C
- [x] #2 Relay identity reaches C only as a bounded, canonical, signature-bound TransportOffer::Libp2p relay hint from the exact-key DHT record; relay addresses are never on wire and are resolved through raw kad peer routing; check-discovery-no-shortcut and kad-exclusive discovery remain biting
- [x] #3 Production writers derive hints only from currently live /p2p-circuit listen addresses after reservation acceptance, never from configured/attempted/bootstrap relays; configured circuit listeners are applied before announce and a missing requested reservation blocks first announce within a bounded integer deadline
- [x] #4 Libp2pTransport consumes record hints through the existing offer argument and an internal locator path without widening NarTransfer, NodeLocator, ProviderRecord, or daemon-core; a directly reachable provider causes no relay query, while unresolved hints are skipped and normal upstream fallback remains intact
- [x] #5 Bites remove/replace R2 with R1, stop R2 on the same warm consumer and attribute failure to NotOpened/unreachable, and exercise two hints with one dead/one live; each mutation fails while discovery remains healthy
- [x] #6 At most two relay identities/lookups and bounded circuit candidates are enforced; duplicate/unsorted/invalid/self relay hints fail closed; no provider-keyed relay map/cache, opaque extension, content identity, or dial address is introduced
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## Authoritative Compass ruling (2026-08-17)

This ruling supersedes the earlier spike recommendation to introduce ProviderRecord schema v2. That recommendation is obsolete and MUST NOT be implemented. TASK-156 established the reviewed wire contract: OFFER_LIBP2P=2 is an explicit additive member of the existing schema-v1 tagged offer union. It does not alter the layouts or signing bytes of tag-0 Iroh, tag-1 BitTorrent, or withdrawals. Schema version 2 remains the exact historical reject vector. A historical reader fails closed with UnknownOffer { tag: 2 }; rollout is therefore reader-first and coordinated.

### Root cause and rejected route A

The multi-relay probe on libp2p 0.56 found that circuit addresses reach a directly connected kad peer but are lost when get_closest_peers combines reports from multiple sources. libp2p-kad Behaviour::discovered overwrites the per-peer address set instead of taking a union. No supported Config knob changes this private query behavior, so route A would require a libp2p-kad fork and is rejected. check-discovery-no-shortcut.py must remain biting.

### Selected route B and wire constraints

Use the TASK-156 TransportOffer::Libp2p { node, relay_hints } tag-2 shape. Hints are signed relay NodeIds only: no relay addresses, content identifiers, opaque bytes, or tolerate-and-drop extension. RelayHints enforces at most two strict Ed25519 identities in ascending unique order; the record codec rejects self-relays, provider-node mismatch, and multiple Libp2p offers. The consumer resolves each relay identity through raw kad.

### Runtime ownership for TASK-219

Provider truth comes only from live accepted /p2p-circuit listen addresses immediately before signing. Requested circuit listeners are installed before first announce, and a missing requested reservation blocks announce within a bounded integer deadline. A changed relay set produces a strictly newer Provide, never a content withdrawal. Consumer resolution first tries the provider directly, then transiently resolves signed hints and composes bounded circuit candidates, then retains TASK-218 known_relays only as a legacy fallback. Dynamic event-driven reannounce after later reservation churn is outside the minimum task scope; stale signed hints remain bounded retries until record TTL and should receive a follow-up if not implemented.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Commit 1842d1a implements bounded signature-bound relay NodeId hints, raw-kad relay resolution without address injection/cache, exact live accepted reservation truth before announce, exact ConnectionId routing, direct-first bounded circuit fallback, and multi-relay dead/live/severing/conflict bites. Vendored libp2p-stream is pinned at 0.4.0-alpha for exact open_stream_on_connection. Mandatory QA and architecture reviews passed; just e2e passed all 9 scenarios and 107 checks on the exact staged tree. Dynamic reannounce after later reservation-set churn remains intentionally out of scope and is tracked separately.
<!-- SECTION:FINAL_SUMMARY:END -->
