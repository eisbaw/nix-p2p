---
id: TASK-219
title: >-
  fabric-libp2p: general multi-relay /p2p-circuit resolution (propagate relay
  identity through the DHT) — ROUTE 2 follow-up to TASK-218
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-15 15:35'
updated_date: '2026-08-17 06:28'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## TASK-219 SPIKE findings (2026-08-17, re-verified on libp2p 0.56)

### 1. Empirical 0.56 root-cause result: circuit address STILL dropped to a third party
Probe (2-relay topology, reverted; not committed) added to nat_dht_resolve.rs. R1=bootstrap the
consumer knows; R2=relay the provider P reserves on but the consumer NEVER learns from config; C=
third-party consumer joining via R1 only. Four attribution points via SwarmHandle::locate_peer
(raw get_closest_peers addrs):
  (i)   P.listen_addrs():  HAS the circuit /ip4/.../tcp/<R2>/p2p/<R2peer>/p2p-circuit/p2p/<P>
  (ii)  R2.locate_peer(P): direct addr ONLY (no circuit)
  (iii) R1.locate_peer(P): BOTH direct AND the circuit addr  <-- identify+kad DID carry it
  (iv)  C.locate_peer(P):  direct addr ONLY (circuit DROPPED)  answered=3 (C DID contact R1)
VERDICT: on 0.56 the /p2p-circuit still does NOT reach a third party. The 0.54 diagnosis holds.
BUT the attribution is REFINED vs TASK-218: the drop is NOT in identify and NOT in kad storage
(R1 proves identify propagates the circuit and kad stores it, iii). The drop is in the MULTI-SOURCE
QUERY ADDRESS COLLECTION.

### 2. Exact mechanism (libp2p-kad 0.48 source)
behaviour.rs Behaviour::discovered() line ~1231:
    query.peers.addresses.insert(peer.node_id, addrs)
addresses is FnvHashMap<PeerId, SmallVec<[Multiaddr;8]>>. insert OVERWRITES the whole per-peer
address set with each responding source's view; into_peerinfos_iter() (query.rs ~318) returns the
final map. So the LAST source to report P wins. R2 and P themselves report P with only the thin
DIRECT addr, clobbering R1's richer direct+circuit set. find_closest_local_peers/KadPeer::from DO
include all kbucket addrs (the circuit would be served by R1), and there is NO receive-side filter -
the loss is purely the OVERWRITE (union would fix it). (Overwrite-vs-filter inferred from source +
observation; strongly supported: C contacted R1 which holds the circuit, yet C's final set is thin.)

### 3. Route A (make circuit survive identify->kad) = REJECTED
No public Config knob controls this. Config setters are timeout/replication/parallelism/disjoint/
record-filtering/kbucket-inserts/caching/... NONE affects query address merge. discovered() is
private; query.peers is pub(crate). Fixing it = FORK libp2p-kad to UNION addresses across sources
(and keep circuit addrs). That is exactly the non-converging-internals FORK hazard the task flags.
The task's viability bar ("clean supported knob, NOT an internals fork") is NOT met. OUT.

### 4. Route B (signed relay-hint in the record) = RECOMMENDED, but the task's premise needs correcting
CORRECTION: the FROZEN ProviderRecord codec does NOT drop unknown transport kinds - it FAILS CLOSED
(UnknownOffer/UnknownVersion/TrailingBytes). The tolerate-and-DROP forward-compat is the daemon JSON
CLAIM wire, NOT this codec (record_codec.rs module doc lines 20-28 say so explicitly). Therefore:
  - Route B CANNOT ride a silent tolerate-drop slot on the ProviderRecord; none exists, and adding one
    would REOPEN the exact TASK-110/223/224 no-enumeration vector (opaque tolerate-drop slot smuggles
    content ids). So the hint MUST be a TYPED, fully-validated, SIGNED field, not an opaque slot.
  - It MUST be a VERSIONED evolution: bump PROVIDER_RECORD_SCHEMA_VERSION 1->2, NEW golden file; v1
    goldens stay frozen/untouched (satisfies AC#3 "does not break the frozen golden vectors" - read as
    v1 vectors unchanged, v2 is a new set). Any body change alters the signing preimage, so an
    in-place additive-and-silently-ignored field is STRUCTURALLY IMPOSSIBLE here by design (AC#2
    no-unasked-field). Interop cost: v1-only nodes fail-closed on a v2 record (no interop until fleet
    upgrades) - the honest main risk, acceptable for a benign coordinated-fleet cache.
  - WIRE SHAPE: carry the RELAY IDENTITY only (relay NodeId, 32B), NOT its address. The consumer still
    resolves the relay's dial address via kad get_closest_peers(relay) - relays are PUBLIC/directly
    reachable so their addr survives (no overwrite problem for a direct addr). Keeps discovery
    kad-EXCLUSIVE (AC#2): relay identity arrives via the signed record, its address via kad; nothing
    out-of-band; check-discovery-no-shortcut.py NOT weakened.
  - SIGNATURE (task Q3): the hint is inside the signed preimage, so a HOSTILE RELAY cannot inject/forge
    a hint - only the provider signs. A lying provider naming a wrong relay only costs the consumer a
    wasted dial + fallback (same failure mode as today's over-compose). No attacker redirect.
  - NO-ENUMERATION (task Q1): fixed-size typed NodeId consumed ONLY as a relay identity for circuit
    composition; cannot carry a content id. Cap the relay-hint count (small, e.g. <=2) and require
    STRICT-ASCENDING canonical order like offers, so count/duplicate is not a covert channel (the
    223/224 count/byte/content trio).

### Recommendation: Route B, as schema-v2 signed relay-hint (relay NodeId), NOT a tolerate-drop slot.
Route A is a kad fork (rejected). Frozen-seam change -> full wire review + codex gate + golden regen.
<!-- SECTION:NOTES:END -->
