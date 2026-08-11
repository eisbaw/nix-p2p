---
id: TASK-140
title: >-
  Define PeerFabric intentional P2P seam (static, compile-time-selectable
  backend)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-11 21:11'
updated_date: '2026-08-11 22:09'
labels:
  - seam
  - p2p
  - architecture
  - static-dispatch
  - wave-2c
  - api-first
dependencies:
  - TASK-114
documentation:
  - docs/peer-fabric-seam.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define the intention-level internal seam over ANY p2p substrate (iroh, libp2p, future), so the backend becomes a COMPILE-TIME selection (static dispatch, feature-gated type alias) and the daemon stops being welded to iroh below the NarSource/Transport seam.

The seam names WHAT the daemon wants (find providers, announce availability, fetch NAR, serve NAR, ask a peer, notice nearby peers) organized as the PRD Wave-2c six participation axes, NOT how a stack does it. Backend = compile-time; operator participation profile = runtime.

This SUPERSEDES the hand-rolled-Kademlia framing of TASK-126 and SUBSUMES the intent of TASK-100 (ContentDiscovery seam v2): the DHT becomes a ProviderDirectory backend we ADOPT (iroh-dht-experiment or libp2p-kad), not invent. Frozen surfaces (ContentKey derivation, ProviderRecord codec) are chosen to match the adopted backend rather than a bespoke one.

Full API proposal for review: docs/peer-fabric-seam.md. API FIRST, no implementation, pending mped-architect pressure-test and owner review.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Seven capability traits frozen with intention doc comments: ProviderDirectory, AvailabilityAnnouncer, NarTransfer, NarServer, PeerHoldQuery, LocalPeerDiscovery, and NodeLocator (node/address = PRD axis 2, gate-able, not buried in fetch); reviewed against the PRD Wave-2c six axes for completeness and non-overlap.
- [ ] #2 Lookup<T> is a 3-way enum (Found/Miss/Unavailable{reason}) not Result<Option>, so 'MISS only after a healthy completed lookup' is legible at the type level; UNAVAILABLE reasons cover bootstrap-outage/partition/deadline/insufficient-routing.
- [ ] #3 Exposure has ONE sink: a single ExposureLedger written as disclosures happen (no duplicate per-call Vec); each capability also answers an a-priori declared_exposure() surface for TASK-120 preflight; docs state the ledger is COOPERATIVE and the packet/source-mutation guard is the adversarial oracle.
- [ ] #4 Backend selection is compile-time: a feature-gated 'type Fabric = ...' alias over a concrete struct (unselected backend not linked); capabilities are Option<Arc<dyn ...>> fields (object-safe, per-axis fakeable) where None == profile-off; the composition root asserts the profile's required axes are present and fails fast. No dyn-vs-static perf claim is made (all axes are I/O-bound).
- [ ] #5 Backend capability vs profile activation are distinct concerns; a fresh upstream_only fabric exposes no P2P axis; NarTransfer keeps the existing runtime tag-keyed TransportRegistry (a claim carries several offers chosen at request time), documented as a legitimately-orthogonal runtime axis, not a hole in compile-time selection.
- [ ] #6 find_providers returns Vec<ProviderRecord> via a Kademlia VALUE store (libp2p put_record/get_record equivalent) on every backend, so the signed record (who + how + expiry) is learnable without the provider being online; the record size cap and store TTL are reconciled with our expiry field.
- [ ] #7 Policy stays above the seam (eligibility, profile, budget numbers); stack-neutrality is proven by mapping all seven axes to iroh and libp2p backends including the dual-stack arrangement, with no serving-core change to swap; a FakeFabric exercises the whole daemon substrate-free.
- [ ] #8 The seam is a standalone 'peer-fabric' crate (traits + value types + Lookup + Exposure + FakeFabric) with ZERO iroh/libp2p dependencies; the frontend crate 'daemon-core' depends on peer-fabric only, so the core compiles and unit-tests against FakeFabric with no P2P stack linked.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation plan (TASK-140, standalone peer-fabric crate; consumed by nobody yet):
1. New workspace crate peer-fabric with ZERO iroh/libp2p deps (normal dep: async-trait; dev: tokio macros+rt). Inherit workspace.package + workspace.lints. Add to root members.
2. Own canonical primitive newtypes (peer-fabric is their home; TASK-141 re-points daemon): NodeId(32 ed25519 bytes), Blake3Digest(32), TransportTag, TransportOffer/InfoHash locator type, tiny lowercase-hex.
3. Value types: ContentKey(32, domain-sep discovery key; derivation is TASK-126), ProviderRecord(key,provider,offers,sequence,issued_at,expiry,signature[64]), DialInfo (opaque above seam), ResolutionPolicy.
4. Outcome: Lookup<T> = Found/Miss/Unavailable(reason) 3-way (AC#2); Unavailable reasons bootstrap-outage/partition/deadline/insufficient-routing/backend.
5. Exposure single sink: Recipient, Disclosed, Exposure, ExposureLedger (one sink, std Mutex), ExposureSurface + declared_exposure() a-priori (AC#3, cooperative-ledger caveat in docs).
6. Budgets: DiscoveryBudget, AnnounceBudget; re-declare SafetyEnvelope/ServeBudget shapes for signatures.
7. Seven capability traits w/ intention doc-comments mapped to PRD Wave-2c six axes (AC#1): ProviderDirectory, AvailabilityAnnouncer, NodeLocator, NarTransfer, NarServer, PeerHoldQuery, LocalPeerDiscovery. Batch hold types owned here.
8. Umbrella PeerFabric: Option<Arc<dyn>> accessors + transfer registry + exposure_ledger (AC#4 shape; binary/type-alias wiring deferred to TASK-141).
9. FakeFabric + per-axis fakes; unit tests: MISS!=UNAVAILABLE representable, ledger records, find_providers->Vec<ProviderRecord>, upstream_only(all None) exposes no axis.
10. Gate: just build/lint/test all green incl. independence. e2e UNAFFECTED (peer-fabric consumed by nobody).
Deferred to TASK-141 (noted in code+notes): feature-gated type alias / two-binaries composition root; daemon-core depends on peer-fabric; delete daemon's duplicate NodeId/Blake3Digest and re-point at peer-fabric.
<!-- SECTION:NOTES:END -->
