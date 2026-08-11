---
id: TASK-141
title: >-
  IrohFabric adapter + crate split: extract fabric-iroh, daemon-core depends
  only on peer-fabric, exactly one backend links
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-11 21:22'
updated_date: '2026-08-11 23:58'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies:
  - TASK-115
  - TASK-140
documentation:
  - docs/peer-fabric-seam.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement PeerFabric and its capability traits over the concrete iroh stack, moving the currently-welded iroh modules (iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http; ~195 iroh refs) BEHIND the TASK-140 seam. Without this task the seam is aspirational and a second backend (libp2p) can never be added - nothing else in the backlog covers de-welding iroh.

NarTransfer/NarServer wrap iroh-blobs on the shared TASK-115 endpoint; NodeLocator wraps the done TASK-138 pkarr NodeId->address lookup; ProviderDirectory/AvailabilityAnnouncer are provided by the adopted backend from TASK-126/103. The serving core must require NO change (it already holds zero iroh types).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 IrohFabric implements PeerFabric as a concrete struct with Option<Arc<dyn ...>> capability fields; the feature-gated 'type Fabric = IrohFabric' alias selects it at compile time; a peers-off/upstream_only construction exposes no P2P axis and links/opens no discovery machinery.
- [ ] #2 NarTransfer and NarServer wrap iroh-blobs on the shared TASK-115 endpoint; the existing tag-keyed TransportRegistry is reused unchanged for offer dispatch.
- [ ] #3 NodeLocator wraps the TASK-138 pkarr NodeId->address lookup and records Exposure to the single ledger; resolution mechanism is policy-selected (explicit peer list vs pkarr/Mainline/DNS) and gate-able per profile.
- [ ] #4 The welded modules (iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http) are reached only through the seam from daemon code; a guard/test asserts the serving core and App hold no concrete iroh types outside the fabric module.
- [ ] #5 No serving-core change is required: the same e2e/S6 peer-served-build passes with the daemon driving IrohFabric through PeerFabric rather than concrete iroh calls.
- [ ] #6 IrohFabric lives in its own 'fabric-iroh' crate (peer-fabric + iroh + iroh-blobs); the welded iroh modules (iroh_runtime, iroh_node_*, iroh_publication*, pinned_http) move into it; 'daemon-core' holds no concrete iroh type and depends on peer-fabric only.
- [ ] #7 Two product binaries daemon-iroh and daemon-libp2p, each = daemon-core + exactly ONE fabric-* crate; the binary is the backend choice (no features, no cfg); each fn main constructs its fabric and calls daemon_core::run(fabric). A build guard proves daemon-iroh's dependency closure contains no libp2p and daemon-libp2p's contains no iroh, so tests and tournament runs never conflate backends.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Re-export unification (low-churn single-source):
Increment 1 (keystone, this session):
1. Enrich peer-fabric ids into a full SUPERSET of daemon value types:
   - add serde + blake3 deps (not p2p; ids have frozen canonical string forms).
   - new peer-fabric/src/hexfmt.rs (mirror daemon: encode/decode_fixed/decode_var).
   - NodeId: +FromStr, +serde, +NodeIdParseError.
   - Blake3Digest: +from_raw_nar/stream_raw_nar (recipe moves here), +FromStr(blake3:),
     +serde, +DigestParseError, +BLAKE3_DOMAIN_SEPARATION/STREAM_CHUNK_BYTES + compile-assert.
   - InfoHash: +v1/v2 ctors, +FromStr, +serde, +InfoHashParseError.
2. daemon depends on peer-fabric; DELETE daemon struct defs in content_id.rs (Blake3Digest),
   transport.rs (NodeId, BitTorrentInfoHash), transport_fetch.rs (TransportTag). Keep each
   module's freeze narrative + conformance tests, replace defs with pub use peer_fabric::...
   (BitTorrentInfoHash = alias of peer_fabric::InfoHash). Keep IROH_BLOBS_ALPN in transport.rs.
3. Reconcile TransportTag::of(&KnownTransport): add KnownTransport::tag()->TransportTag in claim.rs,
   re-point 5 call sites (peer-fabric's of() takes the seam's TransportOffer).
4. Cross-crate equivalence guard: daemon conformance tests now pin peer_fabric type against the
   frozen golden vectors; add a guard test asserting wire encodings agree.
5. FULL gate (build/lint/test + e2e); commit.
Increments 2 (extract daemon-core + fabric-iroh, IrohFabric) and 3 (daemon-iroh bin) are large;
land what is clean, file follow-ups for the rest.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Crate topology (owner directive 2026-08-11: exactly one P2P backend compiled in, never both required): peer-fabric (seam, TASK-140) <- daemon-core (frontend, no p2p) <- fabric-iroh (this task) / fabric-libp2p (later, TASK-103 if selected) <- daemon bin (one backend, optional-dep + mutually-exclusive feature). fabric-libp2p is not a workspace member until libp2p is chosen. testproxy independence is unaffected (it depends on none of these). See docs/peer-fabric-seam.md.

Forward-carried from TASK-140 (peer-fabric seam landed, commit 9073806):
- peer-fabric is now the CANONICAL HOME of NodeId (32 ed25519 bytes), Blake3Digest (32 bytes), TransportTag, TransportOffer/InfoHash, ContentKey, ProviderRecord, DialInfo, Lookup, Exposure*, budgets. TASK-141 MUST delete the daemon's duplicate NodeId (daemon::transport), Blake3Digest (daemon::content_id), TransportTag (daemon::transport_fetch) and re-point the daemon at peer-fabric's copies. They are byte-compatible by construction (same lengths, same lowercase-hex canonical form) but are DISTINCT TYPES today.
- No cross-crate equivalence guard exists (peer-fabric cannot depend on daemon). Until the daemon copies are deleted, treat any edit to peer-fabric's NodeId/Blake3Digest/TransportTag/TransportOffer as requiring a mirrored daemon edit; ideally TASK-141 lands a test proving the wire encodings agree, then removes the duplicates. TransportTag::as_str()/TransportOffer variants were written to match daemon::claim::KnownTransport serde tags ('iroh','bittorrent') - verify on merge.
- Composition root is TASK-141's: the two thin binaries (daemon-iroh/daemon-libp2p), each daemon_core::run(fabric), must assert the selected profile's REQUIRED axes are Some and FAIL FAST otherwise (the peer-fabric doc's Unsupported-ZST-dilemma resolution). peer-fabric only provides the Option<Arc<dyn>> shape; it does not assert requiredness.
- peer-fabric's SafetyEnvelope/ServeBudget mirror daemon::transport_iroh's shapes; NarTransfer::fetch was given expected_size:Option<u64> to match daemon::transport_fetch::Transport::fetch (the seam doc had dropped it). Reconcile the daemon's real IrohTransport onto peer-fabric::NarTransfer without losing the mid-stream NarSize abort.
- peer-fabric::ServeHandle now owns an opaque Box<dyn Send+Sync> teardown guard; the IrohFabric NarServer impl must attach its real listener/task-abort there so drop = teardown.

INCREMENT 1 LANDED (commit d01fb42) - value types de-welded behind the seam. TASK-141 stays In Progress; increments 2+3 filed as follow-ups.

What landed (inc 1):
- daemon now depends on peer-fabric. Deleted the daemon's DUPLICATE value types and moved them to their canonical home peer_fabric::ids: NodeId, Blake3Digest (incl the frozen BLAKE3(RawNarV1) recipe from_raw_nar/stream_raw_nar + BLAKE3_DOMAIN_SEPARATION compile-assert), TransportTag, BitTorrentInfoHash (= peer_fabric::InfoHash). daemon content_id.rs/transport.rs/transport_fetch.rs now re-export peer_fabric's copies from the old module paths (single definition below the seam; freeze narratives stay put).
- peer-fabric gained serde + blake3 deps and a hexfmt codec module. FORCED by the orphan rule: the daemon's claim codec relies on the types' serde/FromStr impls and cannot add them to a foreign type, so they had to move WITH the types. Neither dep is a p2p stack, so AC#8 (no iroh/libp2p in peer-fabric) holds. content.rs stays serde-free (TASK-126 owns that codec) - asymmetry documented in ids.rs so nobody adds derive(Serialize) to ContentKey.
- new KnownTransport::tag() bridges the daemon wire offer enum to the seam TransportTag (the seam's TransportTag::of takes the seam's TransportOffer, a different representation). known_transport_tags_agree_with_the_wire_tags now also asserts offer.tag().as_str() == offer.wire_tag() so the seam string is guarded (was a 4th unguarded copy - mped finding).
- deleted daemon's now-dead hexfmt module (the codec lives once in peer-fabric); fixed the doc_citations SOURCES list and the nixbase32 doc link.

Equivalence guard resolution: with the daemon duplicate deleted there is ONE impl, so a second-impl diff is moot. The genuine cross-crate wire anchor is daemon/tests/golden_vectors.rs + claim_wire_golden.rs (daemon re-export vs committed golden JSON) - both pass. The recipe conformance vectors live once in peer_fabric::ids; daemon content_id keeps only a light re-export smoke test (not re-hardcoding the golden hex - avoids triplication, mped finding).

GATE (all green): build; lint (clippy -D warnings + independence + fmt); cargo workspace 479 passed / 0 failed; just e2e 5/5 scenarios incl s6-p2p (peer-served build over iroh) - the serving core required NO change (AC#5 holds for the value-type move).

REVIEWS: qa-test-runner (independently green) + mped-architect. All findings addressed before commit: (1) claim.rs doc overclaim -> added the direct offer.tag().as_str()==wire_tag() assertion; (2) golden-vector triplication + 'cross-crate equivalence guard' overstatement -> trimmed daemon content_id tests to a re-export smoke test, reframed docs; (3) restored the dropped rejects_non_hex hexfmt test (non-zero-index NonHexChar, now also covers decode_var); (4) documented the serde/content.rs asymmetry.

GOTCHA (cost real time): the Nix flake build (just e2e) only sees GIT-TRACKED files, so a new untracked source file (peer-fabric/src/hexfmt.rs) failed 'mod hexfmt; file not found' INSIDE the derivation while cargo-based just build/test/lint (working tree) passed. Fix: git add new files before running just e2e. Any future new-file increment must stage before the e2e gate.

DEFERRED (large; filed):
- TASK-144 = increment 2 (daemon-core + fabric-iroh extraction, IrohFabric: PeerFabric, NodeLocator/NarTransfer/NarServer wiring, composition-root required-axis assertion, real ServeHandle teardown, move IROH_BLOBS_ALPN into fabric-iroh). deps TASK-141.
- TASK-145 = increment 3 (daemon-iroh thin binary + no-libp2p dep-closure guard). deps TASK-144.
- TASK-146 = daemon-libp2p thin binary, BLOCKED on a future fabric-libp2p (deps TASK-103); deliberately NOT stubbed per the contract.
ACs #1-#7 of TASK-141 remain to be completed by TASK-144/145 (the IrohFabric struct, backend wiring, crate split, two-binary composition root); inc 1 delivered the debt-removal keystone (delete daemon dups + re-point + guard) those build on.
<!-- SECTION:NOTES:END -->
