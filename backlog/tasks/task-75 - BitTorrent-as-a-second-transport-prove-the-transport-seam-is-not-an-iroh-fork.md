---
id: TASK-75
title: >-
  BitTorrent as a second transport (prove the transport seam is not an iroh
  fork)
status: To Do
assignee: []
created_date: '2026-08-09 21:01'
updated_date: '2026-08-10 14:08'
labels:
  - wave-2b
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
PRD wave-2 scope names BitTorrent as the SECOND transport, explicitly so that 'the transport interface and the claim schema must admit it without a network fork'. The seam already exists and was built with this in mind: daemon/src/transport_fetch.rs has the Transport trait (fetch by Blake3Digest + a KnownTransport offer), TransportRegistry dispatches on the offer's transport tag, and the FROZEN claim schema (daemon/src/claim.rs) already carries BitTorrentInfoHash{V1[20]/V2[32]} in daemon/src/transport.rs and a transport discriminator per offer.

So the value of this task is partly the transport itself and partly a FALSIFICATION TEST of a frozen design decision: if adding BitTorrent requires changing the claim wire schema, then the schema freeze was wrong and we learn it here rather than after the network exists.

Note the addressing mismatch that makes this non-trivial: our addressed unit is RawNarV1 keyed by BLAKE3, while BitTorrent addresses by infohash over a piece-hashed torrent. The claim schema's per-offer locator is what bridges them - the content identity (BLAKE3) stays universal, the locator is transport-specific. Verify that story survives contact with a real BitTorrent client, and that gate-1 (verify what arrived hashes to the claimed BLAKE3) still holds when the transport's own integrity scheme is SHA-1/SHA-256 pieces rather than bao.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A BitTorrent Transport impl fetches a raw NAR and passes gate-1 (BLAKE3 of the received bytes == the claimed content id), then gate-2 (nix accepts sig+NarHash) - shown end to end, not in a unit test alone
- [ ] #2 THE FALSIFICATION: adding it required NO change to the frozen claim wire schema. If a change WAS required, say so plainly and treat the freeze as having been premature - do not quietly amend a frozen surface
- [ ] #3 Both transports coexist: a claim carrying both an iroh and a BitTorrent offer resolves via either, and the registry's selection is deterministic and tested
- [ ] #4 Honest limits: what BitTorrent adds that iroh does not (and vice versa) - swarm size, NAT behaviour, tracker/DHT dependency, and whether piece-level integrity buys anything given our whole-NAR BLAKE3 gate
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
## CARRIED FORWARD from TASK-91 round 6 (the batch call shape you inherit)

A TRANSPORT OFFER IS NOT ALWAYS PEER-SCOPED, and assuming it is produced a live
bug. Iroh's locator is the holder NodeId - one value for a whole batch -
but BitTorrent's is an infohash, which addresses one piece of CONTENT. The
first batch response hoisted ONE offer list to the envelope and let every Have
share it; key 2's claim silently received key 1's infohash. The fix:
BatchHoldResponse carries an offer DICTIONARY and each Have names its own entries
BY INDEX (claim.rs BatchHoldAnswer::Have::offer_indices), with every index in
range, no index repeated inside one answer, and every dictionary entry referenced
by at least one Have - so an all-Absent response cannot carry a locator at all.
DO NOT re-introduce a response-wide offer list in any new mechanism.

TWO RULES THAT COST NOTHING TO KEEP AND ARE EXPENSIVE TO RE-DISCOVER:
  * Unknown transport kinds are tolerate-but-drop. On an INDEXED list that means
    the decoder must keep position-preserving SLOTS, validate against the RAW
    positions, then compact and RE-INDEX together. BatchHoldResponse deliberately
    has no derived Deserialize so this cannot be bypassed.
  * serde deny_unknown_fields on an internally-tagged enum is honoured for STRUCT
    variants and SILENTLY INERT for UNIT variants. Any new answer enum must use
    empty struct variants (`Absent {}`), which emit identical bytes.

BOUNDS ARE TYPE INVARIANTS, NOT CALLER PRECONDITIONS: the cap is applied to the
caller-supplied asked-count itself, the responder hard-checks it (it was a
debug_assert, i.e. absent in release), the compatibility shim checks it before
issuing any probe, and every encoder gates its OUTPUT length so this node cannot
emit a message it would itself refuse.

THIS TASK IS THE REASON C1 WAS A BUG AND NOT A STYLE POINT: BitTorrent's locator
is the thing that is per-content. When the backend lands, a peer answering a full
256-key batch with iroh + a distinct infohash per key measures 58 910 B against
the 65 536 B pre-parse gate - it FITS, with ~10% spare, only because the offers
are indexed. The same answer with the offers inlined per Have is ~79 912 B, i.e.
UNSENDABLE. If this task ever needs a third per-content locator kind, re-measure
before assuming the cap still holds.
<!-- SECTION:NOTES:END -->
