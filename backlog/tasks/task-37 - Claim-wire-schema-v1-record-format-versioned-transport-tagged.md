---
id: TASK-37
title: 'Claim wire schema v1 (record format, versioned, transport-tagged)'
status: Done
assignee: []
created_date: '2026-08-08 20:12'
updated_date: '2026-08-08 20:44'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The networks shared language and first wave-2 FROZEN surface. Design the claim record: {schema_version, key=NarHash, payload: enum WholeNar{blake3} (future CastoreRoot), holders:[NodeId], transport: enum Iroh (future BitTorrent), reserved fields for v2 signed-narinfo-relay + claim signatures}. A peer ignores payload/transport variants it does not understand (forward-compat). The DHT KEY DERIVATION is deliberately NOT frozen here (deferred to the wave-2b DHT spike) - this is the record format only. Irreversible: once two daemons exchange claims this cannot change without a version bump + network split.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Serde (de)serialization round-trips; a claim with an unknown payload/transport variant parses and is ignored, not an error (forward-compat test)
- [ ] #2 schema_version present and checked; a wrong-version claim is rejected cleanly (bite)
- [ ] #3 Reserved fields exist for signed-narinfo-relay and claim-signatures so v2 needs no wire break (documented, not implemented)
- [ ] #4 BitTorrent transport tag is representable (proves the schema admits a 2nd transport without a fork), even though only Iroh is implemented
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE as a DRAFT (freeze CONFIRMS at S6/task-41, per review-revision). Delivered daemon/src/claim.rs: versioned Claim record + HoldQuery/HoldResponse envelope, serde derives, JSON as the draft codec (binary codec is a velocity surface). All ACs + the 5 review-note changes met; light gate green (build/lint/test/fmt + nix build .#daemon).

Design:
- Forward-compat has TWO axes kept distinct: (a) unknown VARIANT at the supported schema_version survives verbatim + is ignored (ClaimPayload::Unknown / TransportOffer::Unknown via serde untagged catch-all holding serde_json::Value; struct-level unknown fields via #[serde(flatten)] extra) - a relaying old node does not destroy a future peer's data; (b) wrong schema_version is a hard network-split boundary, rejected cleanly by decode_*(). Tests prove raw serde ACCEPTS v999 while decode_claim REJECTS it, so the check (not the parser) draws the line.
- Transport offer carries iroh's needs: Iroh{node: NodeId, blake3: RawNarBlake3} - a holder NodeId alone is insufficient, a consumer fetches by BLAKE3. BitTorrent{infohash, blake3} is a REPRESENTABLE known variant (wire tag pinned 'bittorrent') proving a 2nd transport is not a fork; no backend (task-38). A genuinely-future 3rd transport lands in TransportOffer::Unknown.
- holders:[NodeId] and transports:[TransportOffer] both exist and are NOT redundant: a BitTorrent coordinate is an infohash not a NodeId, so transports can't be derived from holders. Documented.
- Reserved v2 fields relay:Option<SignedNarinfoRelay> + signatures:Vec<ClaimSignature> present, skip_serializing_if empty in v1, and a REAL round-trip test proves a populated value survives on the wire (not verify-by-trust).
- Query envelope is yes/no only (HoldAnswer::Have{offers}|Absent, flattened onto the response) - no enumeration message exists by construction.

GOTCHAS / honest limits:
- Untagged catch-all is JSON-shaped (serde_json::Value). When the binary wire codec (CBOR/postcard) is frozen, the catch-all value type must be revisited. Follow-up -> task-48.
- untagged swallows a MALFORMED known variant into Unknown (liberal-accept); acceptable for a forward-compat draft, documented.
- NodeId/RawNarBlake3/BitTorrentInfoHash are String placeholders; canonical byte encoding is TODO(task-48) RawNarV1/NodeId freeze - NOT settled here.
- NarHashKey is a serde twin of the frozen source::NarHash (bridged via From/to_nar_hash) rather than adding serde to the frozen wave-1 source.rs; consider unifying at task-48.
- serde + serde_json added to the DAEMON crate ONLY (testproxy stays std-only); not HTTP-stack crates so independence guard unaffected.
- I did NOT run 'just e2e' (containers): this is a pure additive types module with no wiring into the serving path; the orchestrator's review tier (qa-test-runner + mped-architect per global CLAUDE.md) was deferred to the orchestrator.

FORWARD-CARRY: task-48 (RawNarV1/NodeId byte encoding freeze + catch-all value type + serde-on-seam unification), task-38 (transport trait consumes KnownTransport), task-40 (discovery uses HoldQuery/HoldResponse), task-50 (availability index produces Claim).
<!-- SECTION:NOTES:END -->
