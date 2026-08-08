---
id: TASK-48
title: 'FREEZE: RawNarV1 addressed unit + iroh ALPN (golden vectors)'
status: In Progress
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 21:55'
labels:
  - irreversible
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The hardest wave-2 freeze (arch+codex: harder than the schema, cannot be versioned once peers hold blobs). Freeze the exact interop bytes: RawNarV1 = the exact nix-store --dump byte sequence; the BLAKE3 digest length/encoding; canonical NarHash + NodeId encodings; the iroh-blobs ALPN string; domain separation; numeric tags/bounds; and GOLDEN wire/hash vectors so two independent impls agree byte-for-byte. Separate UNIVERSAL content identity (NarHash <-> RawNarV1 BLAKE3) from TRANSPORT-SPECIFIC offers (iroh NodeId+blake3; a future BitTorrent needs an infohash/piece-layout locator, NOT just a tag). Freeze CONFIRMED at S6 interop (task-41), not before.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Golden vectors committed: for a fixed fixture NAR, the exact --dump bytes, its BLAKE3, and NarHash - a second impl (or a re-derivation) matches byte-for-byte
- [x] #2 The iroh ALPN constant + digest encoding + domain separation are pinned as named constants with a conformance test
- [x] #3 Content-identity (NarHash<->BLAKE3) is separated from transport-offer (NodeId+locator); a BitTorrent offer shape is representable (infohash/piece-layout slot), proving no fork
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FREEZE implemented; codex deep-gate round 1 was NO-GO on the claim wire format (architect GO, qa GO, codex confirmed the BLAKE3==iroh-blobs crux is sound and /iroh-bytes/4 IS the real current iroh_blobs ALPN). Round-2 fixes committed; re-parked In Progress awaiting RE-GATE. NOT Done.

FROZEN ENCODINGS (unchanged, crux-confirmed):
- content_id::Blake3Digest = BLAKE3(RawNarV1), plain unkeyed, NO domain sep (== iroh-blobs blob hash), wire 'blake3:'+64 lowercase hex.
- transport::NodeId = ed25519 pubkey, 64 lowercase hex, canonicalized on raw bytes (from_bytes).
- transport::BitTorrentInfoHash v1(20)/v2(32) hex slot.
- IROH_BLOBS_ALPN = /iroh-bytes/4 (codex confirmed correct).
- GOLDEN: lib fixture raw_nar_len=66048, NarHash sha256:06rgb4..., BLAKE3 blake3:95f49df0...; recipe vectors BLAKE3('')=af1349b9..., BLAKE3('nix-p2p/RawNarV1')=74f885af...

ROUND-2 CLAIM-WIRE CANONICALIZATION (commit for hashes: git log task-48):
1 (CRIT) ONE content identity per claim. Offers are now PURE locators (Iroh{node}, BitTorrent{infohash}); blake3 lives once in payload WholeNar{blake3} or once per HoldAnswer::Have{blake3,offers}. A two-blob claim is structurally unrepresentable (chose option (a)).
2 (CRIT) NarHashKey is a STRICT validated type: 32 sha256 bytes, canonical sha256:<52 lowercase nix-base32> via new daemon/src/nixbase32.rs (pinned to Nix's own printHash32 output). key:'not-a-nar-hash' now rejected on decode. Bridges source::NarHash via TryFrom (fallible; seam stays loose by wave-1 design, but real narinfo values are always canonical so they agree by construction).
3 (HIGH) Discriminator-aware Deserialize for ClaimPayload/TransportOffer: unknown TAG -> Unknown (task-37 forward-compat intact), malformed KNOWN tag (bad blake3/node) -> hard ERROR (no silent swallow; the task-13 defect species).
4 (MED) check-golden-vectors.py independently computes sha256(raw NAR) in nix-base32 vs trusting the manifest.
5 (LOW) hex decode lowercase-only (one canonical form); NodeId ed25519 curve-point validity deferred to task-39's iroh::PublicKey::from_bytes (like the ALPN==iroh_blobs::ALPN assert).

BITES proven live: finding2 lenient-parse -> claim_with_a_non_canonical_key_is_rejected FAILS; finding3 swallow -> malformed_known_payload_errors FAILS; finding1 structural. UntaggedPayload control encodes finding3 fails-before permanently in the suite. task-37 forward-compat + reserved-fields + bittorrent-representable all still green.

GATE: nix develop -c just build/lint/test/fmt exit=0 (68 lib tests incl nixbase32/claim/hexfmt; golden_vectors 2; check-golden-vectors independent NarHash ok); nix build .#daemon ok.

HONEST LIMITS: (1) IROH_BLOBS_ALPN and NodeId ed25519-point validity still defer structural checks to task-39 (both fail loudly at connect, corrupt no addressing). (2) source::NarHash left as the loose wave-1 seam String (not unified into the strict type) to avoid rippling into catalog/narinfo_cache and their fake-hash tests; the strict twin + fallible bridge gives 'agree by construction' for real values, which is the interop property that matters.

FORWARD-CARRY: task-39 iroh addresses by Blake3Digest under IROH_BLOBS_ALPN, NodeId via from_bytes, add ==iroh_blobs::ALPN + ed25519-point asserts; task-49 narinfo rewrite uses the raw unit; task-50 availability index computes Blake3Digest::from_raw_nar and keys on the strict NarHashKey.
<!-- SECTION:NOTES:END -->
