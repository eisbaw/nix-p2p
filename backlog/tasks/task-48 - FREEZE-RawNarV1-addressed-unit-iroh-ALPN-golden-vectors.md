---
id: TASK-48
title: 'FREEZE: RawNarV1 addressed unit + iroh ALPN (golden vectors)'
status: In Progress
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 21:11'
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
FREEZE implemented; self-verified, awaiting DEEP gate (qa+architect+codex). NOT Done.

CANONICAL TYPES + ENCODINGS (frozen):
- content_id::Blake3Digest = BLAKE3(RawNarV1), 32 bytes. Wire string 'blake3:'+64 lowercase hex. RawNarV1 = exact 'nix-store --dump' stream (uncompressed NAR; nix defines it). Recipe: PLAIN UNKEYED BLAKE3, NO domain separation (BLAKE3_DOMAIN_SEPARATION=None) so the digest EQUALS the iroh-blobs blob hash -> a peer fetches by it directly. Hex over nix-base32: reproducible by stock b3sum, no shared table, fixed-width, independent of any transport crate Display.
- transport::NodeId = iroh ed25519 pubkey, 32 raw bytes, wire = 64 bare lowercase hex. Canonicalized on RAW BYTES; task-39 rebuilds via iroh::NodeId::from_bytes, never depending on iroh's Display.
- transport::BitTorrentInfoHash = enum V1(20B SHA1)/V2(32B SHA256); wire hex, length (40/64) disambiguates. Proves a BT locator (infohash/piece-layout) is representable.
- transport::IROH_BLOBS_ALPN = b'/iroh-bytes/4' (stock iroh-blobs, per PRD line 210).

GOLDEN VECTORS (daemon/tests/golden/raw_nar_v1.json, single source of truth):
- fixture 'lib' (compression=none, so served .nar == raw NAR): raw_nar_len=66048, NarHash sha256:06rgb4vfjsg365xwwdjz12qhjnvg3w0agfvyqfp977hp3yk2bczb, BLAKE3 blake3:95f49df0cabd4f2cab42dfb89911ee9aa445a5126e445e0b5006532aef7d6638.
- recipe vectors: BLAKE3('')=af1349b9... (published empty vector -> pins plain unkeyed), BLAKE3('nix-p2p/RawNarV1')=74f885af...
- daemon/tests/golden_vectors.rs (include_str!, fixture-free) checks encodings in the Nix sandbox; scripts/check-golden-vectors.py RE-DERIVES from the real fixture (byte-for-byte, AC#1). BITES proven: recipe mutation (domain sep) fails golden tests; ALPN mutation fails conformance; corrupted golden digest fails python re-derivation.

CONTENT-vs-TRANSPORT SEPARATION: universal identity (Blake3Digest) lives in content_id.rs with ZERO transport knowledge; per-transport locators (NodeId, infohash) + ALPN live in transport.rs. Every claim offer carries the shared Blake3Digest + its own locator -> a 2nd transport adds a locator+offer variant, never forks the identity.

claim.rs: replaced String placeholders RawNarBlake3/NodeId/BitTorrentInfoHash with the canonical typed encodings. task-37 tests still pass (updated to real hex/blake3: forms; wire_strings_match_typed guards the literals).

GATE: nix develop -c just build/lint/test/fmt all green; nix build .#daemon ok (flake src widened to keep tests/golden/*.json). blake3 crate daemon-only (independence green).

HONEST LIMITS:
1. IROH_BLOBS_ALPN pinned WITHOUT an iroh dep (task-39 adds iroh). '/iroh-bytes/4' is my best knowledge of the stock value and is an ASSUMPTION; task-39 MUST assert ==iroh_blobs::ALPN. Low risk: a wrong ALPN fails LOUDLY at connect (S6), corrupts no held bytes, reconcilable at S6.
2. iroh NodeId string form assumed; mitigated by canonicalizing on raw bytes + from_bytes/as_bytes, so iroh Display churn cannot break us.
3. --dump reproduction: golden is a COMMITTED constant derived once via b3sum on the pinned reproducible fixture; cargo tests need no nix. Python re-derivation needs the fixture (fast tier ok? no - 'lib' is fast-tier; runs under just test).

FORWARD-CARRY: task-39 iroh addresses blobs by this Blake3Digest under IROH_BLOBS_ALPN, NodeId via from_bytes; add ==iroh_blobs::ALPN assert. task-49 narinfo rewrite uses NarSize/raw unit (compressed .nar.xz is transport-only, never the addressed unit). task-50 availability index computes this same BLAKE3 (Blake3Digest::from_raw_nar).
<!-- SECTION:NOTES:END -->
