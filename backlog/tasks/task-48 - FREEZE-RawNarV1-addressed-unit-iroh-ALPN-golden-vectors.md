---
id: TASK-48
title: 'FREEZE: RawNarV1 addressed unit + iroh ALPN (golden vectors)'
status: Done
assignee: []
created_date: '2026-08-08 20:28'
updated_date: '2026-08-08 22:56'
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
FREEZE: addressed unit (BLAKE3 of RawNarV1) + iroh ALPN + golden vectors + canonical claim wire. Deep-gate: R1 architect+qa GO, codex NO-GO (5 findings) -> R2 fixes -> R3 SIMPLIFY-AT-ROOT (remove Value catch-alls, per mark-emulator B) -> R4 CLOSING (duplicate-key rejection + doc honesty). Re-parked In Progress awaiting FINAL re-gate. NOT Done.

FROZEN ENCODINGS (crux confirmed by codex):
- Blake3Digest = BLAKE3(RawNarV1), plain unkeyed, NO domain sep (== iroh-blobs blob hash), wire 'blake3:'+64 lowercase hex.
- NodeId = ed25519 pubkey 64 lowercase hex (canonicalized on raw bytes). BitTorrentInfoHash v1/v2 hex slot. IROH_BLOBS_ALPN=/iroh-bytes/4 (codex confirmed correct).
- NarHashKey = strict sha256:<52 lowercase nix-base32> via nixbase32.rs (pinned to Nix printHash32).
- GOLDEN: lib fixture 66048 B, NarHash sha256:06rgb4..., BLAKE3 blake3:95f49df0...; recipe vectors af1349b9 / 74f885af. daemon/tests/golden_vectors.rs (sandbox) + scripts/check-golden-vectors.py (independent re-derivation incl. NarHash).

CLAIM WIRE (canonical, single-identity, unambiguous):
- Content digest appears EXACTLY ONCE per claim: payload WholeNar{blake3} or Have{blake3}. Transport offers are PURE LOCATORS (Iroh{node} / BitTorrent{infohash}); Claim::content_id() -> Option<&Blake3Digest>.
- Claim is deny_unknown_fields; NO serde_json::Value catch-all. Unknown payload/transport KIND tolerated-but-INERT (payload->None, offer dropped, nothing retained/re-serialized). Malformed KNOWN kind ERRORS.
- 64 KiB decode size bound (MAX_CLAIM_WIRE_BYTES) before parse.
- R4: NoDuplicateKeys pre-parse guard rejects any repeated key at ANY object level (nested included) in all decode_* -> exactly one canonical parse (serde derive only catches top-level dup fields; the nested-offer dup is the real gap this closes). Kills the last last-wins ambiguity behind findings 1 (dup payload.blake3) and 4 (dup kind drops a malformed known).

BITES (all fails-before/passes-after, several proven live this session): strict NarHashKey rejects non-canonical; malformed-known payload/transport error; deny_unknown_fields rejects smuggled 2nd payload; size bound; duplicate payload.blake3 / duplicate kind / nested-offer duplicate key all rejected; canonical claims still decode.

DOC HONESTY (R4): corrected 3 stale comments (claim.rs + content_id.rs said offers carry the digest; daemon/Cargo.toml claimed a public Unknown(Value) catch-all) - comment-is-spec on a frozen surface.

GATE (every round): nix develop -c just build/lint/test/fmt exit=0; nix build .#daemon ok; golden checks ok.

HONEST LIMITS: (1) lossless relay preservation intentionally DROPPED (wave-2a has no relay) - filed task-55 (wave-2b); referenced in docs. (2) IROH_BLOBS_ALPN + NodeId ed25519-point validity defer structural asserts to task-39 (fail loudly at connect, corrupt no addressing). (3) source::NarHash left loose (wave-1 seam); strict wire twin + fallible bridge = agree-by-construction for real values.

FORWARD-CARRY: task-39 (iroh: address by Blake3Digest under IROH_BLOBS_ALPN, NodeId via from_bytes, add ==iroh_blobs::ALPN + ed25519-point asserts); task-49 (narinfo rewrite uses the raw unit); task-50 (availability index computes Blake3Digest::from_raw_nar, keys on strict NarHashKey, PRODUCES single-identity claims); task-55 (wave-2b relay + lossless preservation). Commits: 14e35c0, 1e45929, 4f8d7d0, 7095d82.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
DONE (irreversible freeze, 4 codex deep-gate rounds). Freezes the wave-2 interop bytes two independent daemons agree on. RawNarV1 = exact nix-store --dump stream; addressed unit = plain unkeyed BLAKE3(RawNarV1), no domain separation, blake3:<64 hex> - CRUX codex-confirmed: this EQUALS iroh_blobs::Hash (iroh Hash newtype over blake3::Hash; bao root == blake3::hash by construction), so a peer fetches by it directly; /iroh-bytes/4 confirmed the real current iroh ALPN. Content identity (content_id.rs) separated from transport locators (transport.rs, iroh NodeId + BitTorrent infohash v1/v2 slot proving no-fork). Claim WIRE hardened across 4 rounds into a canonical format: strict NarHashKey (32 sha256 bytes, sha256:<52 nix-base32>, validated vs nix hash convert both directions), content_id() single-identity (offers are pure locators, digest lives at most once - two-blob claim structurally unrepresentable), serde_json::Value catch-alls REMOVED (deny_unknown_fields; unknown kinds tolerated-but-inert per mark-emulator B; lossless-relay deferred to task-55 since wave-2a has no relay), 64 KiB decode bound before parse, NoDuplicateKeys whole-tree guard (rejects duplicate keys at any nesting incl nested offer objects/arrays - the gap serde deny_unknown_fields misses - while sibling-array-same-key-names correctly pass), malformed-known-kind errors. Golden vectors (raw_nar_v1.json) re-derived by check-golden-vectors.py from the pinned fixture with independent NarHash. Gate: build/lint/test/nix-build green (114 daemon tests). Reviews: architect GO, qa GO (bites mutation-verified), codex (4 NO-GOs each a real distinct wire-canonicalization defect, all closed; functional freeze final-verified sound - only 2 doc comments remained, orchestrator-fixed in-thread). Deferred (filed): task-39 (ALPN==iroh_blobs::ALPN assert + NodeId ed25519-point validity), task-53 (golden fail-closed when fixtures absent), task-55 (lossless relay, wave-2b). Commits 14e35c0/1e45929/4f8d7d0/7095d82/100486d.
<!-- SECTION:FINAL_SUMMARY:END -->
