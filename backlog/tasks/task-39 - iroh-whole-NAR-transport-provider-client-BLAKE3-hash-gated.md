---
id: TASK-39
title: 'iroh whole-NAR transport (provider + client, BLAKE3 hash-gated)'
status: Done
assignee: []
created_date: '2026-08-08 20:12'
updated_date: '2026-08-09 00:10'
labels: []
dependencies:
  - TASK-38
  - TASK-48
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FIRST transport (owner: iroh first prio). A node runs an iroh-blobs PROVIDER serving its /nix/store NARs (rendered via nix-store --dump, addressed by raw-NAR BLAKE3) and a CLIENT that fetches a NAR by BLAKE3 from a peer NodeId. Every fetched blob is BLAKE3-verified by iroh incrementally AND the assembled NAR passes sha256==NarHash. Add iroh to Cargo.lock (daemon-only; testproxy stays std-only - independence guard). n0 relay dependence noted as a soft-centralization limit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Node B provides a fixture NAR; node A fetches it by BLAKE3 over iroh and it passes both the BLAKE3 (transport) and sha256==NarHash (trust) gates - byte-identical to the fixture
- [ ] #2 A corrupted/wrong blob from a lying provider fails the gate; no wrong bytes reach the store (bite)
- [ ] #3 iroh is a daemon-only dep; the independence guard still passes (testproxy does not gain iroh)
- [ ] #4 ALPN reconciliation (task-48 deep-gate finding 2): once iroh is a dependency, assert IROH_BLOBS_ALPN == iroh_blobs::ALPN (compile-time or test) and realign the constant to the pinned iroh version - the task-48 freeze deferred this cross-check here; a wrong ALPN must fail loud at connect, and the offer needs no format field (whole-NAR is always iroh Raw format)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REVIEW REVISION: (1) task-39 no longer DEFINES the addressed unit - it CONSUMES the frozen RawNarV1 from task-48 (dep added). (2) Corruption bite must be SPLIT (codex#6): (a) mutated bytes fail the BLAKE3 TRANSPORT gate; (b) a DIFFERENT valid NAR with its own valid BLAKE3 PASSES transport but fails the signed sha256==NarHash TRUST gate - test both, they are different gates.

FROM task-38 (Transport trait shipped, commit 0d9d6e7): implement iroh as a Transport in daemon/src/transport_fetch.rs. Fill 'impl Transport for IrohTransport' with tag()=TransportTag::Iroh and fetch(content: &Blake3Digest, offer: &KnownTransport). Match offer -> KnownTransport::Iroh{node}; dial via NodeId::as_bytes() -> iroh::NodeId::from_bytes; fetch the blob addressed by content.as_bytes() over IROH_BLOBS_ALPN; iroh-blobs' bao gives incremental BLAKE3 verify (gate1) fail-fast so you never buffer a whole lying blob. Register it in the TransportRegistry the TransportNarSource holds - NO seam change. The corruption bite: make iroh return/accept wrong bytes -> fetch must error (TransportError::IntegrityMismatch/Unavailable) -> fetch_via_offers records it and tries next -> this SPLITS gate1 (transport BLAKE3) from gate2 (Nix sha256). Also: the pinned IROH_BLOBS_ALPN == iroh_blobs::ALPN assert (already your AC) + NodeId ed25519 curve-point validation deferred from transport.rs freeze. Keep verify_blake3() as the single-source-of-truth gate1 recipe.

DONE (commit 120463e). Real iroh whole-NAR Transport shipped: IrohProvider (iroh-blobs MemStore served under the stock ALPN via iroh Router; seed() content-addresses raw NAR by BLAKE3(RawNarV1)==iroh blob hash, task-48 freeze re-checked) + IrohTransport (impl Transport tag=Iroh, daemon/src/transport_iroh.rs). Pinned iroh 1.0.3 + iroh-blobs 0.103.0 (0.103 requires iroh ^1.0; pinned together in Cargo.lock). crane vendors from Cargo.lock -> NO flake edit needed.

Gates (nix develop -c just, LIGHT own-run): build ok; lint ok (clippy -D warnings, fmt, ruff, source-guard, lock-sources); independence ok (HTTP-stack denylist passes even though iroh transitively pulls hyper/reqwest into the daemon, because testproxy reaches no shared stack); test ok (workspace + fixtures + golden + measure self-test); iroh_transport 5/5; nix build .#daemon ok (/nix/store/81nsh5ambc53cl1c0pmli59lcfzdww3z-daemon-0.0.1). Disk stayed ~19-24G free through the iroh builds; no ENOSPC.

AC results: #1 two REAL in-process iroh endpoints, A fetches B's seeded NAR over loopback QUIC (relay DISABLED, presets::Minimal no discovery) - passes gate1 (BLAKE3/bao) AND gate2 (sha256==NarHash), byte-identical. #2 corruption bite SPLIT: (a) wrong_content_id_fails_closed_over_real_iroh; (b) a_different_valid_nar_passes_gate1_but_fails_gate2. #3 daemon-only + independence green. #4 IROH_BLOBS_ALPN == iroh_blobs::ALPN asserted at COMPILE time (const _) AND in a test; /iroh-bytes/4 CONFIRMED equal; NodeId ed25519 curve-point validity enforced via iroh::PublicKey::from_bytes.

HONEST LIMITS: (1) stock iroh-blobs bao makes it IMPOSSIBLE for a provider to serve bytes that mismatch the requested hash, so the 'mutated bytes' half of the gate-1 bite manifests as a fetch ERROR (fail-closed), never a corrupt success - the direct tampered-bytes-rejected-by-recipe bite stays the FakeTransport unit test in transport_fetch.rs (verify_blake3 = single source of truth). (2) NodeId->addr is an in-memory address book (IrohTransport::add_peer); task-40 discovery must feed it. (3) no size bound wired: the Transport trait carries no expected_size and get_blob().bytes() buffers the whole blob - forward-carried to task-25 (streaming NarSize abort) and task-51 (safety envelope); a coarse 20s FETCH_TIMEOUT guards only against an infinite hang. (4) nix build .#daemon (the required gate) verified; nix flake check (which would RUN the iroh loopback test inside the build sandbox) NOT verified - loopback-TCP integration tests already run under the sandbox so QUIC-on-loopback likely works, but iroh netmon behaviour under the sandbox is unconfirmed.

codex cadence review GO: genuine p2p (real iroh QUIC, no memory shortcut), both gates real+independent, ALPN==iroh_blobs::ALPN correct for 0.103.0. Non-blocking findings carried: #3 binding/addressing (loopback direct-addr won't work cross-container - S6/task-41 must fix), #4 NodeId validation is ZIP-215 (rejects non-decompressable, ACCEPTS some reduced encodings - NOT strict-canonical; doc precision), #5 no byte limit -> memory exhaustion (task-25/51).
<!-- SECTION:NOTES:END -->
