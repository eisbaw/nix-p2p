---
id: TASK-38
title: 'Transport trait: abstract p2p fetch/serve behind NarSource'
status: Done
assignee: []
created_date: '2026-08-08 20:12'
updated_date: '2026-08-08 23:10'
labels: []
dependencies:
  - TASK-37
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A Transport interface so iroh is one impl and BitTorrent a future one, sitting under the frozen NarKey::SignedNarHash NarSource seam. resolve(NarHash) via a transport = fetch the addressed-unit (raw-NAR BLAKE3) and verify. The claim transport tag selects the impl. Keeps the p2p layer swappable per PRD wave-2 scope.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Trait defined; a fake in-memory transport satisfies NarSource and passes the NarHash gate in a unit test (URL-less, keyed on NarHash)
- [x] #2 The claim transport tag maps to a transport impl; an unknown tag is skipped, not a crash
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
DONE (LIGHT gate green; own verification run). Delivered daemon/src/transport_fetch.rs + lib.rs re-exports. Commit 0d9d6e7.

Shape:
- Transport trait (object-safe): async fetch(&Blake3Digest, &KnownTransport) -> Result<Vec<u8>, TransportError>. Iroh-agnostic; task-39 plugs the real iroh backend under the SAME trait+registry.
- TransportRegistry (tag -> Box<dyn Transport>) + fetch_via_offers(): offer tag selects impl; NO backend for a tag -> skipped; failed fetch -> recorded, try next; all-exhausted -> FetchError::Exhausted (fail closed).
- FakeTransport: in-memory, URL-less, keyed ONLY on Blake3Digest (ignores the NodeId locator). seed()=content-addressed put; seed_corrupt()=lying holder.
- TransportNarSource: wave-2 NarSource skeleton; resolve(SignedNarHash) via transports; rejects UpstreamPath (no URL). In-memory claim map = task-40 discovery stand-in.

Two gates (distinct): gate1 transport-integrity BLAKE3 (verify_blake3, single source of truth, owned here, fail-fast) vs gate2 trust sha256==NarHash (Nix S1, downstream - daemon is outside the TCB). Shaped so task-39's corruption bite splits them.

Bites (proven by mutation, not by reading):
- AC#1: fake_transport_satisfies_narsource_and_passes_both_gates + a_corrupt_holder_is_rejected_by_the_integrity_gate. Mutation: strip verify_blake3 -> corrupt-holder test FAILS.
- AC#2: an_unimplemented_transport_offer_is_skipped_not_a_crash (bittorrent-only -> Exhausted; [bittorrent,iroh] -> iroh serves). Mutation: panic on unknown tag -> test FAILS.

Honest limits / gotchas:
- The sha256 trust gate is NOT recomputed in-daemon (no sha2 dep; Nix owns S1). The two-gates test asserts byte-identity of the resolved NAR to the addressed unit (what makes Nix's gate pass) + re-checks gate1 explicitly. Deliberate: re-implementing sha256 in the daemon would be a gate the product never runs. If a reviewer wants an in-test sha256, add sha2 as a daemon-only dev-dep (independence denylist is HTTP-only, so safe) - but it churns Cargo.lock+flake vendor hash, avoided for a LIGHT task.
- expected_size (NarSize/risk-6 abort) is accepted but NOT enforced: must be enforced DURING streaming inside the transport (task-25), not post-hoc here, or a lying holder streams a huge blob before a late check. Forward-carried.
- 'Unknown transport tag' at THIS layer = a KNOWN wire variant with no backend (bittorrent). Genuinely-unknown wire tags are already dropped by the claim decoder before reaching here.
- TransportNarSource.announce()/lookup keys on the canonical NarHashKey string; assumes correlated hashes are canonical (true for real narinfo values). Loose seam NarHash strings that are non-canonical won't match - task-40/49 supply canonical keys.
- The driver TRUSTS the Transport contract for gate1 (does not re-hash after fetch), preserving the future streaming/bounded-download property; a buggy transport that skips the gate is caught only by Nix's sha256 (acceptable per TCB reasoning).
<!-- SECTION:NOTES:END -->
