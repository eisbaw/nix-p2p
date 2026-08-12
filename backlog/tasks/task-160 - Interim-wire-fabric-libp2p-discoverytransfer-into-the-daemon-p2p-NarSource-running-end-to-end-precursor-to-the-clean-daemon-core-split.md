---
id: TASK-160
title: >-
  Interim: wire fabric-libp2p discovery+transfer into the daemon p2p NarSource
  (running end-to-end, precursor to the clean daemon-core split)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 09:30'
updated_date: '2026-08-12 10:28'
labels:
  - libp2p
  - daemon
  - integration
  - poc
  - wave-2c
dependencies:
  - TASK-103
  - TASK-151
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Functionality-first path to a RUNNING decentralized content path, ahead of the clean daemon-core/two-binary split (TASK-145/146). Wire fabric-libp2p into the EXISTING daemon crate: on a NAR miss the daemon derives ContentKey from the signed NarHash (frozen content.rs recipe), calls Libp2pFabric ProviderDirectory.find_providers, picks a ProviderRecord, fetches the raw NAR by its content Blake3Digest via NarTransfer, gate-1 BLAKE3-verifies, and serves it to Nix (which re-verifies sig+NarHash). NO injected provider - the answer comes from libp2p-kad. Pass bar: an in-process integration test through the daemon serving stack proving decentralized discover->fetch->serve over libp2p (a full podman multi-daemon e2e is a follow-up). The daemon temporarily links both fabric-iroh and fabric-libp2p; the clean per-binary packaging is TASK-145/146. Reuse the existing main.rs::setup_p2p_source plumbing.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add daemon->fabric-libp2p dep; commit manifest when it builds.
2. Add daemon::Libp2pNarSource (NarSource seam impl) driving PeerFabric provider_directory().find_providers(ContentKey) -> transfer(tag).fetch(content, offer); gate-1 BLAKE3 inside transfer; Miss/Unavailable -> Unreachable (FallbackNarSource -> upstream). Commit.
3. In-process integration test through the daemon serving stack (spawn_app + real libp2p network: bootstrap + serving provider + consumer). Provider discovered via kad NOT injected; byte-identical fetch; MISS/fallback arm. Commit.
4. File follow-ups: podman multi-daemon libp2p e2e; production main.rs libp2p config wiring; forward-carry to 132/145/146/159.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LANDED (code commits, separate from Cargo.lock/tracker):
- 2b075c6 daemon: link fabric-libp2p (dep edge, manifest+lock).
- 311a8e3 daemon: Libp2pNarSource behind the frozen NarSource seam.
- e8b9f47 daemon: dev-deps (fabric-libp2p, ed25519-dalek) for the integration test.
- c91a747 daemon: in-process integration test through the real App serving stack.

DESIGN: option (b). Libp2pNarSource drives the peer-fabric seam types END TO END behind the one NarSource::resolve method, holding Arc<dyn PeerFabric> (backend-swappable, not welded to libp2p). Option (a) was rejected: the daemon's Discovery/TransportRegistry speak daemon-local Claim/KnownTransport and Libp2pTransport implements peer_fabric::NarTransfer (not daemon::Transport), so (a) needs a bridge for every value crossing the seam. Flow: NarHashKey::as_bytes() (32 raw sha256) -> ContentKey::derive_from_signed_nar_hash (FROZEN content.rs recipe) -> provider_directory().find_providers -> pick ProviderRecord (content Blake3Digest + offers) -> transfer(offer.tag()).fetch (gate-1 BLAKE3 inside) -> serve; Miss/Unavailable/exhausted -> Unreachable (FallbackNarSource -> upstream, S2); TooLarge propagates.

PROVEN (integration test, gate-verified GATE_EXIT=0): 3 in-process libp2p nodes (bootstrap + serving provider + consumer). Consumer knows ONLY the bootstrap; it DISCOVERS the provider via libp2p-kad (test asserts the discovered record == the provider's exact signed record - kad-produced, NOT injected), fetches the raw NAR over libp2p request-response, gate-1 BLAKE3-verifies, and the daemon serves BYTE-IDENTICAL bytes through spawn_app with the HTTP upstream never consulted (0 fallbacks). MISS arm: an un-announced NarHash is a healthy kad miss -> clean upstream fallback (exactly 1 fallback).

GOTCHAS / HONEST LIMITS:
- The byte-transfer DIAL address of the provider is injected out-of-band into the consumer swarm (TASK-159 basic-dial shim; Libp2pFabric::node_locator() is None). The DISCOVERY is the decentralized part; the dial mirrors fabric-libp2p's own nar_transport.rs. Real-network NAT/NodeLocator is TASK-159.
- Libp2pTransport registers under TransportTag::Iroh (offer-driven dispatch; the only reachability offer is self-serve TransportOffer::Iroh{NodeId}). A dual-stack transport tournament needs a distinct Libp2p offer on the frozen wire (TASK-156).
- Production main.rs setup_p2p_source still builds ONLY the iroh source; the libp2p production config wiring (CLI bootstrap/listen/scope) is TASK-162, and the podman multi-daemon libp2p e2e is TASK-161. This cycle's bar is the in-process integration test (met).

ENV: a concurrent Claude process in this project saturated the shared command-output-capture tmpfs (ENOSPC), so gate/commit output was routed to target/*.log and read from disk. Full gate (build/independence/clippy/fmt/test incl. the new test + real-nix rewrite check) went green: GATE_EXIT=0.

FLAKE (not a regression): fabric-iroh iroh_node_lookup::synchronous_replay_validation_cannot_return_success_after_absolute_deadline failed once under full-parallel just test, then passed in isolation and on the gate rerun. Timing oracle, same family as TASK-84 / TASK-108.

FORWARD-CARRY: TASK-132 (cold-journey exposure of the kad path), TASK-145/146 (clean daemon-core/two-binary split - this interim both-backends link is deleted there), TASK-159 (real-network NAT for the dial). Follow-ups filed: TASK-161, TASK-162.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Interim daemon libp2p wiring DONE (in-process bar met). daemon links fabric-libp2p; Libp2pNarSource (daemon/src/source_libp2p.rs) implements the NarSource seam: NarHash->ContentKey (frozen recipe)->libp2p-kad find_providers->fetch raw NAR by content Blake3Digest->gate-1 BLAKE3 verify. Integration test (daemon/tests/libp2p_nar_source.rs): 3 in-process libp2p nodes, consumer knows only bootstrap, discovers provider via kad (NOT injected; asserts discovered==provider signed record), serves byte-identical via the real App stack (0 upstream fallbacks), MISS arm clean upstream fallback. Commits 2b075c6/311a8e3/e8b9f47/c91a747. Gate: workspace tests green (daemon lib 126, main 19); iroh e2e 5/5 STILL PASSES (no regression). MILESTONE: the daemon does decentralized content discovery+fetch+serve end-to-end (in-process). Follow-ups: TASK-161 podman multi-daemon libp2p e2e, TASK-162 production setup_p2p_source config, TASK-159 NodeLocator/NAT (byte-dial injected out-of-band today; discovery is the decentralized part).
<!-- SECTION:FINAL_SUMMARY:END -->
