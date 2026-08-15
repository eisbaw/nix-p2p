---
id: TASK-151
title: >-
  fabric-libp2p: libp2p NAR transfer + node discovery (the PRIMARY transport
  stack)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 07:22'
updated_date: '2026-08-15 00:20'
labels:
  - libp2p
  - fabric
  - transport
  - discovery
  - primary
  - wave-2c
dependencies:
  - TASK-103
  - TASK-140
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
libp2p-primary direction (owner 2026-08-12): fabric-libp2p is the PRIMARY backend. Beyond the libp2p-kad ProviderDirectory (TASK-103), a pure-libp2p daemon needs a libp2p NarTransfer + NarServer (request-response or stream protocol, BLAKE3-verified exactly like iroh-blobs, with the same task-72 serve-budget/admission) and libp2p node discovery + NAT traversal (Identify + AutoNAT/DCUtR/relay, and kad peer-routing for addresses). This completes Libp2pFabric: PeerFabric so daemon-libp2p is a full single-stack product needing no iroh. iroh-blobs transfer (fabric-iroh) is the OPTIONAL alternative measured against this in the transport tournament (same libp2p-kad discovery, different transport). Watch the rust-libp2p dependency weight and the public-DHT good-citizen duties (bootstrap, provider republish cadence; announce-on-demand bounds the republish load).
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
FORWARD-CARRY from TASK-103 (cornerstone landed): the libp2p transport SHARES fabric-libp2p's Swarm. Reuse crate::swarm (Behaviour = kad + identify; extend with a request-response protocol for NarTransfer/NarServer over the SAME worker/SwarmHandle - add Command variants + Pending arms, do not spin a second swarm). The request-response feature is already enabled in Cargo.toml. Node identity is the ed25519 record-signing key (keys::keypair_from_seed), so a self-serve Iroh/libp2p offer's node == provider holds. NodeLocator comes from Identify + kad peer-routing (add_address is already fed from identify::Event::Received). Libp2pFabric currently returns None for transfer/server/locator/hold/local - fill those in here.

CORE LANDED + REVIEWED (commits f9c10ae code, e8796d5 review-fixes, c33307b tracker/follow-ups). The libp2p NAR TRANSFER + SERVE now run over the SAME swarm as kad+identify (no second swarm).

WHAT LANDED:
- swarm.rs: Behaviour extended with a request-response protocol /nix-p2p/<scope>/nar/1 (NarCodec). New FetchNar/InstallServe/UninstallServe commands, an nar_pending map + a serve slot on the worker; inbound requests routed through the installed ServeGate.
- nar.rs: the wire codec (response length-capped at MAX_NAR_RESPONSE_BYTES=256 MiB so a lying length never allocates unbounded), the substrate-internal supply seam (Libp2pNarSupplier + MemoryNarSupplier, BELOW the peer_fabric seam mirroring TASK-150's sealed-supplier decision), and the task-72 admission ServeGate (declared-size-before-produce OOM defense).
- transport.rs: Libp2pTransport: peer_fabric::NarTransfer. Derives provider PeerId from the NodeId-locator offer, dials over the swarm, size-aborts vs the signed NarSize, gate-1 BLAKE3-verifies (SSOT Blake3Digest::from_raw_nar) before returning.
- server.rs: Libp2pServer: peer_fabric::NarServer. serve(budget) installs a ServeGate; ServeHandle Drop flips the gate active flag (SYNCHRONOUS stop-admitting) + generation-tagged best-effort uninstall.
- fabric.rs: Libp2pFabric exposes transfer (always) and server (via start_with_supplier); node-locator/hold/LAN stay None.

MULTI-NODE TEST (the pass bar, tests/nar_transport.rs, 6 tests): two REAL libp2p swarms over loopback TCP. Proves (1) byte-identical + BLAKE3-verified fetch A->B; (2) corrupt provider trips gate-1 IntegrityMismatch; (3) signed-bound-smaller-than-served trips TooLarge size-abort; (4) over-per-NAR serve budget is DECLINED (task-72); (5) dropping ServeHandle stops admission; (6) a stale teardown does NOT clobber a live successor session (regression for the re-serve race). Plus nar::tests 5 ServeGate admission unit tests incl the MAX-cap SSOT tripwire.

KEY DECISION (frozen seam UNTOUCHED): the transport services TransportTag::Iroh and consumes TransportOffer::Iroh{node} as a NodeId-locator - because dispatch is OFFER-DRIVEN and the frozen record only carries the Iroh offer, so a libp2p daemon MUST consume it to fetch existing records. Honest ADR in transport.rs. A distinct TransportTag::Libp2p + additive OFFER_LIBP2P frozen-codec tag (needed for the DUAL-STACK transport tournament; a bare new tag would never be selected) is TASK-156.

mped-architect (Mark-emulator) REVIEW ROUND fixes (in e8796d5): #4(silent-failure BUG) re-serve clobber race - UninstallServe now carries the gate Arc, worker clears only if Arc::ptr_eq (regression-tested). #1 ADR rewritten to the honest offer-driven-dispatch reason (dropped the 'locator shape' fiction); noted TransferRegistry::register silent-overwrite risk -> TASK-156. #2 in-flight ceiling documented as vestigial under inline serialized production + TASK-157 TOCTOU comment at the reserve site; ServeBudget destructured EXHAUSTIVELY in ServeGate::new (drift tripwire); max_serve_duration documented unenforced. #3 'never buffer a huge lying blob' overclaim corrected - bounded at the 256 MiB cap NOT the per-call signed size; MAX_NAR_RESPONSE_BYTES SSOT-asserted against ServeBudget::default; hard-ceiling asymmetry documented. #5/#6 gate-1 + error mapping confirmed fail-closed (server-side Decline->Unavailable, signed-size->TooLarge kept distinct - the NarSize-vs-budget unit trap).

GATE (all inside nix develop, ACTUAL): just build green; just lint green (clippy -D + independence + source/lock guards); just test green incl fabric-libp2p unittests 11, decentralized_discovery 1, nar_transport 6; just e2e 5/5 scenarios (s6-p2p 11/11, 76.0s total) - UNAFFECTED (not wired into any daemon yet). No Cargo.toml/lock churn (request-response feature was pre-enabled). No background jobs left.

HONEST LIMITS (filed, not faked): NAT traversal / NodeLocator = TASK-159; true mid-stream per-call size-abort + real body-idle bound + OFF-worker streamed production (inline production blocks the poll loop up to the per-NAR budget; in-flight ceiling vestigial until then) = TASK-157; real store-dump/regular-file cancellation-safe supplier = TASK-158; distinct Libp2p tag + frozen-codec OFFER_LIBP2P for the dual-stack tournament = TASK-156. NOT wired into a daemon (daemon-libp2p = TASK-146).

FORWARD-CARRY: TASK-146 (daemon-libp2p wiring): build Libp2pFabric via start_with_supplier with the daemon's catalog-backed Libp2pNarSupplier (needs TASK-158's real supplier) and register the transport in the fetch path; the transport already consumes the existing Iroh NodeId-locator offer. TASK-132 (cold journey) + TASK-145 (daemon-libp2p binary): depend on TASK-146. Transport tournament (libp2p vs iroh transfer under one kad discovery): BLOCKED on TASK-156 (distinct offer/tag) since a single-process dual-stack currently collides on the Iroh tag.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
RECONCILED + CLOSED (2026-08-15, orchestrator + COMPASS 'reconcile & close'). The PRIMARY libp2p transport stack is delivered and reviewed: the libp2p NAR transfer + serve run over the SAME swarm as kad+identify (request-response /nix-p2p/<scope>/nar/1, BLAKE3-verified, task-72 admission ServeGate, 256 MiB response cap); core landed in f9c10ae, mped-architect review-fixes in e8796d5 (incl. the re-serve clobber race fix), tracker/follow-ups in c33307b. The 6-test multi-node suite (tests/nar_transport.rs) proves byte-identical BLAKE3-verified fetch, corrupt-provider gate-1 trip, signed-size abort, serve-budget decline, drop-stops-admission, and the stale-teardown-doesn't-clobber-successor regression. Every honest-limit this task filed is now DONE: true streamed mid-stream size-abort + off-worker production (TASK-157), real store-dump/regular-file cancellation-safe supplier (TASK-158), NAT traversal + NodeLocator (TASK-159), daemon wiring (TASK-160), container e2e store-serve (TASK-194). The ONLY remaining forward-carry is the additive distinct TransportTag::Libp2p + frozen-codec OFFER_LIBP2P for the dual-stack tournament, which is its own task TASK-156 (this task deliberately kept the frozen seam untouched, consuming the existing Iroh NodeId-locator offer via offer-driven dispatch — honest ADR in transport.rs). Closing here unblocks TASK-156 (its dependency) and thereby the 183/156 coherence prune.
<!-- SECTION:FINAL_SUMMARY:END -->
