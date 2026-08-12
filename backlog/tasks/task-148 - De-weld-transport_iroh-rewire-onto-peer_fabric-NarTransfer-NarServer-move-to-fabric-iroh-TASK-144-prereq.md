---
id: TASK-148
title: >-
  De-weld transport_iroh: rewire onto peer_fabric NarTransfer/NarServer + move
  to fabric-iroh (TASK-144 prereq)
status: To Do
assignee: []
created_date: '2026-08-12 04:16'
updated_date: '2026-08-12 06:55'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies: []
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
transport_iroh (the iroh-blobs NAR transfer + provider serve, ~111KB) is the last iroh module still in the daemon after TASK-144 inc 1, because it is welded to the serving core: it depends on daemon claim (KnownTransport/offers), transport_fetch (Transport trait/TransportError/NarSource/TransportRegistry), source, discovery, supply_catalog. To move it into fabric-iroh WITHOUT dragging the serving core along, its IrohTransport must implement peer_fabric::NarTransfer (not daemon::Transport) and its IrohProvider/serve path must implement peer_fabric::NarServer with a real ServeHandle whose drop == teardown (listener/task-abort owned by the peer_fabric::ServeHandle opaque guard). Also move IROH_BLOBS_ALPN from daemon/src/transport.rs into fabric-iroh (iroh-specific; left in transport.rs by TASK-141 inc 1 on purpose). This unblocks TASK-144 IrohFabric transfer/server axes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 IrohTransport implements peer_fabric::NarTransfer (tag + fetch(content, offer, envelope) -> gate-1-verified bytes); the daemon-side Transport trait dependency is removed or bridged behind the seam
- [ ] #2 IrohProvider serve path implements peer_fabric::NarServer returning a ServeHandle whose Drop aborts the listener/serve task (no leaked serve task); proven by a teardown test
- [ ] #3 transport_iroh moved into fabric-iroh with NO edge back to daemon serving core (claim/transport_fetch/source/discovery/supply_catalog either moved below the seam or the needed pieces are peer-fabric types)
- [ ] #4 IROH_BLOBS_ALPN lives in fabric-iroh; the iroh_blobs::ALPN equality assertion moves with it
- [ ] #5 just build/lint/test/e2e green incl s6-p2p (daemon still substitutes + serves P2P)
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
INCREMENT 1 LANDED (commit 9c0472d) - TRANSFER axis de-welded onto peer_fabric::NarTransfer. FULL GATE GREEN: just build; just lint (clippy -D warnings + independence + source-guard); just test (41 test binaries, 0 failed; iroh_transport now 7, fabric_iroh 91, peer_fabric 68, serve_budget_and_supply 16); just e2e 5/5 incl s6-p2p 11/11 (daemon still substitutes + serves P2P - node A's production fetch now runs through the seam-native fetch_inner via the Transport bridge).

WHAT CHANGED: IrohTransport is now the NATIVE peer_fabric::NarTransfer impl. Its fetch core (new inherent fetch_inner) names ONLY seam types (TransportOffer, TransferError, SafetyEnvelope) - no daemon claim-wire KnownTransport, no serving-core Transport trait. dial_and_stream returns TransferError; gate 1 re-asserted locally via the frozen Blake3Digest::from_raw_nar. New KnownTransport::to_offer() (claim.rs) is the one wire->seam offer conversion. The daemon Transport impl is a thin BRIDGE delegating to fetch_inner (converts KnownTransport->TransportOffer, uses self.envelope, maps TransferError->TransportError which are variant-identical), so TransportRegistry/fetch_via_offers/TransportNarSource are unchanged. New behavioural test fetches a real two-endpoint blob THROUGH peer_fabric::NarTransfer and proves the signed-NarSize TooLarge abort on the seam path. peer-fabric added to daemon [dev-dependencies] so tests can name the seam (Cargo.lock unchanged).

PER-AC STATUS:
#1 IrohTransport: peer_fabric::NarTransfer + daemon Transport dep BRIDGED: DONE (AC#1 explicitly allows 'removed OR bridged'; the impl is native+non-vacuous, exercised by the new test AND the whole s6-p2p production fetch path).
#2 NarServer + real ServeHandle teardown: NOT DONE - BLOCKED, see TASK-150. Genuine seam gap: peer_fabric::NarSupplier::supply()->Option<Vec<u8>> is too weak to preserve the task-72 admission (declared-size BEFORE producing bytes) + the sealed plan-based supplier's cancellation-safety. Wrapping it would reintroduce the peer-triggerable-OOM GAP-1 - rejected as a workaround. Also needs a provider-lifecycle refactor (serving is baked into IrohNodeBuilder.spawn, not a standalone abortable serve()).
#3 move to fabric-iroh, no daemon edge: NOT DONE. Needs (a) retiring the Transport bridge = adopting NarTransfer+TransferRegistry across the daemon fetch path (touches transport_fetch.rs, main.rs::setup_p2p_source, ~6 test files) and (b) severing IndexNarSupplier->supply_catalog (test-only today) via a fabric-iroh catalog-probe trait, and (c) AC#2. Filed under TASK-150.
#4 IROH_BLOBS_ALPN in fabric-iroh: NOT DONE - DELIBERATELY deferred to bundle with AC#3. Moving it alone would add an iroh-blobs dep to fabric-iroh for a single constant; iroh-blobs belongs there only when transport_iroh actually moves (both need it together). Principled grouping, not budget.
#5 gates incl s6-p2p: GREEN for what landed (s6-p2p 11/11); the daemon serves P2P.

REJECTED APPROACH / GOTCHA: replacing the daemon Transport trait outright (not bridging) forces the whole daemon fetch path + ~6 test files onto NarTransfer in one step - high churn, high risk per increment, no safe green stopping point. The bridge (AC#1's 'or bridged') gives a green, verified, non-vacuous stopping point that makes the seam impl the PRODUCTION fetch core today.

ENVIRONMENT HAZARD (forward-carry to the loop): a concurrent sibling process cleaned the working tree (git checkout/stash of uncommitted changes) mid-run and wiped a full green increment once; redone and committed FAST. Commit each green increment immediately; do not leave work uncommitted across a long e2e.

SERVE AXIS UNBLOCKED by TASK-150 (commits 306bc3f AC#1, 4402a50 AC#3, c39b200 AC#2). AC#2 of THIS task (IrohProvider serve path implements peer_fabric::NarServer with a real ServeHandle whose Drop aborts the serve task, teardown-proven) is now DONE via IrohNodeBuilder::defer_serve() + IrohProvider::serve (daemon/tests/iroh_serve_teardown.rs). AC#3's sub-blocker 'sever IndexNarSupplier->supply_catalog' is DONE via the CatalogProbe trait (daemon SupplyCatalogHandle impls it; edge inverted to daemon->transport_iroh). REMAINING for 148: (a) retire the daemon Transport bridge = adopt peer_fabric::NarTransfer + TransferRegistry across the daemon fetch path (transport_fetch.rs, main.rs::setup_p2p_source, ~6 test files); (b) move IROH_BLOBS_ALPN + the iroh_blobs::ALPN assertion into fabric-iroh; (c) move transport_iroh.rs into fabric-iroh with no edge back to the daemon serving core. These are the AC#3/#4 'move' steps, not the seam design - the seam is now in place.
<!-- SECTION:NOTES:END -->
