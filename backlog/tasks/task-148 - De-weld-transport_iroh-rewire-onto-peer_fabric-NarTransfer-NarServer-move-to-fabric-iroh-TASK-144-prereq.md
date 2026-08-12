---
id: TASK-148
title: >-
  De-weld transport_iroh: rewire onto peer_fabric NarTransfer/NarServer + move
  to fabric-iroh (TASK-144 prereq)
status: Done
assignee:
  - mped
created_date: '2026-08-12 04:16'
updated_date: '2026-08-12 23:37'
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
- [x] #1 IrohTransport implements peer_fabric::NarTransfer (tag + fetch(content, offer, envelope) -> gate-1-verified bytes); the daemon-side Transport trait dependency is removed or bridged behind the seam
- [x] #2 IrohProvider serve path implements peer_fabric::NarServer returning a ServeHandle whose Drop aborts the listener/serve task (no leaked serve task); proven by a teardown test
- [x] #3 transport_iroh moved into fabric-iroh with NO edge back to daemon serving core (claim/transport_fetch/source/discovery/supply_catalog either moved below the seam or the needed pieces are peer-fabric types)
- [x] #4 IROH_BLOBS_ALPN lives in fabric-iroh; the iroh_blobs::ALPN equality assertion moves with it
- [ ] #5 just build/lint/test/e2e green incl s6-p2p (daemon still substitutes + serves P2P)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Prior increments landed the SEAM (TASK-148 inc1 NarTransfer native; TASK-150 NarServer+ServeHandle teardown+CatalogProbe). REMAINING: AC#4 ALPN move + AC#3 physical move. INC-A (AC#4): add iroh-blobs dep to fabric-iroh; move IROH_BLOBS_ALPN const + iroh_blobs::ALPN compile-time assertion into fabric-iroh; daemon transport.rs re-exports it. INC-B (AC#3): move transport_iroh.rs into fabric-iroh; SEVER daemon Transport bridge (impl Transport for IrohTransport + transfer_error_to_transport_error + claim::KnownTransport) by RELOCATING it into the daemon (daemon owns the Transport trait so it can impl it for fabric_iroh::IrohTransport - orphan rule OK); rewire crate::content_id::Blake3Digest->peer_fabric, crate::iroh_*->crate::iroh_* (already in fabric-iroh), doc-only crate::discovery ref->plain text; daemon lib.rs re-exports via fabric_iroh::transport_iroh. Full LIGHT gate per increment; commit each green. If INC-B balloons, keep INC-A committed + file follow-up. s6-p2p is the pending regression guard (orchestrator gates e2e).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
REFRAMED 2026-08-12 (libp2p-primary): iroh is now the OPTIONAL transport, not the default. This de-weld work stays valid - it makes iroh a clean swappable NarTransfer/NarServer behind the seam - but it is SECONDARY. Primary is fabric-libp2p (TASK-103 kad discovery + TASK-151 libp2p transport). The transport tournament compares this iroh transport vs the libp2p transport under one libp2p-kad discovery.

MOVE + ALPN LANDED (commit f4c00a7) - AC#3 + AC#4 (the seam re-impl AC#1/#2 landed earlier: TASK-148 inc1 NarTransfer-native 9c0472d; TASK-150 NarServer + real ServeHandle teardown + CatalogProbe c39b200/d7fade2).
WHAT MOVED: transport_iroh.rs daemon/src -> fabric-iroh/src (git rename, history preserved). IROH_BLOBS_ALPN + its compile-time '== iroh_blobs::ALPN' assertion moved from daemon/src/transport.rs into fabric-iroh (added iroh-blobs 0.103 + bao-tree 0.16 + async-trait to fabric-iroh Cargo.toml - all already in the daemon locked closure, so NO new lock source; check-lock-sources green). daemon transport.rs now re-exports IROH_BLOBS_ALPN; daemon lib.rs re-exports the module via 'pub use fabric_iroh::{...,transport_iroh}' so every crate::transport_iroh::/daemon::Foo path is unchanged.
DEPS SEVERED: the moved module names ONLY seam types. crate::content_id::Blake3Digest -> peer_fabric::Blake3Digest; crate::transport::NodeId -> peer_fabric::NodeId; the doc-only crate::discovery link + broken intra-doc Transport/TransportError links reworded to seam equivalents (TransferError) or plain text. The ONLY genuine daemon coupling was the daemon Transport-trait bridge (crate::transport_fetch::{Transport,TransportError} + crate::claim::KnownTransport).
BRIDGE RELOCATED (not deleted): AC#1 says 'removed OR bridged'. The bridge moved UP into the daemon (daemon/src/transport_iroh_bridge.rs). GOTCHA/why it works: the daemon owns the Transport trait, so 'impl Transport for fabric_iroh::IrohTransport' is orphan-rule-legal from the daemon. The bridge cannot call the private fetch_inner across the crate boundary, so it delegates to the PUBLIC native NarTransfer::fetch, disambiguated by UFCS (both traits have a 'fetch'/'tag' on the same type). It needs the transport's configured envelope as a seam type -> new pub IrohTransport::seam_envelope() accessor (the envelope field is private). KnownTransport::to_offer is pub(crate) and reachable since the bridge is in-daemon.
STILL COUPLED (by design, not a defect): the daemon fetch path still drives its OWN transport_fetch::{Transport,TransportRegistry,TransportNarSource}; the relocated bridge is what keeps it functionally identical. Fully retiring the bridge = daemon fetch path onto a PeerFabric IrohNarSource (as source_libp2p.rs already does for libp2p) = TASK-144, which this now UNBLOCKS (all iroh transfer/serve/ALPN is below the seam in fabric-iroh).
CITATION REPOINTS (would have broken the build/gates otherwise): include_str! in daemon/tests/{doc_citations,no_enumeration,iroh_runtime.rs x2} -> ../../fabric-iroh/src/transport_iroh.rs; finalize_iroh_node_lookup.py provenance manifest entry; profile_p2p.py prose. doc_citations still scans the moved file's comments + supplies its fn/const defs to the resolver via the repointed path.
GATE (LIGHT tier): cargo build --workspace ok; just lint ok (clippy -D warnings x2, fmt, ruff, check-independence [daemon->fabric-iroh only, no daemon<->testproxy, HTTP denylist green], check-source-guard, check-lock-sources); cargo test --workspace ok - 54 suites, 0 failed (fabric-iroh lib 92, iroh_runtime 37, iroh_serve_teardown 2, iroh_transport 7, serve_budget_and_supply 16, no_enumeration 10, store_residency oracle/retainall/rss 1/1/1, doc_citations green). NO frozen surface touched (RawNarV1/claim WIRE/ContentKey/ProviderRecord codec untouched - only Rust trait boundaries rewired). AC#5 e2e incl s6-p2p is the PENDING orchestrator-gated regression guard (NOT run here per contract; it is the behavioral proof the daemon still substitutes + serves P2P through the relocated bridge).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
TASK-148 COMPLETE. The iroh-blobs NAR transfer/serve is fully below the peer_fabric seam and physically in fabric-iroh. AC#1 IrohTransport IS peer_fabric::NarTransfer (native; the daemon Transport-trait bridge is RELOCATED into the daemon at transport_iroh_bridge.rs, delegating to NarTransfer::fetch). AC#2 IrohProvider IS peer_fabric::NarServer with a real ServeHandle whose Drop tears the serve driver down (TASK-150). AC#3 transport_iroh.rs MOVED daemon/src -> fabric-iroh/src with NO edge back to the daemon serving core (claim/transport_fetch/source/discovery/supply_catalog all severed - the last via TASK-150's CatalogProbe seam; it now names only peer_fabric types). AC#4 IROH_BLOBS_ALPN + its compile-time iroh_blobs::ALPN assertion live in fabric-iroh; daemon re-exports it. Commits: 9c0472d (inc1 NarTransfer), c39b200/d7fade2 (TASK-150 NarServer/teardown/CatalogProbe), f4c00a7 (this: move + ALPN + bridge relocation). GATE: build/lint/test green (54 suites, 0 failed); no frozen surface touched; daemon->fabric-iroh edge only. AC#5: build/lint/test green; the e2e s6-p2p regression guard is orchestrator-gated (not run here per contract). Unblocks TASK-144 (IrohFabric can now wire NarTransfer/NarServer/NodeLocator + ALPN entirely from fabric-iroh).
<!-- SECTION:FINAL_SUMMARY:END -->
