---
id: TASK-144
title: >-
  fabric-iroh crate + daemon-core split + IrohFabric: PeerFabric (TASK-141 inc
  2)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-11 23:57'
updated_date: '2026-08-12 04:17'
labels:
  - iroh
  - seam
  - adapter
  - de-welding
  - wave-2c
dependencies:
  - TASK-141
  - TASK-148
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Increment 2 of the TASK-141 de-welding, split out from TASK-141 (inc 1 landed: value types de-duplicated behind the seam, commit d01fb42). Extract a daemon-core (frontend: serving core, policy, orchestration; peer-fabric only, NO iroh) and a fabric-iroh crate (the welded iroh modules: iroh_runtime, iroh_node_lookup, iroh_publication*, pinned_http, iroh_relay, transport_iroh, iroh_node_record). Implement IrohFabric as a concrete struct with Option<Arc<dyn Capability>> fields per docs/peer-fabric-seam.md. Wire NodeLocator onto TASK-138's pkarr NodeId->address lookup, NarTransfer/NarServer onto iroh-blobs on the shared TASK-115 endpoint (reuse the existing tag-keyed TransportRegistry). Add the composition-root required-axis assertion (fail fast if a selected profile's required axis is None) and the real ServeHandle teardown (attach the listener/task-abort to peer_fabric::ServeHandle's opaque teardown guard so drop == teardown). Move IROH_BLOBS_ALPN from daemon/src/transport.rs into fabric-iroh (it is iroh-specific; left in transport.rs by inc 1 on purpose). A guard/test asserts the serving core + App hold no concrete iroh types outside the fabric module.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 daemon-core crate holds no concrete iroh type and depends on peer-fabric only (build/guard proves it)
- [ ] #2 fabric-iroh crate contains the welded iroh modules and implements IrohFabric: PeerFabric (concrete struct, Option<Arc<dyn>> capability fields)
- [ ] #3 NodeLocator wraps TASK-138 pkarr lookup; NarTransfer/NarServer wrap iroh-blobs on the TASK-115 endpoint; the tag-keyed TransportRegistry is reused unchanged
- [ ] #4 composition root asserts the selected profile's REQUIRED axes are Some and fails fast otherwise (Unsupported-ZST-dilemma resolution)
- [ ] #5 ServeHandle owns the real listener/task-abort so drop == teardown (no leaked serve task)
- [ ] #6 guard/test asserts the serving core and App hold no concrete iroh types outside the fabric module; just e2e s6-p2p still passes with the daemon driving IrohFabric through PeerFabric
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Cross-ref map done. The weld is bidirectional+deep: serving-core (server->iroh_runtime, availability->process_group) and transport_iroh->serving-core (claim/transport_fetch/source/discovery). SAFE increments:
INC1 (this pass): extract the NODE-DISCOVERY/RUNTIME/PUBLICATION cluster into new crate fabric-iroh (deps: peer-fabric+iroh+iroh-dns+simple-dns+rustix+tokio+n0-future+serde+serde_json+blake3+url). Move iroh_runtime, iroh_node_lookup, iroh_node_record, iroh_publication, iroh_publication_authority(+_tests), iroh_relay, pinned_http, process_group. transport_iroh STAYS in daemon (welded to serving core; de-weld = INC2). Only real edit: 'use crate::transport::NodeId' -> 'use peer_fabric::NodeId'. daemon re-exports via 'pub use fabric_iroh::{modules}' so every crate::iroh_*/process_group/pinned_http path + existing type re-exports still resolve. FULL gate incl e2e s6-p2p, commit.
INC2 (if budget): implement IrohFabric: PeerFabric; rewire transport_iroh onto peer_fabric NarTransfer/NarServer + move it to fabric-iroh; NodeLocator on pkarr; composition-root required-axis assert; real ServeHandle teardown; move IROH_BLOBS_ALPN. Large rewrite - likely follow-up.
INC3: split daemon-core frontend crate - likely follow-up.
Honest partial + filed follow-ups = success per contract.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
INC 1 LANDED (commit 2394bee) - fabric-iroh crate created; the iroh node-discovery/runtime/publication cluster + process_group MOVED out of the daemon behind the peer-fabric seam. FULL GATE GREEN: just build; just lint (clippy -D warnings + independence: fabric-iroh is daemon-side, no testproxy edge + source guards); just test (525 tests, 0 failed); just e2e 5/5 incl s6-p2p 11/11 (daemon still substitutes + serves P2P).

Moved to fabric-iroh/src/: iroh_runtime, iroh_node_lookup, iroh_node_record, iroh_publication, iroh_publication_authority(+_tests), iroh_relay, pinned_http, process_group. Only code edit to moved files: crate::transport::NodeId -> peer_fabric::NodeId. daemon re-exports via 'pub use fabric_iroh::{modules}' so all crate::iroh_*/process_group/pinned_http paths + flat daemon::Foo type re-exports + evidence bins + integration tests are untouched. Promoted 4 iroh_runtime + 8 process_group pub(crate) items to pub (all signatures reference std/iroh:: types -> no private_interfaces cascade); these revert to pub(crate) once transport_iroh+availability move.

Also repointed: daemon/tests/iroh_runtime.rs include_str! guard -> ../../fabric-iroh/src/iroh_runtime.rs; finalize_iroh_node_lookup.py + finalize_iroh_relay_capability.py provenance manifests -> fabric-iroh/src/ (read from git at real finalization; self-tests use synthetic git data so they passed either way, but stale paths would FileNotFoundError on real TASK-138/142 evidence regen).

WHY NOT MORE THIS PASS: transport_iroh (the iroh-blobs transfer/serve, 111KB) is bidirectionally welded to the serving core (it depends on claim/transport_fetch/source/discovery/supply_catalog, which depend on source/discovery). Moving it is a genuine rewrite onto peer_fabric::{NarTransfer,NarServer} -> filed as TASK-148 (now a dep of this task). Without transport_iroh below the seam, IrohFabric cannot wire its transfer/server axes (AC#3), so a partial IrohFabric would be speculative unused scaffolding (only NodeLocator wireable, since iroh_node_lookup IS now in fabric-iroh). Deliberately NOT added.

PER-AC STATUS (all still open - inc1 is groundwork):
#1 daemon-core crate: NOT DONE (frontend still one 'daemon' crate; TASK-145).
#2 IrohFabric: PeerFabric: NOT DONE (blocked on TASK-148 for transfer/server axes).
#3 NodeLocator/NarTransfer/NarServer wiring: NOT DONE (NodeLocator now WIREABLE - iroh_node_lookup is in fabric-iroh; transfer/server blocked on TASK-148).
#4 composition-root required-axis assert: NOT DONE (needs the composition root = daemon-core, TASK-145).
#5 ServeHandle real teardown: NOT DONE (TASK-148).
#6 guard test + s6-p2p: s6-p2p GREEN; guard-that-core-holds-no-iroh not added (core still holds transport_iroh).

FORWARD-CARRY: (a) process_group is generic, not iroh - it rides in fabric-iroh only to keep the cut acyclic (iroh_runtime needs it AND daemon availability needs it); move to a shared util or daemon-core when the frontend splits (TASK-145). (b) daemon/tests/iroh_runtime.rs cites fabric-iroh source by RELATIVE path (../../fabric-iroh/src/...) - fragile cross-crate citation; consider moving the endpoint-construction guard into fabric-iroh's own tests. (c) provenance manifests in the finalize_*.py could also bind fabric-iroh/Cargo.toml+lib.rs (added deps materially define the capability) - only existing .rs paths were repointed to avoid the exact-match self-test fixtures.
<!-- SECTION:NOTES:END -->
