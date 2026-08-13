---
id: TASK-144
title: >-
  fabric-iroh crate + daemon-core split + IrohFabric: PeerFabric (TASK-141 inc
  2)
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-11 23:57'
updated_date: '2026-08-13 00:16'
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
- [x] #2 fabric-iroh crate contains the welded iroh modules and implements IrohFabric: PeerFabric (concrete struct, Option<Arc<dyn>> capability fields)
- [x] #3 NodeLocator wraps TASK-138 pkarr lookup; NarTransfer/NarServer wrap iroh-blobs on the TASK-115 endpoint; the tag-keyed TransportRegistry is reused unchanged
- [x] #4 composition root asserts the selected profile's REQUIRED axes are Some and fails fast otherwise (Unsupported-ZST-dilemma resolution)
- [x] #5 ServeHandle owns the real listener/task-abort so drop == teardown (no leaked serve task)
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

TASK-148 inc 1 landed (commit 9c0472d): the iroh TRANSFER axis is de-welded - IrohTransport IS peer_fabric::NarTransfer (native), daemon Transport is a bridge over it. So IrohFabric can now wire its NarTransfer axis (register IrohTransport into peer_fabric::TransferRegistry). The SERVE axis (NarServer/ServeHandle) is still blocked - filed as TASK-150 (peer_fabric::NarSupplier too weak for the task-72 admission + cancellation-safety invariants; provider lifecycle baked into IrohNodeBuilder.spawn). transport_iroh has NOT moved yet (AC#3 of 148 open), so a full IrohFabric still cannot wire transfer/server from fabric-iroh; NodeLocator remains the only cleanly-wireable axis (iroh_node_lookup is already in fabric-iroh).

SERVE WIRING UNBLOCKED (TASK-150 c39b200): IrohProvider now impls peer_fabric::NarServer::serve(budget)->ServeHandle (abortable, teardown-proven). When IrohFabric wires the serve axis, build the provider node with IrohNodeBuilder::defer_serve() and expose IrohProvider as the fabric's Option<Arc<dyn NarServer>>; call serve(budget) to start and hold the ServeHandle for the fabric's lifetime (drop = teardown). Supply source is bound below the seam at construction (the sealed plan-based NarSupplier in the provider gate); NarServer::serve carries only the budget (peer_fabric seam ADR in capabilities.rs).

UNBLOCKED by TASK-148 (commit f4c00a7): the iroh transfer/serve axes AND the ALPN are now ALL below the peer_fabric seam in fabric-iroh. transport_iroh.rs physically MOVED daemon/src -> fabric-iroh/src (AC#3 of 148 done); IROH_BLOBS_ALPN + its iroh_blobs::ALPN assertion moved into fabric-iroh (AC#4 of 148 done). fabric-iroh now owns: fabric_iroh::transport_iroh::{IrohTransport (peer_fabric::NarTransfer), IrohProvider (peer_fabric::NarServer, real ServeHandle teardown), IROH_BLOBS_ALPN}. So TASK-144 AC#2/#3/#5 are now WIREABLE from fabric-iroh: IrohFabric can hold Option<Arc<dyn NarTransfer>> = Arc<IrohTransport> and Option<Arc<dyn NarServer>> = Arc<IrohProvider> (build the provider node with IrohNodeBuilder::defer_serve(), call serve(budget), hold the ServeHandle for the fabric lifetime = drop teardown), alongside the already-wireable NodeLocator (iroh_node_lookup). NOTE the daemon still drives iroh through a Transport-trait BRIDGE (daemon/src/transport_iroh_bridge.rs) delegating to NarTransfer::fetch; TASK-144's job of replacing that bridge with a PeerFabric IrohNarSource (the source_libp2p.rs sibling) is now the remaining daemon-side wiring - all the below-seam prerequisites are in place. No frozen surface touched; daemon->fabric-iroh edge only (check-independence green).

INC2 LANDED (commit 4a4397c) - IrohFabric + require_axes gate + serving-core no-iroh-STACK guard. AC#2/#3/#4/#5 CHECKED; #1/#6 stay open (honest, below).

WHAT LANDED:
- fabric_iroh::IrohFabric (fabric-iroh/src/fabric.rs): concrete peer_fabric::PeerFabric, Option<Arc<dyn>> fields, wraps one owned IrohNode. Axes WIRED: transfer (always; node.transport_handle() IrohTransport registered under TransportTag::Iroh), node_locator (iff node.node_lookup_handle() is Some -> IrohNodeLocator), server (iff node.provider_handle() is Some -> IrohProvider NarServer). Axes honestly None + WHY: provider_directory (iroh has NO Kademlia VALUE store / content-provider routing - the whole reason libp2p is primary), announcer (iroh publication is NODE-ADDRESS pkarr, feeds the locator, not content-availability), hold_query (no over-iroh protocol), local_peers (no mDNS). into_node() reclaims the node for consuming shutdown.
- fabric_iroh::IrohNodeLocator (fabric-iroh/src/locator.rs): wraps TASK-138 NodeLookupHandle as peer_fabric::NodeLocator. PublicInfrastructure -> pkarr resolve, records Exposure(DnsResolver, OurNodeId) BEFORE consult (same honest Disclosed-enum gap as the libp2p locator: no third-party-NodeId variant). Maps NodeLookupUnavailableKind -> Lookup: Expired/Withdrawn/NoDialableCandidate=Miss, Deadline=Unavailable::DeadlineExceeded, else Unavailable::Backend. ExplicitPeersOnly=Miss, zero disclosure (no address book; TASK-168). Empty candidate set=Miss.
- peer_fabric::require_axes(&dyn PeerFabric, &[Axis]) + Axis + MissingAxes (peer-fabric/src/require.rs): composition-root REQUIRED-axis assertion (AC#4, Unsupported-axis dilemma resolved at construction), fails fast naming EVERY missing axis. Axis covers the 6 Option accessors + Transfer(TransportTag). LIVE CALL SITE: daemon start_and_join_libp2p asserts consumer axes (provider_directory+node_locator+Transfer(Iroh)) and, when serving, +Server+Announcer.

GUARD (AC#6 partial - honest ratchet, NOT the final proof): daemon/tests/serving_core_no_iroh_stack_guard.rs scans a curated set of stack-neutral serving-core modules and asserts NONE names a concrete iroh-STACK token (iroh::/iroh_blobs/IrohTransport/IrohProvider/IrohNode/IrohPeerAddr/EndpointAddr/IrohError/IrohNodeBuilder/IROH_BLOBS_ALPN/use iroh). Boundary-aware (left word boundary) so transport_iroh::/iroh_runtime:: do NOT false-trip; strips full-line comments so doc-links don't. MUTATION-TESTED to bite (injected IrohProvider+iroh::Endpoint -> FAILED as expected). EXCLUDES by design: main.rs/bin (composition root), transport_iroh_bridge.rs (the bridge), transport.rs/transport_fetch.rs (fetch-registry seam naming frozen TransportTag::Iroh), lib.rs (re-export hub). WHY only partial: the DEFINITIVE guard is the daemon-core crate's dep graph (no iroh dep -> naming iroh cannot compile), which needs the daemon-core split (TASK-145). TWO KNOWN stack-neutral residues remain in the core (NOT concrete iroh types, so the guard does not forbid them): server.rs uses crate::iroh_runtime::TaskSupervisorHandle (generic process supervisor); supply_catalog.rs impls crate::transport_iroh::CatalogProbe/ProbedSupply (stack-neutral probe seam). Relocating both to daemon-core/shared-util is the TASK-145 frontend split.

DEFERRED (honestly, filed): AC#1 daemon-core crate extraction = LARGEST part, NOT attempted (would half-extract/break) -> stays TASK-145. Retiring transport_iroh_bridge for an IrohNarSource that wires IrohFabric into main.rs composition (the daemon-side symmetry) = TASK-144 follow-up / co-lands with daemon-core; all below-seam prereqs are in place, but doing it now without daemon-core would be speculative (IrohFabric is fully built+tested as the adapter, ready to adopt). AC#5 real ServeHandle teardown = confirmed already landed (TASK-150 c39b200/d7fade2); the provider test here re-exercises serve()+drop through the fabric's server() axis.

GOTCHAS: (a) IrohNode::shutdown consumes self -> IrohFabric::into_node() added so the composition root can drive clean teardown (axes borrow only the runtime). (b) offline_ephemeral disables address lookup -> node_lookup_handle()=None -> node_locator() honestly None (proven by the consumer test). (c) require_axes' Transfer axis is tag-keyed (checks fabric.transfer(tag).is_some()), the other axes are the Option accessors.

GATE: cargo build --workspace ok; just lint ok (clippy -D x2, fmt, ruff, check-independence [daemon->fabric-iroh only, no daemon<->testproxy], check-source-guard 120 files, check-lock-sources); cargo test --workspace ok - 0 failed (peer-fabric lib 70 incl 2 require tests, fabric-iroh lib 92 + iroh_fabric 2, daemon serving-core guard 1, iroh_serve_teardown 2, serve_budget_and_supply 16, all libp2p + testproxy suites green). NO frozen surface touched (RawNarV1/claim WIRE/ContentKey/ProviderRecord codec untouched - Rust boundaries only). crate-independence green; daemon->fabric-iroh edge only. s6-p2p e2e is the PENDING orchestrator-gated regression guard (NOT run here per contract).
<!-- SECTION:NOTES:END -->
