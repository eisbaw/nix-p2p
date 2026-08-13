---
id: TASK-146
title: daemon-libp2p thin binary (gated on fabric-libp2p)
status: Done
assignee:
  - mped
created_date: '2026-08-11 23:58'
updated_date: '2026-08-13 02:09'
labels:
  - seam
  - de-welding
  - libp2p
  - blocked
dependencies:
  - TASK-103
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The second product binary from docs/peer-fabric-seam.md's two-binary composition root: daemon-libp2p = daemon-core + fabric-libp2p, fn main() { daemon_core::run(fabric_libp2p::Libp2pFabric::new(cfg)) }, with a build guard that its dep closure contains no iroh. BLOCKED and deliberately NOT stubbed: there is no fabric-libp2p backend crate until libp2p is adopted (TASK-103 selects the ProviderDirectory backend). Filed so the two-binary target architecture is tracked; implement only once fabric-libp2p exists. Referenced from the daemon-iroh inc-3 task and TASK-141.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 daemon-libp2p binary crate = daemon-core + fabric-libp2p; build guard proves its dep closure contains no iroh
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Extract proc-supervisor (TaskSupervisor+process_group) so daemon-core + fabric-iroh share it without a cycle; extract daemon-core (16 serving modules + generalized PeerFabricNarSource, peer-fabric+proc-supervisor deps ONLY); add daemon_core::run + the daemon-libp2p thin binary (daemon-core+fabric-libp2p) + the no-iroh cargo-tree closure guard. Retain the daemon composite (both backends) as interim; daemon-iroh is TASK-145.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
LANDED - TASK-146 complete, three green increments on master.

ecb9b1f proc-supervisor: extracted the generic TaskSupervisor + process_group OUT of fabric_iroh::iroh_runtime into a stack-neutral leaf crate (tokio+rustix, ZERO p2p). New SupervisorError with From<> into IrohRuntimeError/IrohError. daemon-core AND fabric-iroh depend on it (acyclic).

46b9dcc daemon-core: the stack-neutral serving FRONTEND crate; deps = peer-fabric + proc-supervisor ONLY (verified by cargo build + the daemon-libp2p no-iroh closure guard). Moved 16 modules (availability/body/cacheinfo/catalog/claim/content_id/discovery/narinfo_cache/nixbase32/rewrite/server/source/supply_catalog/transport/upstream) + generalized peer_source (PeerFabricNarSource/RawServe from the already-generic Libp2pNarSource). The 4 iroh couplings severed (server->proc_supervisor::TaskSupervisorHandle; availability->proc_supervisor::process_group; transport dropped the IROH_BLOBS_ALPN re-export; supply_catalog dropped its CatalogProbe impl).

785d746 daemon-libp2p: the PRIMARY thin binary = daemon-core + fabric-libp2p (AC#1). fn main builds a Libp2pFabric + connectivity and calls daemon_core::run - no features, no cfg. Consumer AND provider modes. daemon_core::run(fabric, RunConfig) = require_axes gate + PeerFabricNarSource with HTTP-upstream fallback + serve (daemon-core/tests/run_gate.rs pins the gate). The no-iroh closure guard (daemon-libp2p/tests/no_iroh_closure_guard.rs, cargo-tree) is DEFINITIVE and mutation-tested to bite.

daemon-core dep set = peer-fabric + proc-supervisor ONLY. NOT in daemon-core (stayed in the daemon composite as the legacy iroh-fetch path): transport_fetch (Transport/registry - only the iroh path uses it; libp2p bypasses it via PeerFabricNarSource), transport_iroh_bridge (direct impl Transport for IrohTransport), iroh_catalog_probe (CatalogProbe newtype). The source_libp2p CONSTRUCTION moved to the daemon-libp2p LIB (SSOT; the composite re-exports it, no drift).

GOTCHAS: (a) ORPHAN-RULE cascade - putting Transport/CatalogProbe in daemon-core would orphan the iroh impls; kept transport_fetch in the composite (Transport local -> direct impl, zero test churn) + made CatalogProbe a local newtype. That is WHY transport_fetch is not in daemon-core. (b) pub bumps for cross-crate use: KnownTransport::{tag,to_offer}, SupplyCatalogHandle::probe_record + SupplyCatalogRecord, ProcessJobRegistry API, TaskSupervisorHandle::disconnected. (c) guards repointed to daemon-core/src (serving_core_no_iroh_stack_guard, no_direct_upstream, doc_citations, no_enumeration); the DEFINITIVE de-weld proof is now the daemon-core/daemon-libp2p crate GRAPH (no iroh dep), superseding the content ratchet.

INTERIM vs FINAL: daemon-core + daemon-libp2p are FINAL. The 'daemon' composite is RETAINED interim (links both backends; s6-p2p iroh + s7-libp2p e2e drive it). Retiring the composite + building daemon-iroh (with transport_fetch + the bridges) is TASK-145. Backend-specific --libp2p-max-* serve knobs are a follow-up (provisional defaults in the bin).

Gate: cargo build --workspace ok; just lint ok (clippy -D workspace+evidence-fixture, fmt, ruff, independence [daemon-core/daemon-libp2p/proc-supervisor daemon-side, no daemon<->testproxy edge], source-guard 129 files, lock-sources); cargo test --workspace ok - 592 passed, 0 failed, 64 suites (incl no-iroh guard + run gate). NO frozen surface touched (RawNarV1/claim WIRE/ContentKey/ProviderRecord codec). s6-p2p + s7-libp2p are the PENDING orchestrator-gated regression guards (not run here per contract).
<!-- SECTION:NOTES:END -->
