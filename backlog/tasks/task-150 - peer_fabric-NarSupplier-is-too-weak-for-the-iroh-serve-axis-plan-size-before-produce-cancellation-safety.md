---
id: TASK-150
title: >-
  peer_fabric::NarSupplier is too weak for the iroh serve axis
  (plan/size-before-produce + cancellation-safety)
status: Done
assignee:
  - '@claude'
created_date: '2026-08-12 05:17'
updated_date: '2026-08-12 07:18'
labels:
  - iroh
  - seam
  - serve
  - de-welding
  - wave-2c
dependencies:
  - TASK-148
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-148 de-welded the iroh TRANSFER axis onto peer_fabric::NarTransfer cleanly, but the SERVE axis (AC#2 NarServer + real ServeHandle teardown, and the AC#3 move) is blocked by a real seam-design gap discovered during implementation.

The iroh provider's task-72 admission gate needs to know a NAR's declared_size WITHOUT producing its bytes (so a 3 GiB request costs a stat, not 3 GiB - the peer-triggerable-OOM defense), and it executes production cancellation-safely via an owned process group (transport_iroh's SEALED, plan-based NarSupplier: plan(content)->SupplyPlan{declared_size, Process/Memory/RegularFile source}). The seam's peer_fabric::NarSupplier::supply(content)->Option<Vec<u8>> produces bytes EAGERLY and carries no size, so a faithful peer_fabric::NarServer impl for iroh cannot preserve either invariant. Papering over it (wrap supply() and allocate first) would be a workaround that reintroduces the exact task-72 GAP-1 OOM and drops cancellation safety - explicitly rejected.

Resolution options to weigh (needs a seam decision, this is peer-fabric contract work, not just the iroh adapter): (a) extend peer_fabric::NarSupplier to a plan/size-first shape (e.g. declared_size(content)->Option<u64> + a cancellation-aware produce), (b) add a richer serve-supply seam type below NarServer, (c) keep the plan-based sealed supplier as an iroh-internal detail and have NarServer accept it via a fabric-iroh-owned trait. Note peer-fabric is a frozen TASK-140 seam, so changing NarSupplier is a cross-cutting decision.

Also blocks the move (AC#3): IrohProvider serving is baked into IrohNodeBuilder::provider(config).spawn() sharing the endpoint/router with the transport, not a standalone serve() on a running runtime; implementing NarServer::serve returning a ServeHandle whose Drop aborts an INDEPENDENTLY-abortable serve task needs a provider-lifecycle refactor. And IndexNarSupplier reaches daemon supply_catalog (test-only today) - severing that needs a fabric-iroh-side catalog-probe trait the daemon implements.

Once resolved, retire the daemon Transport bridge (adopt peer_fabric::NarTransfer + TransferRegistry in the daemon fetch path), move IROH_BLOBS_ALPN + assertion into fabric-iroh (needs iroh-blobs dep there), and move transport_iroh into fabric-iroh (AC#3/#4). See commit 9c0472d and code comments in transport_iroh.rs referencing 'TASK-148 AC#3'.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 peer_fabric::NarServer serve-supply contract preserves declared-size-before-production (task-72 GAP-1 defense) and cancellation-safety, or an explicit ADR records why it need not
- [ ] #2 IrohProvider serving is refactorable to a standalone NarServer::serve on a running runtime, returning a ServeHandle whose Drop aborts the serve task (proven by a teardown test)
- [ ] #3 IndexNarSupplier no longer reaches daemon supply_catalog directly (a fabric-iroh-side catalog-probe trait the daemon implements)
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
SEAM DECISION (option c, refined): keep the plan-based SEALED NarSupplier/SupplyPlan an iroh-internal (below-seam) detail; do NOT drag its size/cancellation machinery up into peer_fabric. Realize it by BINDING the supplier to the server at CONSTRUCTION rather than passing any supplier across the seam:
- Change peer_fabric::NarServer::serve(supplier, budget) -> serve(budget). The concrete server (iroh) already holds its sealed plan-based supplier; the fake holds nothing.
- REMOVE the weak peer_fabric::NarSupplier (supply()->Option<Vec<u8>>): it CANNOT preserve the task-72 GAP-1 declared-size-before-production defense nor the sealed supplier cancellation-safety, and nothing real consumes it yet (only FakeNarServer/NoOpSupplier). Keeping it invites the wrap-and-alloc GAP-1 workaround the task rejects.
Rationale (MPED): peer_fabric stays substrate-neutral (no Process/Memory/plan/process-group types leak up); declared-size-before-produce + cancellation-safe process-group execution stay in the runtime layer that can actually enforce them (transport_iroh gate/admit + TaskSupervisor.execute_process). Rejected (a) extend NarSupplier plan-first: forces a size/produce TOCTOU or drags SupplyPlan sources up-seam; rejected (b) new below-NarServer seam type: same up-seam leakage.
Increments: (1) AC#1 peer_fabric seam change + ADR in docs/peer-fabric-seam.md + capabilities.rs. (2) AC#3 fabric-iroh-side catalog-probe trait daemon implements; IndexNarSupplier depends on the trait not the concrete SupplyCatalogHandle. (3) AC#2 provider-lifecycle refactor: IrohProvider impl peer_fabric::NarServer::serve on a running runtime returning a ServeHandle whose Drop aborts the driver task (teardown test), de-welding the serve axis from the node supervisor while keeping cancellation-safe execute_process. Full gate per increment; commit each green increment immediately.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
INCREMENT 1 LANDED (commit 306bc3f) - AC#1 seam decision + peer_fabric change.
DECISION: option (c) refined - the plan-based SEALED NarSupplier/SupplyPlan stays a substrate-internal (below-seam) detail; the supplier is BOUND to the concrete server at CONSTRUCTION, not passed across the seam. peer_fabric::NarServer::serve(supplier, budget) -> serve(budget); the weak peer_fabric::NarSupplier (supply()->Option<Vec<u8>>) is REMOVED (it cannot preserve task-72 GAP-1 declared-size-before-produce nor cancellation-safety, and nothing real consumed it - only FakeNarServer/NoOpSupplier). Rejected (a) extend NarSupplier plan-first (size/produce TOCTOU or drags SupplyPlan sources up-seam) and (b) new below-NarServer seam type (same up-seam leakage). ADR in peer-fabric/src/capabilities.rs (above ServeHandle) + docs/peer-fabric-seam.md.
GATE: build + lint (clippy -D + independence + source/lock guards) green; just test green (peer_fabric 68, serve_budget_and_supply 16, store_residency_oracle/retainall/rss all 1/1, fabric-iroh lib 91, iroh_runtime 37); just e2e 5/5 incl s6-p2p 11/11. Pre-existing flake iroh_node_lookup::synchronous_replay_validation... failed once under parallel load, passed in isolation and on re-run (guardrail-listed, not mine).

INCREMENT 2 LANDED (commit 4402a50) - AC#3 catalog-probe seam.
IndexNarSupplier no longer names daemon supply_catalog types. New CatalogProbe trait + substrate-neutral ProbedSupply{declared_size, ProbedSource::{Process,RegularFile,Memory}} in transport_iroh; IndexNarSupplier holds Arc<dyn CatalogProbe>. daemon SupplyCatalogHandle impls CatalogProbe (in supply_catalog.rs), inverting the edge to daemon->transport_iroh. new() now takes impl CatalogProbe+'static (call sites unchanged - SupplyCatalogHandle passes by value). Preserves GAP-1 declared-size-before-produce and no-enumeration.
GATE: build/lint green; task-72 oracles green (serve_budget_and_supply 16; store_residency_oracle/retainall/rss 1/1/1; iroh_runtime 37 incl provider_boundary sealing + AvailabilityIndex-non-retention guards); full just test green; just e2e 5/5 incl s6-p2p 11/11.

INCREMENT 3 LANDED (commit c39b200) - AC#2 de-welded serve axis.
IrohProvider now impls peer_fabric::NarServer. New IrohNodeBuilder::defer_serve() registers the provider handler WITHOUT starting the driver (fail-closed via require_ready); IrohProvider::serve starts the driver on an INDEPENDENT tokio task and returns a peer_fabric::ServeHandle whose Drop (AbortOnDrop) aborts JUST that task - de-welding the serve loop lifetime from the node runtime supervisor. Request sub-tasks still spawn on the runtime supervisor, preserving cancellation-safe execute_process/process-group reaping. Serve budget arrives THROUGH the seam: ServeGate.budget is a set-once OnceLock installed before the driver admits (task-72 declared-size-before-produce preserved). Auto-serve path (IrohProviderNode::spawn*, production main.rs) installs at prepare - behaviorally unchanged (risk isolated). Shared driver body extracted to run_provider_event_driver() used by both start (supervisor) and start_abortable (tokio+JoinHandle).
TEARDOWN TEST (daemon/tests/iroh_serve_teardown.rs, 2/2): deferred provider fail-closed until serve(); serve()->ready; drop(handle)->driver aborted (lifecycle leaves READY, the only way a recv()-blocked loop stops) while node runtime stays alive + shuts down clean; auto-serve provider refuses a 2nd serve() with a named error.
GATE: build/lint green; serve_budget_and_supply 16, store_residency_oracle/retainall/rss 1/1/1, iroh_runtime 37, iroh_serve_teardown 2, iroh_transport 7; full just test green; just e2e 5/5 incl s6-p2p 11/11.

REVIEW ROUND (mped-architect, Mark-emulator) LANDED (commit d7fade2). The core safety story was CLEARED: OnceLock 'budget before any admit' is structural (no reachable .expect panic); teardown is fail-closed (aborted driver drops its answer channel -> iroh-blobs InterceptLog request aborts, no bytes served post-teardown); no EventSender/protocol leak; serve_tasks take is not a TOCTOU; removing peer_fabric::NarSupplier + CatalogProbe (no-enumeration preserved) endorsed. Fixes applied: #1(major) reworded the ServeHandle/NarServer seam doc - drop stops NEW admissions only; in-flight drains under the node runtime and its budget is not reclaimed until then (best-effort, async, no happens-before stop signal); #3(footgun) renamed inherent SupplyCatalogHandle::probe -> probe_record so the CatalogProbe trait  can't silently rebind to unbounded recursion; #2/#4 documented deferred serve as single-shot/terminal + async teardown; #6 from_seam destructures peer_fabric::ServeBudget exhaustively (compile-time drift catch); #7 IROH-SERVE-STARTED/-STOPPED session traces. #5(nit budget() expect vs fail-closed) left as documented-unreachable (structural ordering).

NOTE (typo fix): in the review-round note above, the phrase 'the CatalogProbe trait can-t silently rebind' lost the word 'probe' (a shell backtick ate it). Full meaning: renaming the inherent method to probe_record ensures the CatalogProbe trait method named probe cannot be silently rebound to by a future refactor - which would cause unbounded recursion with no compile error.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
All 3 ACs GREEN. SEAM DECISION (AC#1, option c refined): the plan-based SEALED NarSupplier/SupplyPlan stays substrate-internal (below the seam); the supplier is bound to the concrete server at CONSTRUCTION, so peer_fabric::NarServer::serve carries only the budget and the weak peer_fabric::NarSupplier (eager, sizeless) is removed - declared-size-before-produce (task-72 GAP-1) and cancellation-safety stay in the runtime layer that enforces them. AC#2: IrohProvider impls peer_fabric::NarServer; IrohNodeBuilder::defer_serve() registers the handler without starting the driver, IrohProvider::serve starts it on an independent tokio task and returns a ServeHandle whose Drop aborts JUST that task (de-welding the serve axis from the shared runtime supervisor while keeping cancellation-safe execute_process and the OnceLock budget-before-admit bound); teardown-proven by daemon/tests/iroh_serve_teardown.rs (2/2). AC#3: IndexNarSupplier severed from daemon supply_catalog via the CatalogProbe trait + neutral ProbedSupply (edge inverted to daemon->transport_iroh). Commits: 306bc3f AC#1, 4402a50 AC#3, c39b200 AC#2, d7fade2 review fixes. GATE: build/lint green; serve_budget_and_supply 16, store_residency oracle/retainall/rss 1/1/1, iroh_runtime 37, iroh_serve_teardown 2; full test green; e2e 5/5 incl s6-p2p 11/11. TASK-148 remainder (retire daemon Transport bridge -> NarTransfer+TransferRegistry; move transport_iroh + IROH_BLOBS_ALPN into fabric-iroh) NOT attempted here - large/high-blast-radius, tracked under TASK-148 (serve axis + IndexNarSupplier sub-blocker now unblocked).
<!-- SECTION:FINAL_SUMMARY:END -->
