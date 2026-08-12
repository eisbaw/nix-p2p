---
id: TASK-150
title: >-
  peer_fabric::NarSupplier is too weak for the iroh serve axis
  (plan/size-before-produce + cancellation-safety)
status: To Do
assignee: []
created_date: '2026-08-12 05:17'
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
