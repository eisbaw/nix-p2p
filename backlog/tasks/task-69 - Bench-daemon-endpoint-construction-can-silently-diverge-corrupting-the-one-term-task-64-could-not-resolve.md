---
id: TASK-69
title: >-
  Bench/daemon endpoint construction can silently diverge, corrupting the one
  term task-64 could not resolve
status: To Do
assignee: []
created_date: '2026-08-09 14:59'
updated_date: '2026-08-10 22:26'
labels:
  - tech-debt
  - measurement
dependencies: []
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FOUND BY REVIEW during TASK-64. daemon/examples/iroh_throughput.rs's bare_endpoint() restates daemon/src/transport_iroh.rs's private bind_loopback_endpoint(), and provider_endpoint_addr() restates IrohProvider::addr(). They are byte-identical TODAY (verified), so there is no live error - which is exactly why this is worth filing rather than fixing in a hurry. The hazard is silent drift: every rung of the bench's subtraction ladder EXCEPT daemon_fetch runs on the bench's copy, and daemon_fetch runs on the daemon's. Any future divergence - transport config, congestion controller, initial MTU, keep-alive, relay mode - lands invisibly in the iroh_collect -> daemon_fetch difference, which is PRECISELY the term PRD entry 11 already flags as unresolved and swinging +-0.7 ns/B. PRD risk 10 is 'iroh API churn: accepted maintenance tax', so drift is expected rather than hypothetical, and this failure is silent rather than loud. NOT a DRY nit: the bench's central claim is 'raw QUIC on the SAME iroh Endpoint stack', and nothing mechanically holds that true. Options, cheapest first: (a) a #[doc(hidden)] pub re-export of bind_loopback_endpoint so the bench uses the daemon's own binder - but note the module deliberately keeps iroh opaque behind IrohPeerAddr so callers never touch the iroh crate, and this would breach that on purpose; (b) an assertion in the bench comparing the two endpoints' observable configuration; (c) accept and document. Whichever is chosen, the point is that a divergence must FAIL rather than quietly change a number.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The bench's raw-QUIC arms and the daemon's transport provably share one endpoint configuration, or a divergence between them fails loudly
- [ ] #2 The chosen mechanism is proven by mutation: change the daemon's binder and watch the guard go red, restore and watch it go green
- [ ] #3 If option (a) is taken, the deliberate breach of the 'callers never touch iroh' boundary is documented at the export site with its reason
<!-- AC:END -->
