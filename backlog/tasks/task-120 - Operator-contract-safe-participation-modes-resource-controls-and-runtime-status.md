---
id: TASK-120
title: >-
  Operator contract: safe participation modes, resource controls and runtime
  status
status: In Progress
assignee:
  - '@claude'
created_date: '2026-08-10 22:24'
updated_date: '2026-08-17 01:12'
labels:
  - production
  - operator
  - observability
  - privacy
  - wave-2c
dependencies:
  - TASK-24
  - TASK-25
  - TASK-29
  - TASK-31
  - TASK-77
  - TASK-78
  - TASK-100
  - TASK-103
  - TASK-111
  - TASK-115
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Define and implement the production-facing core contract for nix-p2p after the mandatory Iroh discovery path passes. Operators get explicit validated upstream-only consume-only LAN-share and public-share modes. The authoritative typed configuration maps TASK-115 runtime scopes TASK-130 LAN TASK-116 named hold-query TASK-89 DNS/pkarr/relay and passing TASK-103 decentralized global content discovery onto upload serving query publication storage and concurrency budgets with privacy-safe status. Optional tracker and later Mainline or BitTorrent adapters may extend the registry but cannot define or satisfy the core modes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A fresh install is fail-safe: upstream fallback works, while serving, publication, public DHT/Mainline participation and third-party discovery are OFF until the operator explicitly selects a sharing profile.
- [ ] #2 The NixOS module exposes validated upstream-only, consume-only, LAN-share and public-share profiles plus explicit Iroh mechanism overrides; invalid or privacy-contradictory combinations fail evaluation/startup precisely.
- [ ] #3 Upload rate/bytes, concurrent serves, per-NAR/inflight memory, hold-query work, discovery deadline, announce volume, disk and file-descriptor budgets are bounded, documented and visible in effective configuration.
- [ ] #4 A local status surface reports stable NodeId, enabled discovery/transport/codec mechanisms, bootstrap health, holder counts, direct/hole-punched/relay path, miss versus unavailable, fallback reasons and current budget use.
- [ ] #5 Metrics/logs use bounded-cardinality labels and never export StorePath, NarHash, peer IP or full NodeId by default; opt-in diagnostics carry an explicit privacy warning and lifecycle.
- [ ] #6 Restart, dependency outage, exhausted budget and kill-switch drills yield actionable health while S2 holds; the registry contract lets TASK-119 add BitTorrent without redefining profiles or weakening safe defaults.
- [ ] #7 Before public networking is enabled, a one-command preflight lists every DNS/tracker/relay/Mainline/seed dependency, what the selected profile publishes and queries, and the effective resource/privacy controls.
- [ ] #8 The authoritative capability model represents Mainline as non-selectable pending or evidenced-unsupported until TASK-131 supplies a supported artifact. TASK-130 LAN and TASK-89 DNS/relay remain usable without it; no profile aliases pending/unsupported to enabled or silently substitutes another mechanism.
- [ ] #9 One typed configuration model is authoritative across NixOS options daemon CLI TASK-115 endpoint scopes TASK-130 LAN TASK-116 named hold-query TASK-89 DNS and relay passing TASK-103 decentralized content discovery and status or preflight. Optional tracker Mainline and BitTorrent adapters extend the registry only after their own tasks and contradictory duplicate defaults fail parity tests.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Production foundation independent of tournament-derived automatic defaults. TASK-45 exercises this contract from a clean host. Implement and prove it for mandatory Iroh first; optional tracker Mainline and later BitTorrent plug into the same modes without becoming prerequisites. Lower-level scope selection never implies publication lookup relay use or public participation.

Forward-carried from TASK-138 review: the v1 NodeId lookup replay table is fail-closed and non-reclaiming. Before public-share is production-ready define a durable or reclaiming admission policy or operator-visible restart ledger preserving anti-replay guarantees and expose hostile-churn capacity use and exhaustion.

READY (all deps Done as of 2026-08-17: 24/25/29/31/77/78/100/103/111/115) BUT NEEDS A LIBP2P-PRIMARY RE-SCOPE before implementation. The description + ACs are IROH-ERA ("after the mandatory Iroh discovery path passes", "prove it for mandatory Iroh first", "explicit Iroh mechanism overrides") - pre-reconciliation, contradicting the Wave-2c authority (libp2p-kad is PRIMARY + proven; iroh deferred-pending-202). This is DRIFT, not a product change (cf. the PRD Wave-2c execution-order reconciliation). Re-scope: the CORE is transport-agnostic + valid (upstream-only/consume-only/LAN-share/public-share modes; the resource-cap budgets AC#3; the status surface AC#4; the bounded-cardinality privacy-safe metrics AC#5; the preflight AC#7; the one-authoritative-typed-config AC#9) - keep those. Re-point the iroh-first language to "prove on the libp2p path first (the primary, proven); iroh is an optional deferred mechanism override, not a prerequisite." The consume-only/LAN/public modes already have real enforcement shipped (TASK-231 eligibility gate, TASK-77 announce-after-fetch, TASK-78 LeechFabric consume-only) - 120 makes them the AUTHORITATIVE typed operator contract + adds resource caps + status + preflight + the NixOS profiles. TASK-45 exercises it from a clean host. This is the pilot-readiness gate.

CODEX DEEP GATE NO-GO (deep) on 0fff8c0. ROOT CAUSE: OperatorContract is a REPORTING VENEER not the enforcement authority - runtime still branches on legacy booleans. AC#1/#2/#8/#9 FAIL (claimed Complete but bites test the TYPE not the runtime): fresh daemon-libp2p cant do upstream-only (exits 2); NixOS ORs legacy booleans; ContractRequest re-derives from flags not an explicit --profile; IROH GLOBAL-SCOPE PROVIDER MISLABELED lan-share (safety bug); iroh/pkarr flags bypass pending-non-selectability; contradictory ResourceCaps defaults (512/300 vs 256/120). AC#3 phantom caps, AC#7 preflight misreports, AC#5 redaction unwired + NarHash in logs. integer/frozen PASS; 231/77/78 reuse PASS where triggered. Disposition (rework-vs-rescope) routing through mped; core fix = make the contract the ENFORCEMENT AUTHORITY. Commit kept (type is a foundation).
<!-- SECTION:NOTES:END -->
