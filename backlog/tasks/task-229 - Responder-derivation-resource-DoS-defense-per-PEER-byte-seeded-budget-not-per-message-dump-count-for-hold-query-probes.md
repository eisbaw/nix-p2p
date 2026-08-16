---
id: TASK-229
title: >-
  Responder derivation-resource DoS defense: per-PEER byte-seeded budget (not
  per-message dump-count) for hold-query probes
status: To Do
assignee: []
created_date: '2026-08-16 03:18'
labels:
  - daemon-core
  - discovery
  - resource
  - hardening
  - security
dependencies:
  - TASK-104
  - TASK-72
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Forward-carried from TASK-104. TASK-104 added a per-BATCH derivation-work budget (MAX_BATCH_DERIVE_WORK=16 fresh nix-store --dump per batch message), closing AC#1 (one MESSAGE cannot trigger unbounded dumps). Two real resource-safety residuals remain, honestly disclosed at TASK-104 and worth the proper responder-resource DoS defense that TASK-100/TASK-120 need:
1. A dump COUNT does not bound BYTES hashed - 16 large cold dumps is still unbounded I/O. The root-cause bound is a nix path-info -S (NarSize) seeded BYTE budget that can REFUSE a probe before dumping, so the responder work is bounded in bytes, not dump-count.
2. A per-MESSAGE bound is NOT a DoS defense: a hostile peer picks message boundaries (many 16-dump batches, or single-key hold() probes which take the UNLIMITED path). The actual defense is a per-PEER AGGREGATE derivation budget (bytes and/or count) over a time window - the hashing analog of TASK-72's serve budget (which bounds bytes SERVED, not HASHED). The single-key hold() unlimited path must also be brought under this per-peer bound.
Also (minor, from TASK-104): resolve_many could opportunistically re-probe a peer that deferred (convert responder-cache warming into first-contact healing); and MAX_BATCH_DERIVE_WORK=16 is a conservative placeholder, tune from a real per-deployment disk/CPU I/O ceiling. This is a frozen-adjacent resource-contract task (feeds the TASK-120 operator budgets) - DEEP-gate. Do NOT fix by raising PROBE_TIMEOUT (TASK-40).
<!-- SECTION:DESCRIPTION:END -->
