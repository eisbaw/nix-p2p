---
id: TASK-239
title: >-
  Strict announce serveability: GC-root pin or periodic reconcile sweep (TASK-77
  AC#3 residual)
status: To Do
assignee: []
created_date: '2026-08-16 21:56'
labels:
  - discovery
  - hardening
  - serveability
  - supply-model
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-77 (announce-after-fetch, Done) keeps index-coverage==provider-coverage EVENTUALLY-CONSISTENT: correct at announce time, then reconciled opportunistically on the next fetch dispatch + bounded by kad record TTL. An IDLE node can transiently keep advertising a GC-removed (or failed-withdraw) holding until reconcile or TTL. This is WITHIN the project TCB (the serve side re-dumps+BLAKE3-reverifies, so a GC'd path yields a clean Declined with zero bytes -> the querier retries the next provider, never a bad byte), which is why it was accepted for 77. STRICT always-coverage would need either (a) a nix GC-root pin per announced path for the announcement lifetime (bounds disk by the announce budget; a retention/operator-mode decision) OR (b) a periodic timer-driven reconcile sweep so idle nodes self-heal without waiting for TTL. Both are supply-model/operator-contract decisions (TASK-61/120), deferred out of 77. Pick + implement one if strict coverage is wanted; integer-only; do not weaken the eligibility gate. codex round-2/3 flagged this; owner ruled it a deferred follow-up.
<!-- SECTION:DESCRIPTION:END -->
